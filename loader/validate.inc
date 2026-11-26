; Validate the basic ELF identity up front
    cmp [ehdr.magic], 0x464c457f                  ; 0x464c457f is the ELF magic you know that already
    jnz invalidElf                                ; reject files that do not even begin with a valid ELF header
    cmp [ehdr.class], ELFCLASS64                  ; require the 64 bit ELF class this loader was written for
    jne invalidArch                               ; reject unwanted targets
    cmp [ehdr.data], ELFDATA2LSB                  ; check if target ELF is little-endian
    jne invalidElf
    cmp word [ehdr.machine], EM_X86_64            ; check if target ELF is x64
    jne invalidArch
    cmp dword [ehdr.version], EV_CURRENT          ; check ELF version
    jne invalidElf
    ; Beyond identity, the loader validates only the header layout pieces it
    ; directly depends on during mapping. The detailed phdr/PT_LOAD checks
    ; happen in the later scan/mapping phases
    cmp word [ehdr.ehsize], sizeof.EHDR           ; e_ehsize must match the 64 byte ELF64 header we know how to parse
    jne invalidLayout
    cmp word [ehdr.phentsize], sizeof.PHDR        ; each phdr entry must match our native ELF64 program header layout
    jne invalidLayout
    ; The whole phdr table must sit inside the staged file, every later walk
    ; reads it straight out of buffer
    movzx eax, word [ehdr.phnum]
    imul eax, sizeof.PHDR
    mov rdx, [fstat.st_size]
    sub rdx, rax
    jb invalidLayout
    cmp [ehdr.phoff], rdx
    ja invalidLayout

    ; A SHELF image here is expected to be ET_DYN only
    cmp word [ehdr.type], ET_DYN
    jne unsupportedType
    lea rsi, [dbgDynMsg]
    mov rdx, dbgDynMsgLen
    call debugWrite

; SHELF pre scan.
;
; inspects program headers and enforces the SHELF image shape, discovers
; the single PT_LOAD span used to reserve the runtime window, and collects
; PT_DYNAMIC/PT_TLS metadata for later direct entry setup.
;
; expects the classic simplified image shape: ET_DYN, exactly one PT_LOAD,
; p_offset == 0, p_vaddr == 0, no PT_INTERP
scanDynImage:
    mov [baseAddr], 0
    mov qword [phdrRuntime], 0
    mov byte [hasDynamic], 0
    mov byte [hasTls], 0
    mov byte [stackProt], PROT_READ or PROT_WRITE
    mov qword [dynamicVaddr], 0
    mov qword [dynamicSize], 0
    mov qword [tlsVaddr], 0
    mov qword [tlsFilesz], 0
    mov qword [tlsMemsz], 0
    mov qword [tlsAlign], 0
    mov qword [imageMinVaddr], -1
    mov qword [imageMaxVaddr], 0
    mov qword [loadCount], 0
    lea rbx, [buffer]
    add rbx, [ehdr.phoff]
    xor ecx, ecx
    movzx ecx, word [ehdr.phnum]
    .scanDynLoop:
        test rcx, rcx
        jz .scanDynDone
        mov rsi, rbx
        lea rdi, [phdr]
        push rcx
        mov ecx, sizeof.PHDR
        rep movsb
        pop rcx
        cmp dword [phdr.type], PT_INTERP
        jne .scanDynNotInterp
        jmp unsupportedInterp
        .scanDynNotInterp:
        cmp dword [phdr.type], PT_DYNAMIC
        jne .scanDynNotDynamic
        mov byte [hasDynamic], 1
        mov rax, [phdr.vaddr]
        mov [dynamicVaddr], rax
        mov rax, [phdr.memsz]
        mov [dynamicSize], rax
        .scanDynNotDynamic:
        cmp dword [phdr.type], PT_TLS
        jne .scanDynNotTls
        mov byte [hasTls], 1
        mov rax, [phdr.vaddr]
        mov [tlsVaddr], rax
        mov rax, [phdr.filesz]
        mov [tlsFilesz], rax
        mov rax, [phdr.memsz]
        mov [tlsMemsz], rax
        mov rax, [phdr.align]
        mov [tlsAlign], rax
        .scanDynNotTls:
        cmp dword [phdr.type], PT_LOAD
        jne .scanDynNext
        cmp qword [phdr.memsz], 0
        je .scanDynNext
        inc qword [loadCount]
        cmp qword [loadCount], 1
        jne invalidShelf
        cmp qword [phdr.offset], 0
        jne invalidShelf
        cmp qword [phdr.vaddr], 0
        jne invalidShelf
        mov rax, [phdr.vaddr]
        and rax, -PAGE_SIZE
        mov rdx, [phdr.vaddr]
        add rdx, [phdr.memsz]
        add rdx, PAGE_SIZE - 1
        and rdx, -PAGE_SIZE
        UPDATE_LOAD_SPAN rax, rdx, imageMinVaddr, imageMaxVaddr
        .scanDynNext:
        movzx rax, word [ehdr.phentsize]
        add rbx, rax
        dec rcx
        jmp .scanDynLoop
    .scanDynDone:
    mov rax, [imageMinVaddr]
    cmp rax, -1
    je invalidElf
    cmp qword [loadCount], 1
    jne invalidShelf
    mov rdx, [imageMaxVaddr]
    sub rdx, rax
    mov [imageSpanSize], rdx
    jmp getDynAddr

; Reserve an address window large enough for the whole PT_LOAD span.
; The chosen load bias is reserved_base - lowest_load_vaddr. Keep the
; reservation alive until segment mapping overwrites it with MAP_FIXED,
; that avoids transient reuse of the chosen address range by later
; mappings in the same process
getDynAddr:
    lea rsi, [dbgReserveDynMsg]
    mov rdx, dbgReserveDynMsgLen
    call debugWrite
    xor rdi, rdi                                  ; operating system will choose mapping destination
    mov rsi, [imageSpanSize]                      ; reserve the full PT_LOAD span
    mov rdx, PROT_READ or PROT_WRITE              ; protect RW
    mov r10, MAP_PRIVATE or MAP_ANON             ; pages will be private and anonymous
    mov r8, -1                                     ; no fd because anonymous
    xor r9, r9                                    ; no offset because anonymous
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov rdx, [imageMinVaddr]
    sub rax, rdx
    mov qword [baseAddr], rax                     ; save load bias for future use
    lea rsi, [dbgLoadBiasMsg]
    mov rdx, dbgLoadBiasMsgLen
    mov rax, [baseAddr]
    call debugPrintHexLine
