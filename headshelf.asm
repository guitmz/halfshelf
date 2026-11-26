format ELF64 executable 3

include "utils.inc"                      

; Headless SHELF loader \o/
;
; This variant consumes:
;   1. a stripped payload containing the original PT_LOAD bytes after the
;      ELF/program header prefix was removed
;   2. a text metadata sidecar that tells the loader how to reconstruct the
;      missing header derived facts
;
; The runtime still follows the same direct entry path as halfshelf:
; map, relocate, prepare TLS, rebuild the stack, jump to entry

segment readable executable
entry $                                       
    ;   headshelf <payload-file> <meta-file> [args...]
    ; or:
    ;   cat payload | headshelf --memfd <meta-file> [args...]
    ;
    ; The second form is the more 1337 variant for this
    ; SHELF subtree: the stripped payload never needs a pathname 
    ; at all, because the loader stages it directly from stdin into
    ; memory and mirrors those bytes into a memfd file descriptor
    mov rcx, [rsp]                            ; argc is always sits [rsp] before any pushes
    cmp rcx, 3                                ; we want 3 args
    jl usage
    lea rax, [rsp + rcx * 8 + 16]             ; envp starts right after argv[] and its NULL
    mov [targetEnvp], rax

    ; argv[1] is the payload path, or exactly "--memfd". memfdArg carries its
    ; NUL, so a payload file named "--memfd.bin" still counts as file mode
    mov byte [memfdMode], 0
    mov rbx, [rsp + 16]
    lea rdi, [memfdArg]
    mov rcx, memfdArgLen
    .checkMemfdMode:
        test rcx, rcx
        jz .memfdMode
        mov al, [rbx]
        cmp al, [rdi]
        jne .fileMode
        inc rbx
        inc rdi
        dec rcx
        jmp .checkMemfdMode
    .memfdMode:
    mov byte [memfdMode], 1
    lea rax, [memfdTargetPath]                   ; synthetic argv[0] presented to the loaded payload
    jmp .modeReady
    .fileMode:
    mov rax, [rsp + 16]                          ; argv[1] becomes the target visible argv[0] pathname
    .modeReady:
    mov [targetPath], rax
    mov rax, [rsp + 24]                          ; argv[2] is the metadata sidecar pathname
    mov [metaPath], rax
    mov rax, [rsp]
    sub rax, 2                                   ; the loader's own argv[0] and the metadata path are dropped
    mov [targetArgc], rax

    ; Drop the two loader arguments in place. The argv[2] slot becomes the
    ; target's argv[0], and the forwarded args, NULL, envp and auxv already
    ; follow it in the shape stack.inc expects
    mov rax, [targetPath]
    mov [rsp + 24], rax
    lea rax, [rsp + 24]
    mov [targetArgv], rax

    mov rbx, [targetEnvp]
    call scanDebugEnv
    ; Read the metadata sidecar first so we know exactly how large the runtime
    ; mapping must be and where the stripped payload bytes belong in it
    mov rdi, [metaPath]                       
    mov rsi, O_RDONLY                         
    xor rdx, rdx
    mov rax, SYS_OPEN
    syscall
    test rax, rax                             ; the test/js-then-jump-to-a-named-*Failed-handler pattern below repeats for every syscall in this file
    js openFailed
    mov [metaFd], rax

    mov rdi, rax                              ; opened metadata sidecar fd
    lea rsi, [metaStat]
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed

    cmp qword [metaStat.st_size], BUFFER_SIZE    ; one byte is kept free for the NUL terminator below
    jge fileTooLarge

    mov rdi, [metaFd]                         ; sidecar fd
    lea rsi, [metaBuffer]
    mov rdx, [metaStat.st_size]
    mov rax, SYS_READ
    syscall
    cmp rax, [metaStat.st_size]               ; short reads are treated as failure to keep the flow simple
    jne metaReadFailed

    lea rsi, [metaBuffer]
    mov rcx, [metaStat.st_size]
    add rsi, rcx
    mov byte [rsi], 0                         ; NUL terminate the staged bytes so the text format scanners below can detect instead of reading past it

    call parseMetaDispatch

    ; Both metadata formats get the same checks here, so a hand edited text
    ; sidecar cannot get past anything the binary one would reject
    movzx eax, word [ehdr.phentsize]
    cmp eax, sizeof.PHDR
    jne invalidMeta
    mov rax, [loadFilesz]
    cmp rax, [loadMemsz]
    ja invalidMeta                            ; the file part cannot be bigger than the whole segment
    mov rdx, [headerSpan]
    cmp rdx, rax
    ja invalidMeta                            ; the stripped header span is a prefix of load_filesz
    movzx eax, word [ehdr.phnum]
    imul eax, sizeof.PHDR
    sub rdx, rax
    jb invalidMeta
    cmp [phoffValue], rdx
    ja invalidMeta                            ; the phdr table has to end inside the header span

    mov rdi, [metaFd]                         ; sidecar fd, closed once fully parsed
    mov rax, SYS_CLOSE
    syscall
    test rax, rax
    js closeFailed
    ; Read the stripped payload bytes.
    ;
    ; File mode stages the payload exactly like the original headless variant.
    ; Memfd mode instead drains stdin into the same staging buffer while also
    ; mirroring those bytes into a memfd descriptor. The mirror is only there
    ; to show the payload living in a memfd for the article. Nothing reads it
    ; back, the image is always copied from buffer
    cmp byte [memfdMode], 0
    jne .readPayloadFromMemfd

    .readPayloadFromFile:
    mov rdi, [targetPath]                        
    mov rsi, O_RDONLY                            
    xor rdx, rdx                                 ; open(2) ignores mode bits without O_CREAT
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [targetFd], rax

    mov rdi, rax                                 ; opened stripped payload fd
    lea rsi, [fstat]                             
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed

    cmp qword [fstat.st_size], BUFFER_SIZE       ; whole file staging still has to fit into the fixed scratch buffer
    jg fileTooLarge

    mov rdi, [targetFd]                          
    lea rsi, [buffer]                            
    mov rdx, [fstat.st_size]                     
    mov rax, SYS_READ
    syscall
    cmp rax, [fstat.st_size]                     ; short reads are treated as failure to keep the flow simple
    jne fileReadFailed
    jmp .payloadReady                         ; skips the memfd only staging path below

    .readPayloadFromMemfd:
    lea rsi, [dbgMemfdMsg]                    ; traced before memfd_create so failures below are still visible even without inspecting /proc
    mov rdx, dbgMemfdMsgLen
    call debugWrite
    lea rdi, [memfdName]                         ; debug friendly memfd name shown by tools like /proc/*/fd
    xor rsi, rsi                                 ; memfd_create flags = 0 for the simplest anonymous in-memory file
    mov rax, SYS_MEMFD_CREATE
    syscall
    test rax, rax
    js openFailed
    mov [targetFd], rax
    xor r12, r12                                 ; total number of payload bytes staged so far
    .stdinReadLoop:
        mov rdx, BUFFER_SIZE
        sub rdx, r12                             ; remaining free room in the fixed staging buffer
        jz fileTooLarge                       ; memfd mode has no fstat size to check ahead of time, so overflowing the fixed staging buffer only shows up here
        lea rsi, [buffer + r12]                  ; append new stdin bytes after the already staged prefix
        mov rdi, STDIN                           ; stdin is the headless payload source in --memfd mode
        mov rax, SYS_READ
        syscall
        test rax, rax
        js fileReadFailed
        jz .stdinReadDone                        ; read(0) == 0 means EOF, so the payload is fully staged
        mov r13, rax                             ; remember how many new bytes this read produced
        mov rdi, [targetFd]                      ; mirror the same chunk into the memfd file descriptor
        lea rsi, [buffer + r12]                  ; write exactly the bytes that just landed in the staging buffer
        mov rdx, r13
        mov rax, SYS_WRITE
        syscall
        cmp rax, r13
        jne fileReadFailed
        add r12, r13                             ; total staged payload bytes grows by the successful chunk length
        jmp .stdinReadLoop
    .stdinReadDone:
    mov [fstat.st_size], r12                     ; synthesize the st_size field the rest of the loader expects

    .payloadReady:

    ; The stripped payload should be exactly the original PT_LOAD file size
    ; minus the removed ELF/program header prefix.
    mov rax, [loadFilesz]
    sub rax, [headerSpan]
    cmp [fstat.st_size], rax                  ; fstat.st_size here is the freshly staged payload size, not the original loadFilesz from metadata
    jne invalidMeta

    ; Reserve and populate the one SHELF PT_LOAD mapping
    mov rax, [loadMemsz]
    add rax, PAGE_SIZE - 1                    ; rounds the mapping size up to a whole page, memsz (not filesz) drives this since BSS/zero-fill still needs backing pages
    and rax, -PAGE_SIZE                       ; -PAGE_SIZE as a mask only works because PAGE_SIZE is a power of two
    mov [imageSpanSize], rax                  ; read back by mprotect below and by the stack/reloc code as the image's mapped length

    lea rsi, [dbgReserveDynMsg]               ; Dyn here refers to the ET_DYN image reservation below, not PT_DYNAMIC
    mov rdx, dbgReserveDynMsgLen
    call debugWrite

    xor rdi, rdi                              ; NULL hint lets the kernel place the mapping, nothing here depends on a fixed address
    mov rsi, [imageSpanSize]
    mov rdx, PROT_READ or PROT_WRITE          ; mapped RW first since the payload bytes still need to be copied in below, final protections land later via mprotect
    mov r10, MAP_PRIVATE or MAP_ANON          ; payload bytes are copied in by hand rather than mmap'd straight from a file
    mov r8, -1                                ; ignored since MAP_ANON is set, but Linux still wants -1 
    xor r9, r9                                ; irrelevant for an anonymous mapping
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov [baseAddr], rax                       ; the real load bias, replacing the placeholder zero set while parsing metadata above

    lea rsi, [dbgLoadBiasMsg]
    mov rdx, dbgLoadBiasMsgLen
    mov rax, [baseAddr]
    call debugPrintHexLine

    lea rsi, [dbgMapMainMsg]
    mov rdx, dbgMapMainMsgLen
    mov rax, [baseAddr]
    call debugPrintHexLine

    mov rdi, [baseAddr]
    call synthesizeHeaders                   ; writes the reconstructed ehdr + phdr table into the mapping before the payload copy below can safely land after headerSpan
    mov rdi, [baseAddr]
    add rdi, [headerSpan]                     ; headerSpan marks where the synthesized ehdr/phdr region ends and the stripped payload begins, the two must not overlap
    lea rsi, [buffer]
    mov rcx, [fstat.st_size]
    rep movsb                                 ; copies the stripped payload bytes in one shot now that the mapping is writable

    mov r8d, dword [loadFlags]
    ELF_FLAGS_TO_PROT r8d, edx                ; loadFlags carries raw ELF PF_* bits, this macro is the only place they get translated into PROT_* values
    mov rdi, [baseAddr]
    mov rsi, [imageSpanSize]                  ; protects the whole image span in one call, since a SHELF image only ever has the one PT_LOAD
    mov rax, SYS_MPROTECT
    syscall
    test rax, rax
    js mprotectFailed

    mov rax, [baseAddr]
    add rax, [phoffValue]
    mov [phdrRuntime], rax                    ; becomes the AT_PHDR value the target's own libc startup code looks for in auxv
    ; PT_DYNAMIC/PT_TLS are optional in a SHELF image, a zero size in the metadata is how their absence gets recorded here
    mov byte [hasDynamic], 0
    cmp qword [dynamicSize], 0
    je .noDynamic
    mov byte [hasDynamic], 1
    .noDynamic:
    mov byte [hasTls], 0
    cmp qword [tlsMemsz], 0
    je .noTls
    mov byte [hasTls], 1
    .noTls:
    mov byte [stackProt], PROT_READ or PROT_WRITE  ; unlike halfshelf, headless mode never re-scans phdrs for PT_GNU_STACK, so the stack is always RW

    ; Allocate the synthetic target stack and continue with the shared entry 
    ; relocation/TLS/stack logic
allocateStack:
    xor rdi, rdi
    mov rsi, STACK_SIZE                       ; fixed 8 mb reservation for the rebuilt argv/envp/auxv plus target stack usage, not resized dynamically
    mov rdx, PROT_READ or PROT_WRITE
    mov r10, MAP_PRIVATE or MAP_ANON
    mov r8, -1
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov [stackAddr], rax                      ; base of the brand new stack mapping stack.inc finishes populating
    lea rsi, [dbgStackMsg]
    mov rdx, dbgStackMsgLen
    mov rax, [stackAddr]
    call debugPrintHexLine
    jmp relocate                              ; hands off into the shared reloc/TLS/stack pipeline from here, same entry point halfshelf uses

include "loader/reloc.inc"                    ; shared with halfshelf, handles PT_DYNAMIC RELA/JMPREL relocations against baseAddr
include "loader/stack.inc"                    ; shared with halfshelf, builds the target's TLS block and synthetic stack, then jumps to the entry point
include "loader/common.inc"                   ; shared debug tracing, error exits and exit

parseMetaDispatch:
    ; Metadata sidecars come in two formats now:
    ;   * SHELFMETA1 : text that is easy to inspect by hand
    ;   * SHELFBN1   : compact binary metadata that is easier to pipe around
    ;
    ; Autodetecting the magic keeps the runtime loader interface stable while
    ; letting the helper tools pick whichever encoding is more convenient
    lea rsi, [metaBuffer]                      ; first byte of the staged metadata sidecar
    lea rdi, [metaMagic]
    mov rcx, metaMagicLen
    call tryPrefix
    cmp rax, 1
    je parseMetaText
    lea rsi, [metaBuffer]
    lea rdi, [metaBinMagic]
    mov rcx, metaBinMagicLen
    call tryPrefix
    cmp rax, 1
    je parseMetaBin
    jmp invalidMeta

parseMetaText:
    ; each field below repeats the same shape: a fixed key literal, then a hex value up to the trailing newline
    lea rsi, [metaBuffer]
    lea rdi, [metaMagic]                      ; re-verifies the exact magic bytes tryPrefix already matched in parseMetaDispatch, this can't actually fail but keeps the two code paths symmetric
    mov rcx, metaMagicLen
    call expectPrefix
    call expectNl

    lea rdi, [metaEntryKey]
    mov rcx, metaEntryKeyLen
    call expectPrefix
    call parseHexLine
    mov [ehdr.entry], rax                     ; stays an offset from baseAddr rather than an absolute address, stack.inc adds baseAddr + ehdr.entry at the final jump

    lea rdi, [metaPhoffKey]
    mov rcx, metaPhoffKeyLen
    call expectPrefix
    call parseHexLine
    mov [phoffValue], rax
    mov [ehdr.phoff], rax                   ; duplicated deliberately: phoffValue feeds the pointer math below, ehdr.phoff is what synthesizeHeaders serializes into the image

    lea rdi, [metaPhnumKey]
    mov rcx, metaPhnumKeyLen
    call expectPrefix
    call parseHexLine
    mov word [ehdr.phnum], ax               ; e_phnum is only 16 bits wide in ELF64, parseHexLine's 64 bit accumulator gets truncated 

    lea rdi, [metaPhentsizeKey]
    mov rcx, metaPhentsizeKeyLen
    call expectPrefix
    call parseHexLine
    mov word [ehdr.phentsize], ax             ; same 16 bit truncation as phnum, a normal ELF64 PHDR table has phentsize = 0x38

    lea rdi, [metaHeaderSpanKey]
    mov rcx, metaHeaderSpanKeyLen
    call expectPrefix
    call parseHexLine
    mov [headerSpan], rax                     ; marks where the synthesized ehdr/phdr region ends and the stripped payload begins

    lea rdi, [metaLoadOffsetKey]
    mov rcx, metaLoadOffsetKeyLen
    call expectPrefix
    call parseHexLine
    test rax, rax
    jne invalidMeta                           ; SHELF's single PT_LOAD must start at file offset 0, anything else means the strip tool made something this loader can't reconstruct

    lea rdi, [metaLoadVaddrKey]
    mov rcx, metaLoadVaddrKeyLen
    call expectPrefix
    call parseHexLine
    test rax, rax
    jne invalidMeta                           ; must map at vaddr 0 too, keeping baseAddr as the image's only load bias

    lea rdi, [metaLoadFileszKey]
    mov rcx, metaLoadFileszKeyLen
    call expectPrefix
    call parseHexLine
    mov [loadFilesz], rax                     ; original PT_LOAD file size before the header prefix was stripped, used to size-check the incoming payload later

    lea rdi, [metaLoadMemszKey]
    mov rcx, metaLoadMemszKeyLen
    call expectPrefix
    call parseHexLine
    mov [loadMemsz], rax                        ; drives the mmap reservation below (rounded up to a page), not loadFilesz

    lea rdi, [metaLoadFlagsKey]
    mov rcx, metaLoadFlagsKeyLen
    call expectPrefix
    call parseHexLine
    mov dword [loadFlags], eax                ; raw PF_R/PF_W/PF_X bits, translated into PROT_* only once mapping begins

    lea rdi, [metaDynamicVaddrKey]
    mov rcx, metaDynamicVaddrKeyLen
    call expectPrefix
    call parseHexLine
    mov [dynamicVaddr], rax                   ; PT_DYNAMIC's runtime vaddr, consumed later by reloc.inc when resolving RELA entries

    lea rdi, [metaDynamicMemszKey]
    mov rcx, metaDynamicMemszKeyLen
    call expectPrefix
    call parseHexLine
    mov [dynamicSize], rax                    ; a zero dynamicSize is how hasDynamic below decides the image carries no PT_DYNAMIC segment

    lea rdi, [metaTlsVaddrKey]
    mov rcx, metaTlsVaddrKeyLen
    call expectPrefix
    call parseHexLine
    mov [tlsVaddr], rax                       ; PT_TLS virtual address, consumed by stack.inc's TLS block setup

    lea rdi, [metaTlsFileszKey]
    mov rcx, metaTlsFileszKeyLen
    call expectPrefix
    call parseHexLine
    mov [tlsFilesz], rax                      ; file-backed portion of the TLS template, the rest up to tlsMemsz is zero filled at load time

    lea rdi, [metaTlsMemszKey]
    mov rcx, metaTlsMemszKeyLen
    call expectPrefix
    call parseHexLine
    mov [tlsMemsz], rax                       ; a zero tlsMemsz is likewise how hasTls gets decided further down

    lea rdi, [metaTlsAlignKey]
    mov rcx, metaTlsAlignKeyLen
    call expectPrefix
    call parseHexLine
    mov [tlsAlign], rax                       ; passed through as is, reloc.inc/stack.inc apply their own minimum alignment clamping

    lea rdi, [metaPhdrHexKey]
    mov rcx, metaPhdrHexKeyLen
    call expectPrefix
    lea rdi, [phdrBlob]
    call decodeHexBlobLine                    ; the only variable length metadata field, hence the dedicated blob decoder instead of parseHexLine

    ; the rest of the header is reconstructed from constants, not the sidecar: a SHELF image only ever comes from this project's own strip tool and always has this exact shape
    mov word [ehdr.type], ET_DYN
    mov dword [ehdr.magic], 0x464c457f        ; the .ELF magic, little-endian dword
    mov byte [ehdr.class], ELFCLASS64
    mov byte [ehdr.data], ELFDATA2LSB
    mov byte [ehdr.elfversion], 1
    mov byte [ehdr.os], 3
    mov byte [ehdr.abiversion], 0
    mov word [ehdr.machine], EM_X86_64        ; anything else in a real ELF file would mean a foreign architecture (aliens dude meme)
    mov dword [ehdr.version], EV_CURRENT
    mov word [ehdr.ehsize], sizeof.EHDR
    mov qword [baseAddr], 0                   ; just an initial value, the mmap further down overwrites it with the real load bias before anything reads it
    ret

parseMetaBin:
    ; Binary metadata is a fixed little-endian record followed by the raw phdr
    ; table bytes. Because the loader itself runs on little-endian x64, the
    ; parser can read those qwords directly from memory after range checks
    mov rax, [metaStat.st_size]                
    cmp rax, metaBinFixedSize                    ; the fixed size binary header must fit before we read any fields
    jb invalidMeta
    lea rsi, [metaBuffer + metaBinMagicLen]    ; skip the 8 byte "SHELFBN1" magic prefix

    mov rax, [rsi]
    mov [ehdr.entry], rax                     ; same entry field as the text format, decoded from a raw qword instead of ASCII hex
    add rsi, 8
    mov rax, [rsi]
    mov [phoffValue], rax
    mov [ehdr.phoff], rax
    add rsi, 8
    mov rax, [rsi]
    cmp rax, 0xffff                              ; the reconstructed EHDR field is 16 bit
    ja invalidMeta
    mov word [ehdr.phnum], ax
    add rsi, 8
    mov rax, [rsi]
    cmp rax, 0xffff                              ; 16 bit field too, the exact size is checked after parsing
    ja invalidMeta
    mov word [ehdr.phentsize], ax
    add rsi, 8
    mov rax, [rsi]
    mov [headerSpan], rax                     ; same header_span boundary as the text format
    add rsi, 8
    mov rax, [rsi]                               ; load_offset must stay zero for a valid SHELF single PT_LOAD image
    test rax, rax
    jne invalidMeta
    add rsi, 8
    mov rax, [rsi]                               ; load_vaddr must also stay zero in this narrowed SHELF format
    test rax, rax
    jne invalidMeta
    add rsi, 8
    mov rax, [rsi]
    mov [loadFilesz], rax                     ; same field as the text format's load_filesz, this format just carries it as a plain qword instead of ASCII hex
    add rsi, 8
    mov rax, [rsi]
    mov [loadMemsz], rax
    add rsi, 8
    mov eax, [rsi]
    mov dword [loadFlags], eax
    add rsi, 8
    mov rax, [rsi]
    mov [dynamicVaddr], rax                   ; same field as the text format's dynamic_vaddr, just read as a raw qword here
    add rsi, 8
    mov rax, [rsi]
    mov [dynamicSize], rax                    ; zero here means no PT_DYNAMIC, same convention as the text format
    add rsi, 8
    mov rax, [rsi]
    mov [tlsVaddr], rax                       ; same tls_vaddr field as the text format
    add rsi, 8
    mov rax, [rsi]
    mov [tlsFilesz], rax                    ; file TLS bytes, same meaning as the text format's tls_filesz
    add rsi, 8
    mov rax, [rsi]
    mov [tlsMemsz], rax                        ; zero here means no PT_TLS, checked the same way hasTls is set later
    add rsi, 8
    mov rax, [rsi]
    mov [tlsAlign], rax                       ; same tls_align field as the text format, just decoded from raw bytes
    add rsi, 8
    mov rax, [rsi]                               ; binary metadata ends the fixed header with the raw phdr blob size
    cmp rax, 4096                                ; the shared phdr scratch buffer in rwdata.inc is 4096 bytes large
    ja invalidMeta
    mov r8, rax                                  ; declared phdr blob size in bytes
    movzx rax, word [ehdr.phnum]
    movzx rcx, word [ehdr.phentsize]
    imul rax, rcx
    cmp r8, rax                                  ; declared phdr blob size must match phnum * phentsize exactly
    jne invalidMeta
    mov rax, [metaStat.st_size]
    sub rax, metaBinFixedSize                    ; number of bytes after the fixed binary header
    cmp rax, r8                                  ; fixed record + PHDR blob is the complete file and trailing bytes are invalid
    jne invalidMeta
    lea rsi, [metaBuffer + metaBinFixedSize]   ; first raw program header byte in the binary metadata sidecar
    lea rdi, [phdrBlob]                          ; scratch buffer that later synthesizeHeaders copies from
    mov rcx, r8                                  ; number of phdr bytes to copy
    rep movsb

    ; same reconstructed header constants as the text format path above
    mov word [ehdr.type], ET_DYN
    mov dword [ehdr.magic], 0x464c457f
    mov byte [ehdr.class], ELFCLASS64
    mov byte [ehdr.data], ELFDATA2LSB
    mov byte [ehdr.elfversion], 1
    mov byte [ehdr.os], 3
    mov byte [ehdr.abiversion], 0
    mov word [ehdr.machine], EM_X86_64        
    mov dword [ehdr.version], EV_CURRENT
    mov word [ehdr.ehsize], sizeof.EHDR
    mov qword [baseAddr], 0
    ret

synthesizeHeaders:
    ; Recreate the stripped ELF header and phdr table at the front of the
    ; mapped image so libc/static PIE startup code can still find __ehdr_start
    ; and a normal in-memory AT_PHDR region
    push rdi                                  ; save/restore rather than assume the one call site today doesn't need these
    push rsi
    push rcx
    lea rsi, [ehdr]
    mov rcx, sizeof.EHDR
    rep movsb                                 ; copies the reconstructed EHDR to the very front of the mapped image, where __ehdr_start/AT_PHDR expect it
    mov rdi, [baseAddr]
    add rdi, [phoffValue]
    lea rsi, [phdrBlob]
    movzx rcx, word [ehdr.phnum]
    movzx rax, word [ehdr.phentsize]
    imul rcx, rax                             ; total phdr table length, the same computation decodeHexBlobLine used to validate the blob size
    rep movsb                                 ; copies the decoded phdr table right after the ehdr, completing the synthesized header region
    pop rcx
    pop rsi
    pop rdi
    ret

expectPrefix:
    ; compare against a fixed key, jumps straight to invalidMeta on the first mismatch since there's no format ambiguity here
    .loop:
        test rcx, rcx
        jz .done
        mov al, [rsi]
        mov dl, [rdi]
        cmp al, dl
        jne invalidMeta                       ; a mismatch here means the sidecar doesn't start with the key parseMetaText expected next
        inc rsi
        inc rdi
        dec rcx
        jmp .loop
    .done:
    ret

tryPrefix:
    ; Like expectPrefix, but return success/failure in rax instead of jumping
    ; to the invalid path. That is useful for format autodetection
    push rsi                                  ; preserved because tryPrefix always returns normally, unlike expectPrefix which just exits the whole process on a mismatch
    push rdi
    push rcx
    xor rax, rax
    .loop:
        test rcx, rcx
        jz .matched
        mov dl, [rsi]
        mov bl, [rdi]
        cmp dl, bl
        jne .done                             ; falls through with rax still zero, meaning no match, the caller decides what to try next
        inc rsi
        inc rdi
        dec rcx
        jmp .loop
    .matched:
    mov rax, 1
    .done:
    pop rcx
    pop rdi
    pop rsi
    ret

expectNl:
    cmp byte [rsi], 0xa                        ; newline terminates every text-format key's value line
    jne invalidMeta
    inc rsi
    ret

parseHexLine:
    xor rax, rax                              ; accumulator for the decoded value, every caller expects the result back in rax
    .loop:
        mov dl, [rsi]
        cmp dl, 0xa                            ; newline also ends a hex value line here, same convention expectNl checks explicitly for the header line
        je .done
        test dl, dl
        jz invalidMeta                        ; a NUL before the newline means the value was cut off
        shl rax, 4
        cmp dl, '0'
        jb invalidMeta
        cmp dl, '9'
        jbe .digit
        cmp dl, 'a'
        jb .checkUpper
        cmp dl, 'f'
        ja invalidMeta
        sub dl, 'a' - 0xa
        jmp .store
        .checkUpper:
        cmp dl, 'A'
        jb invalidMeta
        cmp dl, 'F'
        ja invalidMeta
        sub dl, 'A' - 0xa
        jmp .store
        .digit:
        sub dl, '0'
        .store:
        add al, dl
        inc rsi
        jmp .loop
    .done:
    inc rsi                                   ; leaves rsi just past the trailing newline, ready for whatever expectPrefix/parseHexLine call comes next
    ret

; decodes a long run of ASCII hex pairs with no separators, used only for phdr_hex since its length isn't fixed
decodeHexBlobLine:
    xor r8, r8                                ; counts decoded bytes so the total can be checked against phnum * phentsize below
    .loop:
        mov al, [rsi]
        cmp al, 0xa
        je .done
        test al, al
        jz invalidMeta                        ; same truncated value guard as parseHexLine's NUL check
        cmp r8, 4096                          ; phdrBlob size, the same cap the binary format enforces
        jae invalidMeta
        call parseNibble
        shl al, 4
        mov bl, al
        inc rsi
        mov al, [rsi]
        call parseNibble
        or al, bl
        mov [rdi], al
        inc rdi
        inc rsi
        inc r8
        jmp .loop
    .done:
    inc rsi
    movzx rax, word [ehdr.phnum]
    movzx rcx, word [ehdr.phentsize]
    mul rcx
    cmp r8, rax                               ; decoded byte count must exactly match phnum * phentsize, catching a truncated or padded phdr_hex line
    jne invalidMeta
    ret

; like the mapping parseHexLine inlines above, factored out here since decodeHexBlobLine needs it twice per byte
parseNibble:
    cmp al, '0'
    jb invalidMeta
    cmp al, '9'
    jbe .digit
    cmp al, 'a'
    jb .checkUpper
    cmp al, 'f'
    ja invalidMeta
    sub al, 'a' - 0xa
    ret
    .checkUpper:
    cmp al, 'A'
    jb invalidMeta
    cmp al, 'F'
    ja invalidMeta
    sub al, 'A' - 0xa
    ret
    .digit:
    sub al, '0'
    ret

; Error exits only headshelf reaches, the shared ones live in loader/common.inc
invalidMeta:
    lea rsi, [invalidMetaMsg]
    mov rdx, invalidMetaMsgLen
    jmp writeError

metaReadFailed:
    lea rsi, [metaReadFailedMsg]
    mov rdx, metaReadFailedMsgLen
    jmp writeError

usage:
    ; usage errors show both the version banner and the usage text, the same version line HALFSHELF_DEBUG prints above
    lea rsi, [versionMsg]
    mov rdx, versionMsgLen
    mov rdi, STDOUT                           ; unlike the error paths above, usage/version text is expected output, so it goes to stdout
    mov rax, SYS_WRITE
    syscall
    lea rsi, [husageMsg]
    mov rdx, husageMsgLen
    mov rdi, STDOUT
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1                       ; usage still exits nonzero, since it was triggered by insufficient arguments
    jmp exit

segment readable
include "loader/rodata.inc"                   
husageMsg            db "Usage: headshelf <payload-file> <meta-file> [args...]", 0xa, \  
                         "   or: headshelf --memfd <meta-file> [args...] < payload", 0xa
husageMsgLen         = $ - husageMsg
metaMagic            db "SHELFMETA1"          ; must match the first line of a SHELFMETA1 sidecar exactly
metaMagicLen         = $ - metaMagic
metaBinMagic         db "SHELFBN1"            ; binary sidecar's identifier, distinguishes it from SHELFMETA1 during autodetection
metaBinMagicLen      = $ - metaBinMagic
metaBinFixedSize     = metaBinMagicLen + (17 * 8)  ; 17 qword fields follow the magic: entry, phoff, phnum, phentsize, header_span, load_offset, load_vaddr, load_filesz, load_memsz, load_flags, dynamic_vaddr, dynamic_memsz, tls_vaddr, tls_filesz, tls_memsz, tls_align, phdr_blob_size, matching parseMetaBin's field order
memfdArg             db "--memfd", 0          ; the NUL makes the mode check an exact match
memfdArgLen          = $ - memfdArg
memfdName            db "shelf_payload", 0
memfdTargetPath      db "memfd:shelf", 0      ; fake argv[0] handed to the loaded payload in --memfd mode

metaEntryKey         db "entry "              
metaEntryKeyLen      = $ - metaEntryKey
metaPhoffKey         db "phoff "              
metaPhoffKeyLen      = $ - metaPhoffKey
metaPhnumKey         db "phnum "              
metaPhnumKeyLen      = $ - metaPhnumKey
metaPhentsizeKey     db "phentsize "          
metaPhentsizeKeyLen  = $ - metaPhentsizeKey
metaHeaderSpanKey    db "header_span "        
metaHeaderSpanKeyLen = $ - metaHeaderSpanKey
metaLoadOffsetKey    db "load_offset "        
metaLoadOffsetKeyLen = $ - metaLoadOffsetKey
metaLoadVaddrKey     db "load_vaddr "         
metaLoadVaddrKeyLen  = $ - metaLoadVaddrKey
metaLoadFileszKey    db "load_filesz "        
metaLoadFileszKeyLen = $ - metaLoadFileszKey
metaLoadMemszKey     db "load_memsz "         
metaLoadMemszKeyLen  = $ - metaLoadMemszKey
metaLoadFlagsKey     db "load_flags "         
metaLoadFlagsKeyLen  = $ - metaLoadFlagsKey
metaDynamicVaddrKey    db "dynamic_vaddr "    
metaDynamicVaddrKeyLen = $ - metaDynamicVaddrKey
metaDynamicMemszKey    db "dynamic_memsz "    
metaDynamicMemszKeyLen = $ - metaDynamicMemszKey
metaTlsVaddrKey      db "tls_vaddr "          
metaTlsVaddrKeyLen   = $ - metaTlsVaddrKey
metaTlsFileszKey     db "tls_filesz "         
metaTlsFileszKeyLen  = $ - metaTlsFileszKey
metaTlsMemszKey      db "tls_memsz "          
metaTlsMemszKeyLen   = $ - metaTlsMemszKey
metaTlsAlignKey      db "tls_align "          
metaTlsAlignKeyLen   = $ - metaTlsAlignKey
metaPhdrHexKey       db "phdr_hex "           
metaPhdrHexKeyLen    = $ - metaPhdrHexKey

segment readable writeable
include "loader/rwdata.inc"                   
