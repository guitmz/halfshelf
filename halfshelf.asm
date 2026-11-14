format ELF64 executable 3

include "utils.inc"

; This file keeps the high level control flow for the SHELF focused loader:
;   1. read and validate the target ELF
;   2. enforce the narrow SHELF image shape
;   3. map the one PT_LOAD segment
;   4. apply the direct entry relocation subset
;   5. rebuild the initial process stack
;   6. jump directly into the target image
;
; Supporting data lives in:
;   loader/rodata.inc
;   loader/rwdata.inc

segment readable executable
entry $
; Parse the loader's own initial stack.
;
; Linux starts us with:
;   [rsp + 0]  = argc
;   [rsp + 8]  = argv[0]
;   [rsp + 16] = argv[1]
;
; This loader expects exactly one target path argument, so the loaded SHELF
; program sees a rewritten argv where its argv[0] becomes the path we were
; given as argv[1]
    mov rcx, [rsp]                                ; loader argc as provided by the kernel at process entry
    cmp rcx, 2                                    ; we need one target argument in addition to argv[0]
    jl usage
    mov rax, rcx                                  ; copy argc so we can derive the target's future argc
    dec rax                                       ; target argc = loader argc - 1 because argv[0] becomes the target path
    mov [targetArgc], rax                         ; save the argc value the loaded program should eventually observe
    lea rax, [rsp + 16]                          ; loader argv[1], which becomes target argv[0]
    mov [targetArgv], rax                         ; save the original argv vector position for later stack rebuilding
    mov rax, [rsp + 16]
    mov [targetPath], rax                           ; remember the requested target path for open(2) and AT_EXECFN patching
    ; Debug tracing is controlled by the loader's own environment, not the
    ; target program's future environment. We scan for HALFSHELF_DEBUG=<value>
    ; once up front so later phases can cheaply branch on one byte
    mov byte [debugEnabled], 0
    lea rbx, [rsp + rcx * 8 + 16]                 ; first envp entry after argv[] and its NULL
    .scanDebugEnv:
        mov rdi, [rbx]
        test rdi, rdi                             ; NULL means we reached the end of the environment vector
        jz .debugEnvDone
        lea rsi, [debugEnvPrefix]                 ; rsi walks the literal "HALFSHELF_DEBUG=" prefix
        mov rdx, debugEnvPrefixLen                
        .debugEnvCmp:
            test rdx, rdx                         ; once the prefix byte count reaches zero, the prefix matched
            jz .debugEnvMatched
            mov al, [rdi]
            mov cl, [rsi]
            cmp al, cl                            ; mismatch means this env entry is not HALFSHELF_DEBUG=...
            jne .debugEnvNext
            inc rdi
            inc rsi
            dec rdx
            jmp .debugEnvCmp
        .debugEnvMatched:
            ; Any non empty value other than zero enables tracing
            mov al, [rdi]
            test al, al                           ; empty value means present but disabled
            jz .debugEnvNext
            cmp al, '0'                           ; "0" is the off switch
            je .debugEnvNext
            mov byte [debugEnabled], 1            
            lea rsi, [versionMsg]
            mov rdx, versionMsgLen
            call debugWrite
            lea rsi, [dbgEnabledMsg]              
            mov rdx, dbgEnabledMsgLen
            call debugWrite
            jmp .debugEnvDone
        .debugEnvNext:
        add rbx, 8
        jmp .scanDebugEnv
    .debugEnvDone:
; Open the target image and read it into the loader's staging buffer.
; The actual PT_LOAD mapping later copies from this in-memory image
    mov rdi, [targetPath]
    mov rsi, O_RDONLY                             ; open the target read only because the loader never writes to it
    xor rdx, rdx                                  ; open(2) mode is unused without O_CREAT
    mov rax, SYS_OPEN
    syscall                                      
    test rax, rax
    js openFailed
    mov [targetFd], rax
; Query the target file metadata.
;
; The loader mainly cares about st_size so it can bound header reads and the
; whole file staging read into buffer
    mov rdi, [targetFd]
    lea rsi, [fstat]                             
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed
; Read just the ELF header first.
;
; This is enough to validate the target type and discover where the phdr table
; lives before committing to the whole file staging read
    mov rdi, [targetFd]
    lea rsi, [ehdr]                               
    mov rdx, sizeof.EHDR                         
    mov r10, 0
    mov rax, SYS_PREAD64
    syscall
    cmp rax, sizeof.EHDR
    jne headerReadFailed
; Stage the entire target file in memory.
;
; Later PT_LOAD mapping code copies segment bytes out of this buffer into
; their final anonymous mappings
    cmp qword [fstat.st_size], BUFFER_SIZE
    jg fileTooLarge
    mov rdi, [targetFd]
    lea rsi, [buffer]                             ; beginning of the fixed staging buffer
    mov rdx, [fstat.st_size]
    mov rax, SYS_READ
    syscall
    cmp rax, [fstat.st_size]
    jne fileReadFailed
; Delay close(2).
;
; The fd stays open for now because later phases still use pread64(2) while
; walking the main program header table
include "loader/validate.inc"
; Allocate the synthetic target stack mapping. Creates the RW stack mapping
; that later phases will populate, reserves enough room for argv/envp/auxv
; pointer tables and copied string payloads, but does not write the final
; stack contents yet, later phases may still need to patch auxv values
; based on interpreter/TLS decisions
allocateStack:
    xor rdi, rdi                                  ; OS will choose mapping destination
    mov rsi, STACK_SIZE
    mov rdx, PROT_READ or PROT_WRITE              ; protect RW by default
    mov r10, MAP_PRIVATE or MAP_ANON              ; pages will be private and anonymous
    mov r8, -1                                    ; no fd because anonymous duh
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov qword [stackAddr], rax                    ; save stack mmap address for future use
    lea rsi, [dbgStackMsg]
    mov rdx, dbgStackMsgLen
    mov rax, [stackAddr]
    call debugPrintHexLine
; Main image program header walk. Iterates the staged SHELF program headers,
; remembers PT_DYNAMIC/PT_TLS/PT_GNU_STACK metadata, maps the one PT_LOAD
; segment RW, populates it, zeroes bss, then mprotects it to the final PF_*
; permissions, and computes phdrRuntime for AT_PHDR if the phdr table lives
; inside the one load segment
processPhdrs:
    mov qword [phdrRuntime], 0
    mov r9, [ehdr.phoff]
    xor rbx, rbx
    .loopPhdr:
        mov rdi, [targetFd]
        lea rsi, [phdr]
        mov dx, word [ehdr.phentsize]
        mov r10, r9                               ; r9 tracks the running phdr file offset across loop iterations, advanced by phentsize at the bottom of the loop
        mov rax, SYS_PREAD64
        syscall
        cmp rax, sizeof.PHDR
        jne phdrReadFailed
        cmp dword [phdr.type], PT_GNU_STACK
        je .stack
        jne .notStack
        .stack:
            mov r8d, [phdr.flags]
            ELF_FLAGS_TO_PROT r8d, edx
            .stackProtect:                        ; install the final stack protection derived from PT_GNU_STACK
                mov [stackProt], dl
                mov rdi, [stackAddr]
                mov rsi, STACK_SIZE
                mov rax, SYS_MPROTECT
                syscall
                test rax, rax
                js mprotectFailed
        .notStack:
            cmp dword [phdr.type], PT_DYNAMIC
            jne .notDynamic
            mov byte [hasDynamic], 1
            mov rax, [phdr.vaddr]
            mov [dynamicVaddr], rax
            mov rax, [phdr.memsz]
            mov [dynamicSize], rax
        .notDynamic:
            cmp dword [phdr.type], PT_TLS
            jne .notTls
            mov byte [hasTls], 1
            mov rax, [phdr.vaddr]
            mov [tlsVaddr], rax
            mov rax, [phdr.filesz]
            mov [tlsFilesz], rax
            mov rax, [phdr.memsz]
            mov [tlsMemsz], rax
            mov rax, [phdr.align]
            mov [tlsAlign], rax
        .notTls:
            cmp [phdr.type], PT_LOAD
            jne .next_phdr
            ; All bytes copied from the file must actually exist in the staged
            ; ELF image. The loader allows bss segments (filesz == 0)
            ; but not file ranges that overrun the input buffer
            mov rax, [phdr.filesz]
            cmp rax, [phdr.memsz]
            ja invalidSegment
            mov rax, [phdr.offset]
            cmp rax, [fstat.st_size]
            ja invalidSegment
            mov rdx, [phdr.filesz]
            mov rcx, [fstat.st_size]
            sub rcx, rax
            cmp rdx, rcx
            ja invalidSegment
            mov rax, [ehdr.phoff]
            cmp rax, [phdr.offset]
            jb .notPhdrHost
            mov rdx, [phdr.offset]
            add rdx, [phdr.filesz]
            cmp rax, rdx
            jae .notPhdrHost
            mov rdx, [baseAddr]                   ; start from the chosen ET_DYN load bias
            add rdx, [phdr.vaddr]
            add rdx, rax                          ; move by the phdr table's file offset inside the ELF image
            sub rdx, [phdr.offset]                ; subtract this segment's file offset to convert file offset -> runtime address
            mov [phdrRuntime], rdx                ; save the future AT_PHDR runtime pointer for stack rebuilding
            .notPhdrHost:
            cmp qword [phdr.memsz], 0             ; zero sized PT_LOAD segments do not need mmap/copy/protect work
            je .next_phdr
; compute the mapped segment range, rounded to whole pages
            mov r15, [phdr.vaddr]                ; r15 = original segment runtime start address from p_vaddr
            and r15, -PAGE_SIZE                  ; round the mapping start down so mmap begins on a whole page
            push r15                             ; save the page aligned mapping base for the later mprotect call
            mov r14, [phdr.vaddr]
            sub r14, r15                          ; in-page offset from the rounded base to the true segment start
            mov r13, [phdr.memsz]                 ; unrounded in-memory segment size from p_memsz
            add r13, r14                          ; include the in-page offset so the mapping fully covers the segment bytes
            add r13, PAGE_SIZE - 1                ; bias upward before rounding the mapping size to a whole page count
            and r13, -PAGE_SIZE
            push r13                              ; save the page rounded mapping size for the later mprotect call
; Map a writable scratch view for this segment, populate it, then tighten
; protections to match the ELF flags
           push r9                             ; save the phdr table file offset tracker across mmap's use of r9
           mov rdi, [baseAddr]
           add rdi, r15
           mov rsi, r13
           mov rdx, PROT_READ or PROT_WRITE        ; temporary RW permissions while bytes are copied and bss is cleared
           mov r10, MAP_PRIVATE or MAP_ANON or MAP_FIXED   ; force this PT_LOAD to land exactly inside the reserved span
           mov r8, -1
           xor r9, r9
           mov rax, SYS_MMAP
           syscall
           test rax, rax
           js mmapFailed
           pop r9                                  ; restore the running program header file offset for the outer loop
           lea rsi, [dbgMapMainMsg]                
           mov rdx, dbgMapMainMsgLen
           mov rax, [baseAddr]
           add rax, r15
           call debugPrintHexLine
; copy the segment contents from the in-memory ELF image
           mov r10, [phdr.offset]                 
           mov r11, [phdr.vaddr]                 
           lea rsi, [buffer + r10]
           mov rdi, [baseAddr]
           add rdi, r11
           mov rcx, [phdr.filesz]
           .memcpy:
               test rcx, rcx                      ; stop once every file segment byte has been copied
               jz .memcpyDone
               lodsb                              ; AL = *rsi, then rsi is the next staged source byte
               stosb                              ; *rdi = AL, then rdi is the next runtime destination byte
               loop .memcpy                       
           .memcpyDone:
; fill .bss with zeros if it exists
           mov r10, [phdr.memsz]
           mov r11, [phdr.filesz]
           cmp r10, r11                           ; if memsz <= filesz, there is no bss tail to clear
           jl .bssIgnore
           sub r10, r11                           ; count of implicit zero bytes that belong to the segment's bss tail
           mov rcx, r10                           ; byte count for rep stosb
           mov r10, [phdr.vaddr]
           mov rdi, [baseAddr]
           add rdi, r10
           add rdi, r11
           mov al, 0                              ; AL=0 so rep stosb writes zero bytes into the bss tail
           rep stosb                              ; memset(segmentStart + filesz, 0, memsz - filesz)
; set phdr protections
           .bssIgnore:
               mov r8d, [phdr.flags]              ; ELF PF_* bits that describe the segment's final permissions
               ELF_FLAGS_TO_PROT r8d, edx
               .phdrProtect:                        ; tighten the populated PT_LOAD mapping to its final ELF permissions
                   pop r13                          ; restore the page rounded mapping size saved before mmap
                   pop r15                           ; restore the page aligned mapping start saved before mmap
                   mov rdi, [baseAddr]
                   add rdi, r15
                   mov rsi, r13
                   mov rax, SYS_MPROTECT
                   syscall                      ; replace the temporary RW mapping permissions with the ELF final ones
                   test rax, rax
                   js mprotectFailed
    .next_phdr:
        inc bx
        cmp bx, word [ehdr.phnum]                 ; compare the processed count against e_phnum
        jge interp                                ; once all phdrs are done, choose direct entry vs PT_INTERP handoff
        movzx r10, word [ehdr.phentsize]          
        add r9, r10
        jmp .loopPhdr
; Once the single SHELF PT_LOAD segment is mapped, the `jge interp` above
; jumps straight into loader/reloc.inc's `interp:` label, which either
; applies relocations itself or hands off to prepareTlsAndStack when there
; is nothing to relocate.
;
; PT_INTERP is rejected earlier, so this loader always stays on
; the direct entry path

include "loader/reloc.inc"
loadInterp:
    jmp unsupportedInterp
include "loader/stack.inc"
forkTransformExec:
    jmp unsupportedType
; Error/reporting paths.
;
; These stay syscall only and simple so they remain usable even
; if startup fails before a target libc, TLS block, or interpreter exists
unsupportedType:
    lea rsi, [unsupportedTypeMsg]
    mov rdx, unsupportedTypeMsgLen
    jmp writeError

unsupportedInterp:
    lea rsi, [unsupportedInterpMsg]
    mov rdx, unsupportedInterpMsgLen
    jmp writeError

unsupportedReloc:
    lea rsi, [unsupportedRelocMsg]
    mov rdx, unsupportedRelocMsgLen
    jmp writeError

invalidShelf:
    lea rsi, [invalidShelfMsg]
    mov rdx, invalidShelfMsgLen
    jmp writeError

stackStorageTooSmall:
    lea rsi, [stackStorageTooSmallMsg]
    mov rdx, stackStorageTooSmallMsgLen
    jmp writeError

openFailed:
    lea rsi, [openFailedMsg]
    mov rdx, openFailedMsgLen
    jmp writeError

fstatFailed:
    lea rsi, [fstatFailedMsg]
    mov rdx, fstatFailedMsgLen
    jmp writeError

headerReadFailed:
    lea rsi, [headerReadFailedMsg]
    mov rdx, headerReadFailedMsgLen
    jmp writeError

fileTooLarge:
    lea rsi, [fileTooLargeMsg]
    mov rdx, fileTooLargeMsgLen
    jmp writeError

fileReadFailed:
    lea rsi, [fileReadFailedMsg]
    mov rdx, fileReadFailedMsgLen
    jmp writeError

closeFailed:
    lea rsi, [closeFailedMsg]
    mov rdx, closeFailedMsgLen
    jmp writeError

mmapFailed:
    lea rsi, [mmapFailedMsg]
    mov rdx, mmapFailedMsgLen
    jmp writeError

phdrReadFailed:
    lea rsi, [phdrReadFailedMsg]
    mov rdx, phdrReadFailedMsgLen
    jmp writeError

mprotectFailed:
    lea rsi, [mprotectFailedMsg]
    mov rdx, mprotectFailedMsgLen
    jmp writeError

archPrctlFailed:
    lea rsi, [archPrctlFailedMsg]
    mov rdx, archPrctlFailedMsgLen
    jmp writeError

writeError:
    mov rdi, STDERR                               ;
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1                           
    jmp exit

; Debug helpers.
;
; These helpers are tiny and syscall only. They never depend on
; libc and they only emit output when debugEnabled is non zero
debugWrite:
    cmp byte [debugEnabled], 0                    ; leave immediately when runtime tracing is disabled
    je .done
    push rax                                      ; preserve the caller's registers across the syscall
    push rdi
    push rcx
    push r11
    mov rdi, STDERR                               
    mov rax, SYS_WRITE
    syscall
    pop r11
    pop rcx
    pop rdi
    pop rax
    .done:
    ret

debugPrintHexLine:
    ; Inputs:
    ;   rsi = prefix string
    ;   rdx = prefix length
    ;   rax = 64 bit value to print as 0xhhhhhhhhhhhhhhhh\n
    ;
    ; The helper preserves caller registers so it is cheap to drop into
    ; interesting points in the loader without disturbing the surrounding code
    cmp byte [debugEnabled], 0
    je .done
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r11

    mov rdi, STDERR                
    mov rax, SYS_WRITE
    syscall

    pop r11
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r11

    lea rdi, [debugHexBuf]                        ; use the shared scratch buffer for "0x" + 16 hex digits + "\n"
    mov byte [rdi], '0'
    mov byte [rdi + 1], 'x'
    lea rsi, [hexDigits]                          ; "0123456789abcdef"
    mov rbx, rax                                  ; copy the value so we can shift nibbles out of rbx
    lea rdi, [debugHexBuf + 2]
    mov rcx, 16                                   ; 64 bit values render as exactly 16 hex nibbles
    .hexLoop:
        mov r8, rbx
        shr r8, 60                                ; move the highest nibble down to the low 4 bits
        mov dl, [rsi + r8]
        mov [rdi], dl
        inc rdi
        shl rbx, 4                                ; expose the next nibble by shifting left
        dec rcx
        jnz .hexLoop
    mov byte [rdi], 0xa
    mov rdi, STDERR
    lea rsi, [debugHexBuf]
    mov rdx, 19                                   ; 2 prefix bytes + 16 digits + 1 newline
    mov rax, SYS_WRITE
    syscall

    pop r11
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    .done:
    ret
    
usage:
    lea rsi, [versionMsg]
    mov rdx, versionMsgLen
    mov rdi, STDOUT
    mov rax, SYS_WRITE
    syscall
    lea rsi, [usageMsg]
    mov rdx, usageMsgLen
    mov rdi, STDOUT
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1
    jmp exit
invalidElf:
    lea rsi, [invalidElfMsg]
    mov rdx, invalidElfMsgLen
    mov rdi, STDOUT
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1
    jmp exit

invalidLayout:
    lea rsi, [invalidLayoutMsg]
    mov rdx, invalidLayoutMsgLen
    mov rdi, STDOUT
    mov rax, SYS_WRITE
    mov [exitStatus], 1
    jmp exit

invalidSegment:
    lea rsi, [invalidSegmentMsg]
    mov rdx, invalidSegmentMsgLen
    mov rdi, STDOUT
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1
    jmp exit

invalidArch:
    lea rsi, [invalidArchMsg]
    mov rdx, invalidArchMsgLen
    mov rdi, STDOUT
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1
; Final process exit.
;
; All success and failure paths converge here after placing the desired exit
; status byte into exitStatus
exit:
    mov dil, byte [exitStatus]                    ; place the final 8 bit exit status into the first syscall argument register
    mov rax, SYS_EXIT
    syscall
segment readable
include "loader/rodata.inc"

segment readable writeable
include "loader/rwdata.inc"
