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
    ; target program's future environment
    lea rbx, [rsp + rcx * 8 + 16]                 ; first envp entry after argv[] and its NULL
    call scanDebugEnv
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
include "loader/validate.inc"
; Allocate the synthetic target stack mapping. Creates the RW stack mapping
; that later phases will populate, reserves enough room for argv/envp/auxv
; pointer tables and copied string payloads, but does not write the final
; stack contents yet, later phases may still need to patch auxv values
; based on TLS decisions
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
; Main image program header walk. scanDynImage already recorded PT_DYNAMIC
; and PT_TLS and checked the table fits in the staged file, so this walk reads
; the same staged headers, applies PT_GNU_STACK, maps the one PT_LOAD segment
; RW, populates it, zeroes bss, then mprotects it to the final PF_*
; permissions, and computes phdrRuntime for AT_PHDR if the phdr table lives
; inside the one load segment
processPhdrs:
    mov qword [phdrRuntime], 0
    lea r12, [buffer]
    add r12, [ehdr.phoff]                         ; r12 walks the staged phdr table
    movzx ebx, word [ehdr.phnum]                  ; rbx counts the headers left
    .loopPhdr:
        test rbx, rbx
        jz relocate                               ; all phdrs done, apply relocations next
        mov rsi, r12
        lea rdi, [phdr]
        mov ecx, sizeof.PHDR
        rep movsb
        cmp dword [phdr.type], PT_GNU_STACK
        jne .notStack
            mov r8d, [phdr.flags]
            ELF_FLAGS_TO_PROT r8d, edx
            mov [stackProt], dl                   ; install the final stack protection derived from PT_GNU_STACK
            mov rdi, [stackAddr]
            mov rsi, STACK_SIZE
            mov rax, SYS_MPROTECT
            syscall
            test rax, rax
            js mprotectFailed
        .notStack:
            cmp dword [phdr.type], PT_LOAD
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
            mov r14, [phdr.vaddr]
            sub r14, r15                          ; in-page offset from the rounded base to the true segment start
            mov r13, [phdr.memsz]                 ; unrounded in-memory segment size from p_memsz
            add r13, r14                          ; include the in-page offset so the mapping fully covers the segment bytes
            add r13, PAGE_SIZE - 1                ; bias upward before rounding the mapping size to a whole page count
            and r13, -PAGE_SIZE
; Map a writable scratch view for this segment, populate it, then tighten
; protections to match the ELF flags
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
           lea rsi, [dbgMapMainMsg]
           mov rdx, dbgMapMainMsgLen
           mov rax, [baseAddr]
           add rax, r15
           call debugPrintHexLine
; copy the segment contents from the in-memory ELF image
           lea rsi, [buffer]
           add rsi, [phdr.offset]
           mov rdi, [baseAddr]
           add rdi, [phdr.vaddr]
           mov rcx, [phdr.filesz]
           rep movsb
; fill .bss with zeros, rdi already sits at segmentStart + filesz
           mov rcx, [phdr.memsz]
           sub rcx, [phdr.filesz]                 ; filesz <= memsz was checked above
           xor eax, eax
           rep stosb
; set phdr protections
           mov r8d, [phdr.flags]                  ; ELF PF_* bits that describe the segment's final permissions
           ELF_FLAGS_TO_PROT r8d, edx
           mov rdi, [baseAddr]
           add rdi, r15
           mov rsi, r13
           mov rax, SYS_MPROTECT
           syscall                                ; replace the temporary RW mapping permissions with the ELF final ones
           test rax, rax
           js mprotectFailed
    .next_phdr:
        add r12, sizeof.PHDR
        dec rbx
        jmp .loopPhdr

include "loader/reloc.inc"
include "loader/stack.inc"
include "loader/common.inc"

; Error exits only halfshelf reaches. They all go through writeError, so
; every message lands on stderr
unsupportedType:
    lea rsi, [unsupportedTypeMsg]
    mov rdx, unsupportedTypeMsgLen
    jmp writeError

unsupportedInterp:
    lea rsi, [unsupportedInterpMsg]
    mov rdx, unsupportedInterpMsgLen
    jmp writeError

invalidShelf:
    lea rsi, [invalidShelfMsg]
    mov rdx, invalidShelfMsgLen
    jmp writeError

headerReadFailed:
    lea rsi, [headerReadFailedMsg]
    mov rdx, headerReadFailedMsgLen
    jmp writeError

invalidElf:
    lea rsi, [invalidElfMsg]
    mov rdx, invalidElfMsgLen
    jmp writeError

invalidLayout:
    lea rsi, [invalidLayoutMsg]
    mov rdx, invalidLayoutMsgLen
    jmp writeError

invalidSegment:
    lea rsi, [invalidSegmentMsg]
    mov rdx, invalidSegmentMsgLen
    jmp writeError

invalidArch:
    lea rsi, [invalidArchMsg]
    mov rdx, invalidArchMsgLen
    jmp writeError

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

segment readable
include "loader/rodata.inc"

segment readable writeable
include "loader/rwdata.inc"
