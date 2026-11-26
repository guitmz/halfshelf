; Direct entry TLS setup (I hated this very much, took me like 1 year of work).
;
; This file owns the two ABI sensitive chores nobody really gets for free here:
;   * fake just enough TLS for direct entry PT_TLS binaries
;   * rebuild a kernel like initial stack with patched auxv values

prepareTlsAndStack:
    cmp byte [hasTls], 0
    je prepareStackImage
    ; An initializer bigger than the block would make the zero fill below
    ; count backwards through memory
    mov rax, [tlsFilesz]
    cmp rax, [tlsMemsz]
    ja invalidTls
    lea rsi, [dbgTlsMsg]
    mov rdx, dbgTlsMsgLen
    call debugWrite
    ; x64 TLS is variant II. The block ends at the thread pointer and starts at
    ; tp minus roundup(p_memsz, p_align), the same offset the linker baked into
    ; every %fs relative access. Placing it at tp minus p_memsz shifts every
    ; variable whenever p_memsz is not a multiple of p_align
    mov rax, [tlsAlign]
    test rax, rax
    jnz .tlsAlignReady
    mov rax, 1                                    ; zero = no special alignment
    .tlsAlignReady:
    mov rcx, [tlsMemsz]
    add rcx, rax
    dec rcx
    mov rdx, rax
    neg rdx
    and rcx, rdx
    mov [tlsMemszAligned], rcx
    cmp rax, 16                                   ; the TCB itself still gets at least 16 byte alignment
    jae .tlsAlignSized
    mov rax, 16
    .tlsAlignSized:
    ; Layout is
    ;   [TLS block][TCB][small DTV]
    ;
    ; Then FS points at the TCB. Minimal, yes, but enough for the cases we care
    mov [tlsAlignWork], rax
    mov rcx, [tlsMemszAligned]
    add rcx, TLS_TCB_SIZE + TLS_DTV_SIZE          ; reserve extra room for the TCB and tiny DTV after the TLS block
    add rcx, rax                                  ; add enough slack to round the TCB up to its required alignment
    add rcx, 15
    and rcx, -16                                  ; final anonymous mapping length for the direct entry TLS area
    mov rdi, 0                                    ; let the kernel choose the TLS mapping address
    mov rsi, rcx
    mov rdx, PROT_READ or PROT_WRITE
    mov r10, MAP_PRIVATE or MAP_ANON
    mov r8, -1
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    ; TCB goes right after the rounded block, aligned up. The TCB alignment is
    ; a multiple of p_align, so the block start below is p_align aligned too
    mov rdi, rax
    add rdi, [tlsMemszAligned]
    mov rax, [tlsAlignWork]
    dec rax
    add rdi, rax
    not rax
    and rdi, rax
    mov [tlsTcb], rdi
    mov rax, rdi
    sub rax, [tlsMemszAligned]
    mov [tlsBlock], rax
    mov rdi, rax
    mov rsi, [baseAddr]
    add rsi, [tlsVaddr]
    ; Copy the initializer bytes, then zero the tail if there is one. The
    ; padding between the block and the TCB is already zero from mmap
    mov rcx, [tlsFilesz]
    rep movsb
    mov rcx, [tlsMemsz]
    sub rcx, [tlsFilesz]
    xor eax, eax
    rep stosb
    mov rdi, [tlsTcb]
    mov rax, rdi                                  ; copy the TCB pointer into rax for self referential TCB fields
    mov [rdi], rax
    lea rax, [rdi + TLS_TCB_SIZE + 16]
    mov [rdi + 8], rax
    mov [rdi + 16], rdi
    ; Seed a tiny DTV that describes one TLS module starting at tlsBlock
    lea rsi, [rdi + TLS_TCB_SIZE]
    mov qword [rsi], 1
    mov qword [rsi + 8], 0
    mov qword [rsi + 16], 1
    mov qword [rsi + 24], 0
    mov rax, [tlsBlock]
    mov [rsi + 32], rax
    mov qword [rsi + 40], 0
    mov rdi, ARCH_SET_FS                          ; arch_prctl subcommand selecting FS base installation
    mov rsi, [tlsTcb]
    mov rax, SYS_ARCH_PRCTL
    syscall
    test rax, rax
    js archPrctlFailed

prepareStackImage:
    ; Rebuild a kernel initial stack in loader memory:
    ;   argc
    ;   argv[]
    ;   NULL
    ;   envp[]
    ;   NULL
    ;   auxv[]
    ;
    ; We also duplicate the pointed to strings and aux payloads so the loaded
    ; program does not keep pointers into the loader's own stack by accident
    lea rsi, [dbgStackBuildMsg]
    mov rdx, dbgStackBuildMsgLen
    call debugWrite
    mov rbx, [targetArgv]                         ; pointer to argv[0] in the loader's original startup stack
    mov rcx, [targetArgc]                         ; number of target argv entries, including argv[0]
    lea rdx, [rbx + rcx * 8 + 8]                  ; skip argv[] plus its trailing NULL to reach envp[0]
    mov [targetEnvp], rdx
    mov rsi, rdx                                  ; rsi walks the original envp vector while we look for auxv
    .findAuxv:
        mov rax, [rsi]
        add rsi, 8
        test rax, rax                             ; NULL marks the end of envp and the beginning of auxv
        jnz .findAuxv
    mov [targetAuxv], rsi
    mov rdx, [targetEnvp]
    xor rcx, rcx
    .countEnvp:
        mov rax, [rdx]
        add rdx, 8
        inc rcx                                   ; count one more envp slot, including the eventual NULL
        test rax, rax
        jnz .countEnvp
    dec rcx
    mov [targetEnvc], rcx
    mov rsi, [targetAuxv]
    xor rcx, rcx
    .countAuxv:
        mov rax, [rsi]
        add rsi, 16                               ; auxv entries are 16 bytes (a_type + a_val), so skip by 16
        inc rcx                                    ; count one more auxv entry, including the AT_NULL terminator
        test rax, rax                             ; AT_NULL has type 0 and ends the auxv vector
        jnz .countAuxv
    mov [targetAuxc], rcx
    xor rcx, rcx
    ; First count how many string bytes we are about to duplicate. If the
    ; reserved stack storage is too small, bail out now instead of half
    ; building a stack
    mov rsi, [targetArgv]
    mov rdx, [targetArgc]
    .countArgStrings:
        test rdx, rdx
        jz .countEnvStrings
        mov rdi, [rsi]                            ; pointer to the current argument string
        .countArgStringBytes:
            inc rcx                               ; account for the next byte in totalStringBytes
            mov al, [rdi]
            inc rdi
            test al, al                           ; the first NUL byte ends this argument string
            jnz .countArgStringBytes
        add rsi, 8
        dec rdx
        jmp .countArgStrings
    .countEnvStrings:
    mov rsi, [targetEnvp]
    mov rdx, [targetEnvc]
    .countEnvStringsLoop:
        test rdx, rdx
        jz .countStringsDone
        mov rdi, [rsi]
        .countEnvStringBytes:
            inc rcx
            mov al, [rdi]
            inc rdi
            test al, al
            jnz .countEnvStringBytes
        add rsi, 8
        dec rdx
        jmp .countEnvStringsLoop
    .countStringsDone:
    mov [totalStringBytes], rcx
    cmp rcx, STACK_STRING_SIZE
    jg stackStorageTooSmall
    mov rax, [stackAddr]
    add rax, STACK_STORAGE_SIZE
    mov [stringWritePtr], rax
    mov rax, [stackAddr]
    add rax, STACK_SIZE
    and rax, -16
    ; The ABI wants rsp 16 byte aligned at entry. Below the top go auxv (a
    ; multiple of 16 bytes) and argc, argv, NULL, envp, NULL, which is
    ; argc + envc + 3 words. Drop one extra word when that count is odd
    mov rcx, [targetEnvc]
    add rcx, [targetArgc]
    test rcx, 1
    jnz .stackTopReady
    sub rax, 8
    .stackTopReady:
    mov [newStackPtr], rax
    ; Pointer tables go downward from the top:
    ;   auxv, then envp, then argv, then argc
    ;
    ; Copied strings and aux payloads grow upward from stringWritePtr.
    ; That split keeps ownership obvious and avoids leaving target pointers
    ; aimed at the loader's original entry stack
    mov rdi, [newStackPtr]
    mov rcx, [targetAuxc]
    shl rcx, 4
    sub rdi, rcx
    mov [auxvDst], rdi
    mov rsi, [targetAuxv]
    mov rcx, [targetAuxc]
    .copyAuxv:
        ; Auxv copy/patch pass.
        ;
        ; Most entries survive unchanged, but some values must be rewritten
        ; because the loader changed image placement, entry routing, or the
        ; storage backing the strings/payloads they point at
        mov rax, [rsi]
        mov r8, [rsi + 8]
        cmp rax, AT_PHDR
        jne .auxNotPhdr
        mov r8, [phdrRuntime]
        jmp .auxStore
        .auxNotPhdr:
        cmp rax, AT_PHENT
        jne .auxNotPhent
        movzx r8, word [ehdr.phentsize]
        jmp .auxStore
        .auxNotPhent:
        cmp rax, AT_PHNUM
        jne .auxNotPhnum
        movzx r8, word [ehdr.phnum]               ; AT_PHNUM should report the main executable's phdr count
        jmp .auxStore
        .auxNotPhnum:
        cmp rax, AT_BASE
        jne .auxNotBase
        xor r8d, r8d                              ; no interpreter is ever loaded, so there is no interpreter base
        jmp .auxStore
        .auxNotBase:
        cmp rax, AT_ENTRY                          ; AT_ENTRY should always describe the main programs entry point
        jne .auxNotEntry
        mov r8, [baseAddr]
        add r8, [ehdr.entry]
        jmp .auxStore
        .auxNotEntry:
        cmp rax, AT_EXECFN                        ; AT_EXECFN should reference the executable pathname string
        jne .auxNotExecfn
        mov r8, [targetPath]                      ; later we repoint it at the copied argv[0] storage
        jmp .auxStore
        .auxNotExecfn:
        cmp rax, AT_RANDOM
        jne .auxNotRandom
        ; AT_RANDOM points at 16 random bytes, not a C string, so copy the
        ; payload as is and then patch the auxv value to the copied address
        push rcx
        push rax
        mov r9, [stringWritePtr]                  ; next free byte in the target copied string storage area
        mov [rdi + 8], r9                         ; temporarily store the copied AT_RANDOM destination pointer into auxv
        mov r10, [rsi + 8]                        ; original AT_RANDOM payload pointer from the loader's own auxv
        mov rcx, 16                               ; AT_RANDOM always points at exactly 16 bytes of random data
        .copyAuxRandom:
            mov dl, [r10]
            mov [r9], dl
            inc r9
            inc r10
            loop .copyAuxRandom
        mov [stringWritePtr], r9                  ; commit the new end of the copied payload/string area
        pop rax                                   ; restore the auxv type value we are currently processing
        pop rcx
        mov r8, [rdi + 8]                         ; replacement AT_RANDOM pointer that now targets storage
        jmp .auxStore
        .auxNotRandom:
        cmp rax, AT_PLATFORM
        je .copyAuxString
        cmp rax, AT_BASE_PLATFORM
        jne .auxStore
        .copyAuxString:
        ; These auxv entries point at NUL terminated strings that also need to
        ; move onto the target stack image
        push rcx
        push rax
        mov r9, [stringWritePtr]
        mov [rdi + 8], r9
        mov r10, [rsi + 8]                        ; original auxv string pointer (AT_PLATFORM / AT_BASE_PLATFORM)
        .copyAuxCString:
            mov dl, [r10]
            mov [r9], dl
            inc r9
            inc r10
            test dl, dl                           ; stop after copying the terminating NUL byte
            jnz .copyAuxCString
        mov [stringWritePtr], r9
        pop rax
        pop rcx
        mov r8, [rdi + 8]
        .auxStore:
        mov [rdi], rax
        mov [rdi + 8], r8
        add rsi, 16
        add rdi, 16
        dec rcx
        jnz .copyAuxv
    mov rdi, [auxvDst]                            ; start from the lowest address occupied by the rebuilt auxv array
    mov rax, [targetEnvc]
    inc rax                                       ; reserve one extra slot for the terminating envp NULL
    shl rax, 3
    sub rdi, rax                                  ; place envp immediately below auxv in the downward built stack image
    mov [envpDst], rdi
    mov rdi, [envpDst]
    mov rsi, [targetEnvp]
    mov rcx, [targetEnvc]
    .copyEnvStrings:
        ; Environment vector rewrite.
        ;
        ; Each envp[i] pointer is rewritten to point at a copied string owned
        ; by the synthetic stack mapping instead of the loader's original
        ; startup stack
        test rcx, rcx
        jz .copyEnvStringsDone
        mov r8, [stringWritePtr]                  ; destination address for the copied current environment string
        mov [rdi], r8                             ; rewrite envp[i] to point at that copied target string
        mov r9, [rsi]                             ; source pointer to the original environment string
        .copyOneEnvString:
            mov al, [r9]
            mov [r8], al
            inc r8
            inc r9
            test al, al                           ; stop after copying the terminating NUL byte
            jnz .copyOneEnvString
        mov [stringWritePtr], r8                  ; commit the new end of the copied string storage area
        add rdi, 8
        add rsi, 8
        dec rcx
        jmp .copyEnvStrings
    .copyEnvStringsDone:
    mov qword [rdi], 0                            ; write the mandatory terminating NULL after the rebuilt envp table
    mov rdi, [envpDst]
    mov rax, [targetArgc]
    inc rax
    shl rax, 3
    sub rdi, rax
    mov [argvDst], rdi
    mov rdi, [argvDst]
    mov rsi, [targetArgv]
    mov rcx, [targetArgc]
    .copyArgStrings:
        ; Argument vector rewrite.
        ;
        ; argv is treated exactly like envp: rewrite pointer slots downward,
        ; copy actual string bytes upward into target storage
        test rcx, rcx
        jz .copyArgStringsDone
        mov r8, [stringWritePtr]
        mov [rdi], r8
        mov r9, [rsi]
        .copyOneArgString:
            mov al, [r9]
            mov [r8], al
            inc r8
            inc r9
            test al, al
            jnz .copyOneArgString
        mov [stringWritePtr], r8
        add rdi, 8
        add rsi, 8
        dec rcx
        jmp .copyArgStrings
    .copyArgStringsDone:
    mov qword [rdi], 0
    mov rax, [argvDst]
    mov rax, [rax]                                ; load the copied argv[0] string pointer itself
    mov [targetPathNew], rax                      ; remember the copied executable path for the later AT_EXECFN patch
    mov rsi, [auxvDst]
    mov rcx, [targetAuxc]
    .patchExecfnAuxv:
        ; AT_EXECFN should reference the copied argv[0] string, not the old
        ; pointer into the loader's original stack
        test rcx, rcx
        jz .patchExecfnDone
        mov rax, [rsi]
        cmp rax, AT_EXECFN                        ; only the AT_EXECFN entry needs a second patching pass here
        jne .nextExecfnAuxv
        mov rax, [targetPathNew]
        mov [rsi + 8], rax                        ; rewrite auxv.a_val so the target sees the executable path
        jmp .patchExecfnDone
        .nextExecfnAuxv:
        add rsi, 16
        dec rcx
        jmp .patchExecfnAuxv
    .patchExecfnDone:
    ; After argv/envp/auxv are laid out, prepend argc immediately below them.
    ; That final pointer is what the target entry code will observe in rsp.
    mov rdi, [argvDst]
    sub rdi, 8                                    ; reserve one machine word immediately below it for argc
    mov rax, [targetArgc]
    mov [rdi], rax
    mov [newStackPtr], rdi                         ; remember the exact rsp value that should be installed at handoff

    ; The stack image is complete and every target byte that matters already
    ; lives in anonymous mappings, so the staged file descriptor can go
    mov rdi, [targetFd]
    mov rax, SYS_CLOSE
    syscall
    test rax, rax                               ; negative return means close(2) failed
    js closeFailed

    mov r11, [baseAddr]
    add r11, [ehdr.entry]                         ; direct entry runtime address of the main executable's entry point
    lea rsi, [dbgJumpMainMsg]
    mov rdx, dbgJumpMainMsgLen
    mov rax, r11
    call debugPrintHexLine
    ENTER_PREPARED_IMAGE newStackPtr, r11
