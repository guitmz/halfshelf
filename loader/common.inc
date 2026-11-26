; Code shared by halfshelf and headshelf. Debug tracing, the error exits both
; loaders reach, and the final exit. Everything here is syscall only so it
; still works before the target has a libc, TLS block or stack of its own

; Turn tracing on when the loader's own environment has HALFSHELF_DEBUG set to
; anything other than empty or "0". Takes rbx = envp, clobbers rbx rdx rdi rsi
scanDebugEnv:
    mov byte [debugEnabled], 0
    .nextEnv:
        mov rdi, [rbx]
        test rdi, rdi                             ; NULL ends envp
        jz .done
        lea rsi, [debugEnvPrefix]
        mov rdx, debugEnvPrefixLen
        .cmp:
            test rdx, rdx                         ; every prefix byte matched
            jz .matched
            mov al, [rdi]
            cmp al, [rsi]
            jne .skip
            inc rdi
            inc rsi
            dec rdx
            jmp .cmp
        .matched:
            mov al, [rdi]
            test al, al                           ; present but empty means off
            jz .skip
            cmp al, '0'
            je .skip
            mov byte [debugEnabled], 1
            lea rsi, [versionMsg]
            mov rdx, versionMsgLen
            call debugWrite
            lea rsi, [dbgEnabledMsg]
            mov rdx, dbgEnabledMsgLen
            call debugWrite
            ret
        .skip:
        add rbx, 8
        jmp .nextEnv
    .done:
    ret

; Write rsi/rdx to stderr when tracing is on. Preserves every register
debugWrite:
    cmp byte [debugEnabled], 0
    je .done
    push rax
    push rdi
    push rcx
    push r11                                      ; syscall clobbers rcx and r11
    mov rdi, STDERR
    mov rax, SYS_WRITE
    syscall
    pop r11
    pop rcx
    pop rdi
    pop rax
    .done:
    ret

; Write the rsi/rdx prefix, then rax as 0x plus 16 hex digits and a newline.
; Preserves every register
debugPrintHexLine:
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
    mov rbx, rax                                  ; the prefix write below overwrites rax with its result
    mov rdi, STDERR
    mov rax, SYS_WRITE
    syscall
    mov byte [debugHexBuf], '0'
    mov byte [debugHexBuf + 1], 'x'
    lea rsi, [hexDigits]
    lea rdi, [debugHexBuf + 2]
    mov rcx, 16
    .hexLoop:
        mov r8, rbx
        shr r8, 60                                ; top nibble first
        mov dl, [rsi + r8]
        mov [rdi], dl
        inc rdi
        shl rbx, 4
        dec rcx
        jnz .hexLoop
    mov byte [rdi], 0xa
    mov rdi, STDERR
    lea rsi, [debugHexBuf]
    mov rdx, 19                                   ; 2 prefix bytes, 16 digits, 1 newline
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

unsupportedReloc:
    lea rsi, [unsupportedRelocMsg]
    mov rdx, unsupportedRelocMsgLen
    jmp writeError

invalidTls:
    lea rsi, [invalidTlsMsg]
    mov rdx, invalidTlsMsgLen
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

mprotectFailed:
    lea rsi, [mprotectFailedMsg]
    mov rdx, mprotectFailedMsgLen
    jmp writeError

archPrctlFailed:
    lea rsi, [archPrctlFailedMsg]
    mov rdx, archPrctlFailedMsgLen
    jmp writeError

; Every failure ends here. Diagnostics go to stderr so they never mix with
; the target's stdout
writeError:
    mov rdi, STDERR
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1

exit:
    mov dil, byte [exitStatus]
    mov rax, SYS_EXIT
    syscall
