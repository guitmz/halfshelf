; Direct entry relocation handling for ET_DYN. It just knows specific kinds of
; relocations that we actually need and nothing else
relocate:
    cmp byte [hasDynamic], 0
    je prepareTlsAndStack
    lea rsi, [dbgRelocMsg]
    mov rdx, dbgRelocMsgLen
    call debugWrite
    ; Read PT_DYNAMIC once to find the RELA/JMPREL tables and their sizes.
    ; If the target wants more than RELATIVE/IRELATIVE world, let's bail
    mov rsi, [baseAddr]
    add rsi, [dynamicVaddr]
    mov rcx, [dynamicSize]
    shr rcx, 4
    .parseDynamic:
        test rcx, rcx
        jz .dynamicParsed
        mov rax, [rsi + DYN.tag]                  ; DYN.tag says which field this entry carries (DT_RELA, DT_RELASZ, etc)
        mov rdx, [rsi + DYN.val]
        cmp rax, DT_NULL                          ; DT_NULL terminates the dynamic table early
        je .dynamicParsed
        cmp rax, DT_RELA
        jne .notDtRela
        mov [relaAddr], rdx
        jmp .nextDynamic
        .notDtRela:
        cmp rax, DT_RELASZ
        jne .notDtRelaSz
        mov [relaSize], rdx
        jmp .nextDynamic
        .notDtRelaSz:
        cmp rax, DT_RELAENT
        jne .notDtRelaEnt
        mov [relaEnt], rdx                        ; checked against sizeof.RELA below rather than trusted
        jmp .nextDynamic
        .notDtRelaEnt:
        cmp rax, DT_JMPREL
        jne .notDtJmpRel
        mov [jmprelAddr], rdx
        jmp .nextDynamic
        .notDtJmpRel:
        cmp rax, DT_PLTRELSZ
        jne .notDtPltRelSz
        mov [jmprelSize], rdx
        jmp .nextDynamic
        .notDtPltRelSz:
        cmp rax, DT_PLTREL
        jne .nextDynamic
        mov [pltrelType], rdx                     ; DT_PLTREL says whether JMPREL holds Elf64_Rela or Elf64_Rel entries, only the Rela encoding is handled here
        .nextDynamic:
        add rsi, sizeof.DYN
        dec rcx
        jmp .parseDynamic
    .dynamicParsed:
    ; x64 entries are always Elf64_Rela, so a missing DT_RELAENT (a binary with
    ; only JMPREL) is fine, any other size is not
    cmp qword [relaEnt], 0
    je .relaEntOk
    cmp qword [relaEnt], sizeof.RELA
    jne unsupportedReloc
    .relaEntOk:
    cmp qword [pltrelType], 0
    je .pltrelOk
    cmp qword [pltrelType], DT_RELA
    jne unsupportedReloc
    .pltrelOk:
    ; Plain RELATIVE pointers first, in both tables, so the IRELATIVE resolvers
    ; called in the second pass already run against a fixed up image. Some
    ; static PIEs put entries of either kind in JMPREL instead of RELA
    mov r12, R_X86_64_RELATIVE
    mov rsi, [relaAddr]
    mov rcx, [relaSize]
    call applyRelaTable
    mov rsi, [jmprelAddr]
    mov rcx, [jmprelSize]
    call applyRelaTable
    mov r12, R_X86_64_IRELATIVE
    mov rsi, [relaAddr]
    mov rcx, [relaSize]
    call applyRelaTable
    mov rsi, [jmprelAddr]
    mov rcx, [jmprelSize]
    call applyRelaTable
    jmp prepareTlsAndStack

; Apply one pass over one Elf64_Rela table.
;   rsi = table vaddr, rcx = table size in bytes, r12 = the type this pass applies
; RELATIVE writes base + addend. IRELATIVE calls the resolver at base + addend
; and writes its answer. Any other type bails, since only a real dynamic
; linker could resolve it
applyRelaTable:
    mov rax, rcx
    xor edx, edx
    mov r8, sizeof.RELA
    div r8                                        ; entry count
    mov rcx, rax
    add rsi, [baseAddr]
    .loop:
        test rcx, rcx
        jz .done
        mov eax, dword [rsi + RELA.info]          ; the type is the low half of r_info, the symbol index is unused
        cmp eax, R_X86_64_RELATIVE
        je .known
        cmp eax, R_X86_64_IRELATIVE
        jne unsupportedReloc
        .known:
        cmp rax, r12
        jne .next
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]              ; the slot to patch
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]
        cmp r12, R_X86_64_IRELATIVE
        jne .store
        ; Entry rsp is 16 byte aligned and nothing on the way here is left
        ; pushed, so the return address plus these 3 pushes keep the resolver
        ; call ABI aligned. r12 is callee saved, the resolver keeps it
        push rcx
        push rsi
        push rdi
        call rax
        pop rdi
        pop rsi
        pop rcx
        .store:
        mov [rdi], rax
        .next:
        add rsi, sizeof.RELA
        dec rcx
        jmp .loop
    .done:
    ret
