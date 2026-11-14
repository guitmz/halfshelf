; Direct entry relocation handling for ET_DYN. It just knows specific kinds of
; relocations that we actually need and nothing else
interp:
    cmp byte [hasInterp], 0
    jne loadInterp
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
        mov [relaEnt], rdx                        ; relaEnt is trusted from the dynamic table, then checked against sizeof.RELA below rather than assumed
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
        jne .notDtPltRel
        mov [pltrelType], rdx                     ; DT_PLTREL says whether JMPREL holds Elf64_Rela or Elf64_Rel entries, only the Rela encoding is handled here
        jmp .nextDynamic
        .notDtPltRel:
        cmp rax, DT_RELACOUNT
        jne .nextDynamic
        .nextDynamic:
        add rsi, sizeof.DYN
        dec rcx
        jmp .parseDynamic
    .dynamicParsed:
    ; No RELA table means nothing for us to do here
    cmp qword [relaEnt], 0
    je prepareTlsAndStack
    cmp qword [relaEnt], sizeof.RELA
    jne unsupportedReloc
    cmp qword [pltrelType], 0
    je .applyRelaRelative
    cmp qword [pltrelType], DT_RELA
    jne unsupportedReloc
    ; Pass 1: plain RELATIVE relocations.
    ;
    ; Write (base + addend) into (base + offset) and continue. Do this first so
    ; later passes operate against a simpler image
    .applyRelaRelative:
    mov rsi, [baseAddr]
    add rsi, [relaAddr]
    mov rcx, [relaSize]
    xor rdx, rdx
    mov rax, [relaEnt]
    test rax, rax
    jz unsupportedReloc
    div rax
    mov rcx, rax
    .relaRelativeLoop:
        test rcx, rcx
        jz .applyJmpRelRelative
        mov rax, [rsi + RELA.info]                ; RELA.info packs the relocation type in the low 32 bits, symbol index in the high 32
        and eax, 0xffffffff                        ; only the type half is read here
        cmp eax, R_X86_64_RELATIVE                 ; this pass only patches the plain RELATIVE kind
        jne .nextRelaRelative
        mov rdi, [baseAddr]                       ; rdi starts at the mapped image base
        add rdi, [rsi + RELA.offset]             ; then add r_offset: rdi is now the exact byte to patch
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]              ; rax = base + r_addend, the value the RELATIVE contract writes at that address
        mov [rdi], rax                            ; committing the relocated pointer into the image
        .nextRelaRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .relaRelativeLoop

    .applyJmpRelRelative:
    ; Some static PIEs also sneak RELATIVE relocations into JMPREL
    cmp qword [jmprelSize], 0
    je .applyRelaIRelative
    mov rsi, [baseAddr]                           ; JMPREL sits in a separate table from the main RELA one, same record layout though
    add rsi, [jmprelAddr]                         ; MPREL's first record
    mov rcx, [jmprelSize]                         ; total JMPREL byte size, about to become an entry count
    xor rdx, rdx                                  ; rdx:rax is the dividend for div, leaving rdx dirty corrupts the quotient
    mov rax, [relaEnt]
    test rax, rax                                 ; guards a malformed/missing DT_RELAENT (relaEnt == 0) from faulting the div
    jz unsupportedReloc
    div rax
    mov rcx, rax
    .jmprelRelativeLoop:
        test rcx, rcx
        jz .applyRelaIRelative
        mov rax, [rsi + RELA.info]                ; same RELA.info layout as the main table
        and eax, 0xffffffff                       ; type bits only, same as above
        cmp eax, R_X86_64_RELATIVE                ; still just the RELATIVE subset in this pass
        jne .nextJmpRelRelative
        mov rdi, [baseAddr]                       
        add rdi, [rsi + RELA.offset]              
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]              ; some static PIEs put ordinary RELATIVE entries in JMPREL instead of RELA
        mov [rdi], rax                            ; patched the same way as the main table
        .nextJmpRelRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .jmprelRelativeLoop

    .applyRelaIRelative:
    ; Pass 2: IRELATIVE relocations.
    ;
    ; These call back into resolver code inside the image, after the plain
    ; RELATIVE pointers are already fixed
    mov rsi, [baseAddr]                           ; rewalk the main RELA table now for the IRELATIVE subset
    add rsi, [relaAddr]                           ; rsi back at the first main table record
    mov rcx, [relaSize]                           ; total RELA byte size again
    xor rdx, rdx                                  ; clear the dividend high half before dividing again
    mov rax, [relaEnt]
    test rax, rax                                 ; relaEnt could theoretically be zero here too (don't quote me on that)
    jz unsupportedReloc
    div rax
    mov rcx, rax
    .relaIRelativeLoop:
        test rcx, rcx
        jz .applyJmpRelIRelative
        mov rax, [rsi + RELA.info]                ; RELA.info, same packing as always
        and eax, 0xffffffff                       ; type bits only
        cmp eax, R_X86_64_IRELATIVE                ; this pass only runs indirect (IRELATIVE) resolvers
        jne .checkUnsupportedRela
        mov rdi, [baseAddr]                       ; rdi starts at the mapped image base
        add rdi, [rsi + RELA.offset]              ; the slot that will receive the resolver's result
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]              ; for IRELATIVE the addend is the resolver's address, not a data value
        push rcx
        push rsi
        push rdi
        call rax                                  ; jump into the image's own resolver, its return value is the real relocated address
        pop rdi
        pop rsi
        pop rcx
        mov [rdi], rax                            ; store the resolver's answer at the destination slot
        jmp .nextRelaIRelative
        .checkUnsupportedRela:
        cmp eax, R_X86_64_RELATIVE                ; plain RELATIVE entries are legal here too, they were already handled in the earlier pass
        je .nextRelaIRelative
        jmp unsupportedReloc
        .nextRelaIRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .relaIRelativeLoop

    .applyJmpRelIRelative:
    ; Same idea again for the PLT relocation table, because some binaries stash
    ; IRELATIVE entries there instead of in the main RELA table (if I understood
    ; correctly, but seems to work?)
    cmp qword [jmprelSize], 0
    je prepareTlsAndStack
    mov rsi, [baseAddr]                           ; and once more for JMPREL's IRELATIVE entries
    add rsi, [jmprelAddr]                         ; first PLT/JMPREL record
    mov rcx, [jmprelSize]                         ; rcx = total PLT/JMPREL byte size
    xor rdx, rdx                                  ; clear the dividend high half
    mov rax, [relaEnt]
    test rax, rax                                 ; relaEnt == 0 guard, same reasoning as the earlier passes
    jz unsupportedReloc
    div rax
    mov rcx, rax
    .jmprelIRelativeLoop:
        test rcx, rcx
        jz prepareTlsAndStack
        mov rax, [rsi + RELA.info]                ; same RELA.info layout
        and eax, 0xffffffff                       ; type bits only, symbol index unused
        cmp eax, R_X86_64_IRELATIVE                ; only IRELATIVE entries are resolved in this pass
        jne .checkUnsupportedJmpRel
        mov rdi, [baseAddr]                       ; rdi at the mapped image base
        add rdi, [rsi + RELA.offset]              ; rdi = the PLT relocation's destination slot
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]              ; same contract as the main table: addend is a resolver address here too
        push rcx
        push rsi
        push rdi
        call rax                                  ; run the PLT resolver, same contract as the main RELA table above
        pop rdi
        pop rsi
        pop rcx
        mov [rdi], rax                            ; store the resolver's result
        jmp .nextJmpRelIRelative
        .checkUnsupportedJmpRel:
        cmp eax, R_X86_64_RELATIVE                ; RELATIVE entries were already patched by the earlier pass, nothing to do here
        je .nextJmpRelIRelative
        jmp unsupportedReloc
        .nextJmpRelIRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .jmprelIRelativeLoop
