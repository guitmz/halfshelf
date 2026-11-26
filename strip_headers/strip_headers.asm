; strip_headers takes a SHELF ELF64 image and splits it into a flat payload
; blob plus a small metadata sidecar, so the loader can reconstruct what it needs
; to map and run the thing without linking an ELF parser into itself
;
; it expects exactly one PT_LOAD segment starting at file offset 0 and vaddr 0,
; plus optionally one PT_DYNAMIC and one PT_TLS, which is what a single segment
; position independent binary looks like once a minimal link step has run
;
; two invocation shapes are supported
;   strip_headers <input-elf> <output-payload> <output-meta>
;   strip_headers --headless-bin <input-elf> <output-payload> <output-meta>
; the first writes a human readable key/value text sidecar, the second a compact
; binary sidecar for the headless loader's autodetect path, same fields, same
; order, just two different encodings of the same facts
;
; this tool only ever reads the one input file and writes the two output files,
; nothing here touches the network or spawns anything else
;
; every path through here exits 0 on success or 1 on failure, there's no
; partial or otherwise distinguishable exit status
;
; assemble with: fasm strip_headers.asm
;
; sidecar field order (same order in both the text and binary encodings):
;   entry, phoff, phnum, phentsize, header_span,
;   load_offset, load_vaddr, load_filesz, load_memsz, load_flags,
;   dynamic_vaddr, dynamic_memsz,
;   tls_vaddr, tls_filesz, tls_memsz, tls_align,
;   phdr_hex (raw phdr table bytes, the binary sidecar carries the table's byte
;   size instead, since it appends the same raw bytes rather than hex text)

format ELF64 executable 3 

include "../utils.inc" 

O_WRONLY = 1
O_CREAT  = 64
O_TRUNC  = 512 

MODE_0644 = 420 ; 0644 octal rw-r--r--

; writes a fixed string embedded in this binary, sym##Len is a FASM token paste,
; not a runtime length, so the size falls out of assembly rather than a strlen
macro WRITE_LITERAL sym
{
    mov rdi, [metaFd]
    lea rsi, [sym]
    mov rdx, sym##Len
    call writeBuf
}

; writes one "key <hex>\n" line of the text sidecar, the key is a literal, the
; value is whatever 64 bit quantity valueSym currently holds
macro WRITE_KEY_HEX keySym, valueSym
{
    lea rsi, [keySym]
    mov rdx, keySym##Len
    mov rax, [valueSym]
    call writeKeyHex
}

; every failure path in this tool ends here: print one fixed message, exit 1.
; nothing needs unwinding since we never hold more state than a couple of fds
macro WRITE_AND_EXIT msgSym, lenSym
{
    mov rdi, STDOUT
    lea rsi, [msgSym]
    mov rdx, lenSym
    call writeBuf
    mov edi, 1
    mov eax, SYS_EXIT
    syscall
}

segment readable executable 
entry $ 
    ; argc sits at [rsp] on process entry, before argv[0], this is the raw
    ; kernel-provided stack layout, not a function call, so there's no argc
    ; parameter to read the usual way
    mov rcx, [rsp]
    cmp rcx, 4                                       ; argv[0] plus 3 paths: plain text mode invocation
    je .textModeArgs
    cmp rcx, 5                                        ; argv[0], a flag, and 3 paths: binary mode invocation
    jne usage
    mov rax, [rsp + 16]                          ; argv[1] may optionally request the binary metadata format
    mov rbx, rax                                      ; rbx walks argv[1] byte by byte against binArg in the comparison loop below
    lea rdi, [binArg]
    mov rdx, binArgLen
    ; walks argv[1] and binArg together until either a mismatch or the flag runs out
    .checkBinArg:
        test rdx, rdx
        jz .binModeArgs
        mov al, [rbx]
        mov cl, [rdi]
        cmp al, cl                                    ; case sensitive 
        jne usage
        inc rbx
        inc rdi
        dec rdx
        jmp .checkBinArg

    ; text mode has no leading flag argument, so its three paths sit one stack
    ; slot earlier than in binary mode below
    .textModeArgs:
    mov byte [modeBin], 0
    mov rax, [rsp + 16]                          ; re-read here since the flag check above only compared bytes
    mov [inputPath], rax
    mov rax, [rsp + 24]
    mov [payloadPath], rax
    mov rax, [rsp + 32]
    mov [metaPath], rax
    jmp .argsReady

    .binModeArgs:
    mov byte [modeBin], 1
    mov rax, [rsp + 24]
    mov [inputPath], rax
    mov rax, [rsp + 32]
    mov [payloadPath], rax
    mov rax, [rsp + 40]
    mov [metaPath], rax
    ; both branches above converge here with inputPath/payloadPath/metaPath
    ; filled in and modeBin set, everything from here on treats the two
    ; invocation shapes identically
    .argsReady:

    ; a negative return here is the raw syscall convention: negated errno
    ; packed directly into rax, not a separate errno global the way libc wraps it
    mov rdi, [inputPath]
    mov rsi, O_RDONLY
    xor rdx, rdx
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [inputFd], rax                                ; stored for completeness, nothing later reopens it by name, r12 below carries it forward instead
    mov r12, rax                                      ; kept here across the fstat/read calls below since rax itself gets overwritten by each syscall's return value

    mov rdi, r12
    lea rsi, [fileStat]
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed

    ; refuses to grow the read buffer dynamically, anything bigger than the
    ; static BUFFER_SIZE scratch area is rejected up front instead
    cmp qword [fileStat.st_size], BUFFER_SIZE
    jg fileTooLarge

    mov rdi, r12
    lea rsi, [buf]
    mov rdx, [fileStat.st_size]
    mov rax, SYS_READ
    syscall
    cmp rax, [fileStat.st_size]                       ; a short read would leave the zeroed tail of buf posing as file bytes
    jne fileReadFailed

    cmp dword [buf + EHDR.magic], 0x464c457f          ; 0x464c457f means \x7fELF in a little-endian 
    jne invalidElf
    ; only 64 bit, little-endian, ET_DYN images are accepted, this tool has no
    ; reason to deal with 32 bit, big-endian, or plain ET_EXEC layouts
    cmp byte [buf + EHDR.class], ELFCLASS64
    jne invalidElf
    cmp byte [buf + EHDR.data], ELFDATA2LSB
    jne invalidElf
    cmp word [buf + EHDR.type], ET_DYN
    jne invalidElf
    cmp word [buf + EHDR.phentsize], sizeof.PHDR      ; a mismatched phentsize would desync every offset below, so bail before the scan starts
    jne invalidElf

    ; stash the header fields still needed once buf gets reused below as the
    ; phdr scan cursor
    mov rax, qword [buf + EHDR.entry]
    mov [entryValue], rax
    mov rax, qword [buf + EHDR.phoff]
    mov [phoffValue], rax
    movzx eax, word [buf + EHDR.phnum]                ; phnum is a 16 bit ELF field, stored here as a full qword
    mov [phnumValue], rax
    movzx eax, word [buf + EHDR.phentsize]             ; phentsize is 16 bits on disk too
    mov [phentsizeValue], rax

    ; end of the phdr table = phoff + phnum*phentsize, also the number of
    ; header bytes that are not part of the payload once it's stripped out
    mov rax, [phoffValue]
    mov rdx, [phnumValue]
    mov rcx, [phentsizeValue]
    imul rdx, rcx
    add rax, rdx
    mov [headerSpan], rax

    ; The phdr table must lie inside the file we actually read, otherwise the
    ; scan below walks past buf. phoff is checked first so the sum cannot wrap
    mov rax, [phoffValue]
    cmp rax, [fileStat.st_size]
    ja invalidShelf
    mov rax, [headerSpan]
    cmp rax, [fileStat.st_size]
    ja invalidShelf

    ; walk every phdr once, remembering the first PT_LOAD/PT_DYNAMIC/PT_TLS
    ; entry of each kind, a SHELF image is expected to carry at most one of each
    lea rbx, [buf]
    add rbx, [phoffValue]
    mov rcx, [phnumValue]
    .scanPhdrs:
        test rcx, rcx
        jz .scanDone
        cmp dword [rbx + PHDR.type], PT_LOAD
        jne .notLoad
        inc qword [loadCount]
        cmp qword [loadCount], 1                      ; a second PT_LOAD means this isn't a single segment SHELF image, bail rather than pick one
        jne invalidShelf
        mov eax, dword [rbx + PHDR.flags]                 ; a 32 bit field, not like offset/vaddr/filesz/memsz below which are all 64 bit
        mov dword [loadFlagsValue], eax
        mov rax, qword [rbx + PHDR.offset]
        mov [loadOffsetValue], rax
        mov rax, qword [rbx + PHDR.vaddr]
        mov [loadVaddrValue], rax
        mov rax, qword [rbx + PHDR.filesz]
        mov [loadFileszValue], rax
        mov rax, qword [rbx + PHDR.memsz]
        mov [loadMemszValue], rax
        jmp .nextPhdr
        .notLoad:
        ; PT_DYNAMIC and PT_TLS are optional and only ever remembered once each,
        ; unlike PT_LOAD above, a repeat isn't treated as an error
        cmp dword [rbx + PHDR.type], PT_DYNAMIC
        jne .notDynamic
        mov rax, qword [rbx + PHDR.vaddr]
        mov [dynamicVaddrValue], rax
        mov rax, qword [rbx + PHDR.memsz]
        mov [dynamicMemszValue], rax
        jmp .nextPhdr
        .notDynamic:
        cmp dword [rbx + PHDR.type], PT_TLS
        jne .nextPhdr
        ; all four TLS fields are captured together, a partial TLS record
        ; wouldn't be meaningful to whatever reads the sidecar back
        mov rax, qword [rbx + PHDR.vaddr]
        mov [tlsVaddrValue], rax
        mov rax, qword [rbx + PHDR.filesz]
        mov [tlsFileszValue], rax
        mov rax, qword [rbx + PHDR.memsz]
        mov [tlsMemszValue], rax
        mov rax, qword [rbx + PHDR.align]
        mov [tlsAlignValue], rax
        .nextPhdr:
        add rbx, sizeof.PHDR
        dec rcx
        jmp .scanPhdrs
    .scanDone:

    ; re-checked outside the loop since the loop body only rejects a *second*
    ; PT_LOAD, a file with zero PT_LOAD segments slips past it otherwise
    cmp qword [loadCount], 1
    jne invalidShelf
    ; the payload split below assumes the PT_LOAD starts at the very first byte
    ; of both the file and memory, anything else and headerSpan wouldn't line
    ; up with where the payload actually begins
    cmp qword [loadOffsetValue], 0
    jne invalidShelf
    cmp qword [loadVaddrValue], 0
    jne invalidShelf
    ; The PT_LOAD file bytes must exist in the input and contain the header
    ; span, otherwise a truncated ELF would turn into a payload padded with
    ; zeros that headshelf happily runs
    mov rax, [loadFileszValue]
    cmp rax, [fileStat.st_size]
    ja invalidShelf
    cmp rax, [headerSpan]
    jb invalidShelf

    ; everything in the PT_LOAD past the header/phdr table is the payload the
    ; loader will map back in later
    mov rax, [loadFileszValue]
    sub rax, [headerSpan]
    mov [payloadSize], rax

    ; Write stripped payload
    mov rdi, [payloadPath]
    mov rsi, O_WRONLY or O_CREAT or O_TRUNC
    mov rdx, MODE_0644
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [payloadFd], rax

    mov rdi, rax
    lea rsi, [buf]
    add rsi, [headerSpan]                             ; payload starts headerSpan bytes into the buffer already read in, no second read needed
    mov rdx, [payloadSize]
    mov rax, SYS_WRITE
    syscall
    cmp rax, [payloadSize]                            ; a short write here would silently truncate the payload, treat it as fatal rather than retrying the remainder
    jne fileWriteFailed

    mov rdi, [payloadFd]
    mov rax, SYS_CLOSE
    syscall
    test rax, rax                                     ; close(2) failures are rare but happen 
    js closeFailed

    ; Write either the original textual metadata sidecar or the compact binary
    ; sidecar used by loader new binary autodetect path
    mov rdi, [metaPath]                               ; clobbers whatever already exists at this path, there's no check for a pre-existing file first
    mov rsi, O_WRONLY or O_CREAT or O_TRUNC
    mov rdx, MODE_0644
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [metaFd], rax

    cmp byte [modeBin], 0                             ; branches on the mode flag set back during argument parsing
    jne .writeBinaryMeta

    ; field order here defines the sidecar layout for both this text form and
    ; the binary form below, keep the two lists in sync if a field is ever added
    WRITE_LITERAL metaMagic                           ; tags this as a SHELFMETA1 sidecar so a future format revision can be told apart from this one
    WRITE_KEY_HEX metaEntryKey, entryValue            ; target's original entry point, before the loader applies its own base- ddress bias
    WRITE_KEY_HEX metaPhoffKey, phoffValue            ; with phnum/phentsize below, lets the loader point AT_PHDR/AT_PHENT/AT_PHNUM at its own headers once mapped
    WRITE_KEY_HEX metaPhnumKey, phnumValue            ; number of entries in that table
    WRITE_KEY_HEX metaPhentsizeKey, phentsizeValue    ; size in bytes of one entry in that table
    WRITE_KEY_HEX metaHeaderSpanKey, headerSpan       ; bytes sliced off the front to make the payload, the loader adds this back when placing things in memory
    WRITE_KEY_HEX metaLoadOffsetKey, loadOffsetValue  ; always 0 by this point, recorded for the sidecar's sake, not because the loader still needs to check it
    WRITE_KEY_HEX metaLoadVaddrKey, loadVaddrValue    ; always 0 for the same reason
    WRITE_KEY_HEX metaLoadFileszKey, loadFileszValue  ; still the *original* filesz, header span included, not the size of the payload file written alongside this
    WRITE_KEY_HEX metaLoadMemszKey, loadMemszValue    ; same original-size caveat as filesz above
    WRITE_KEY_HEX metaLoadFlagsKey, loadFlagsValue    ; PF_R/PF_W/PF_X bits for the one PT_LOAD, ELF_FLAGS_TO_PROT in utils.inc turns these into mmap PROT_* bits
    WRITE_KEY_HEX metaDynamicVaddrKey, dynamicVaddrValue ; zero when the target has no PT_DYNAMIC, the loader reads that as "nothing to relocate", not an error
    WRITE_KEY_HEX metaDynamicMemszKey, dynamicMemszValue ; zero alongside dynamicVaddrValue when there's no PT_DYNAMIC
    WRITE_KEY_HEX metaTlsVaddrKey, tlsVaddrValue      ; zero across all four TLS fields when the target carries no PT_TLS segment at all
    WRITE_KEY_HEX metaTlsFileszKey, tlsFileszValue
    WRITE_KEY_HEX metaTlsMemszKey, tlsMemszValue
    WRITE_KEY_HEX metaTlsAlignKey, tlsAlignValue      ; must stay a power of two, same constraint PHDR.align carries in utils.inc

    ; also dumps the raw phdr table as hex, so a consumer that doesn't trust
    ; the parsed fields above can re-derive them independently
    mov rdi, [metaFd]
    lea rsi, [metaPhdrHexKey]
    mov rdx, metaPhdrHexKeyLen
    call writeBuf

    lea rsi, [buf]
    add rsi, [phoffValue]
    mov rcx, [phnumValue]
    mov rax, [phentsizeValue]
    imul rcx, rax
    call writeHexBytes

    mov rdi, [metaFd]                                 ; closes out the phdr_hex line, the text sidecar is line oriented throughout, unlike the binary one
    lea rsi, [nl]
    mov rdx, 1
    call writeBuf

    mov rdi, [metaFd]
    mov rax, SYS_CLOSE
    syscall
    test rax, rax
    js closeFailed
    jmp .doneSuccess

    ; same fields as the text sidecar above, same order, just packed as raw
    ; little-endian u64s back to back instead of hex text lines, so the
    ; headless loader can read this straight in without a text parser
    ; there are no keys in this encoding, so a reader has to count bytes to
    ; know which field is which, offsets noted below assume metaBinMagic's
    ; 8 byte magic (SHELFBN1) sits at offset 0
    .writeBinaryMeta:
    mov rdi, [metaFd]
    lea rsi, [metaBinMagic]
    mov rdx, metaBinMagicLen
    call writeBuf
    mov rdi, [metaFd]
    mov rax, [entryValue]
    call writeU64Le                                    ; offset 8
    mov rdi, [metaFd]
    mov rax, [phoffValue]
    call writeU64Le                                    ; offset 16
    mov rdi, [metaFd]
    mov rax, [phnumValue]
    call writeU64Le                                    ; offset 24
    mov rdi, [metaFd]
    mov rax, [phentsizeValue]
    call writeU64Le                                    ; offset 32
    mov rdi, [metaFd]
    mov rax, [headerSpan]
    call writeU64Le                                   ; offset 40
    mov rdi, [metaFd]
    mov rax, [loadOffsetValue]
    call writeU64Le                                    ; offset 48
    mov rdi, [metaFd]
    mov rax, [loadVaddrValue]
    call writeU64Le                                    ; offset 56
    mov rdi, [metaFd]
    mov rax, [loadFileszValue]
    call writeU64Le                                    ; offset 64
    mov rdi, [metaFd]
    mov rax, [loadMemszValue]
    call writeU64Le                                    ; offset 72
    mov rdi, [metaFd]
    mov rax, [loadFlagsValue]
    call writeU64Le                                    ; offset 80
    mov rdi, [metaFd]
    mov rax, [dynamicVaddrValue]
    call writeU64Le                                    ; offset 88
    mov rdi, [metaFd]
    mov rax, [dynamicMemszValue]
    call writeU64Le                                    ; offset 96
    mov rdi, [metaFd]
    mov rax, [tlsVaddrValue]
    call writeU64Le                                    ; offset 104
    mov rdi, [metaFd]
    mov rax, [tlsFileszValue]
    call writeU64Le                                    ; offset 112
    mov rdi, [metaFd]
    mov rax, [tlsMemszValue]
    call writeU64Le                                    ; offset 120
    mov rdi, [metaFd]
    mov rax, [tlsAlignValue]
    call writeU64Le                                    ; offset 128
    mov rdi, [metaFd]
    mov rax, [phnumValue]
    imul rax, [phentsizeValue]                        ; not a stored field, computed here: total phdr table size in bytes
    call writeU64Le                                    ; offset 136
    mov rdi, [metaFd]
    lea rsi, [buf]
    add rsi, [phoffValue]
    mov rdx, [phnumValue]
    imul rdx, [phentsizeValue]
    call writeBuf                                      ; offset 144 onward are  phdr table bytes, same content as the hex dump above, just not hex-encoded

    ; two exit points rather than one shared tail: this one ends the binary
    ; sidecar path just above, .doneSuccess ends the text sidecar path further
    ; up, both just exit 0, there was no reason to jmp back and share it
    mov edi, 0
    mov eax, SYS_EXIT
    syscall
    .doneSuccess:
    mov edi, 0
    mov eax, SYS_EXIT
    syscall

; renders rcx raw bytes at [rsi] as lowercase ascii hex pairs, streaming them
; out one byte (two hex chars) at a time instead of building the whole string
; in a buffer first
writeHexBytes:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push r8
    push r9
    mov r8, rsi                                       ; r8/r9 survive the writeBuf call below since rsi/rcx are clobbered by it
    mov r9, rcx
    .loop:
        test r9, r9
        jz .done
        mov bl, [r8]                                   ; bl holds the raw byte, both nibble computations below read it back out of dl/bl
        mov dl, bl
        shr dl, 4                                     ; high nibble first, then the low nibble below
        mov al, [hexDigits + rdx]
        mov [hexBuf], al
        movzx rdx, bl
        and edx, 0xf
        mov al, [hexDigits + rdx]
        mov [hexBuf + 1], al
        mov rdi, [metaFd]
        lea rsi, [hexBuf]
        mov rdx, 2
        call writeBuf
        inc r8
        dec r9
        jmp .loop
    .done:
    pop r9
    pop r8
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; writes "key" then the 64 bit value in rax as 16 lowercase hex digits plus a
; newline, only used by the human-readable text sidecar
writeKeyHex:
    ; two separate save/restore groups below: the first guards the key-text
    ; write, the second guards the hex-digit loop, kept apart since each only
    ; needs to protect the registers live during its own half of the work
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    mov rdi, [metaFd]
    call writeBuf
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    lea rsi, [hexLineBuf + 15]
    mov rcx, 16
    mov rbx, rax                                      ; rbx holds the value being shifted apart one nibble at a time below
    ; fills the digit buffer back to front, least significant nibble first,
    ; since each nibble is only known after shifting the value down
    .hexLoop:
        mov rdx, rbx
        and rdx, 0xf
        mov al, [hexDigits + rdx]
        mov [rsi], al
        dec rsi
        shr rbx, 4
        dec rcx
        jnz .hexLoop
    lea rsi, [hexLineBuf]
    mov byte [hexLineBuf + 16], 10
    mov rdi, [metaFd]
    mov rdx, 17                                       ; writes all 17 bytes, 16 hex digits plus the newline, in one call now that the buffer is filled
    call writeBuf
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret

; every write in this tool funnels through here, so a short or failed write
; is treated as fatal instead of silently continuing with truncated output
;
; the syscall instruction itself clobbers rcx and r11 as a side effect (the
; CPU uses them to stash the return rip/rflags), which is why nothing above
; ever expects rcx to survive a call down into here
writeBuf:
    mov rax, SYS_WRITE
    syscall
    cmp rax, rdx
    jne fileWriteFailed
    ret

writeU64Le:
    ; The host is already little-endian x64, so make the qword into
    ; a scratch buffer and write those 8 bytes directly
    mov [u64leBuf], rax
    lea rsi, [u64leBuf]
    mov rdx, 8
    call writeBuf
    ret

; reached either when argc matched neither invocation shape, or when argc was
; 5 but argv[1] wasn't exactly "--headless-bin", every label below this one
; instead comes from a syscall failing partway through the real work
;
; functionally identical to WRITE_AND_EXIT usageMsg, usageMsgLen, just written
; out longhand here rather than through the macro
usage:
    mov rdi, STDOUT
    lea rsi, [usageMsg]
    mov rdx, usageMsgLen
    call writeBuf
    mov edi, 1
    mov eax, SYS_EXIT
    syscall

openFailed: 
    WRITE_AND_EXIT openFailedMsg, openFailedMsgLen
fstatFailed:
    WRITE_AND_EXIT fstatFailedMsg, fstatFailedMsgLen
fileTooLarge:
    WRITE_AND_EXIT fileTooLargeMsg, fileTooLargeMsgLen
fileReadFailed:
    WRITE_AND_EXIT fileReadFailedMsg, fileReadFailedMsgLen
fileWriteFailed:
    WRITE_AND_EXIT fileWriteFailedMsg, fileWriteFailedMsgLen
invalidElf: 
    WRITE_AND_EXIT invalidElfMsg, invalidElfMsgLen
invalidShelf: 
    WRITE_AND_EXIT invalidShelfMsg, invalidShelfMsgLen
closeFailed: 
    WRITE_AND_EXIT closeFailedMsg, closeFailedMsgLen

segment readable
usageMsg            db "Usage: strip_headers <input-elf> <output-payload> <output-meta>", 0xa, \
                       "   or: strip_headers --headless-bin <input-elf> <output-payload> <output-meta>", 0xa
usageMsgLen         = $ - usageMsg
binArg              db "--headless-bin" 
binArgLen           = $ - binArg
metaMagic           db "SHELFMETA1", 0xa
metaMagicLen        = $ - metaMagic
metaBinMagic        db "SHELFBN1"
metaBinMagicLen     = $ - metaBinMagic
metaEntryKey        db "entry "
metaEntryKeyLen     = $ - metaEntryKey
metaPhoffKey        db "phoff "
metaPhoffKeyLen     = $ - metaPhoffKey
metaPhnumKey        db "phnum "
metaPhnumKeyLen     = $ - metaPhnumKey
metaPhentsizeKey    db "phentsize "
metaPhentsizeKeyLen = $ - metaPhentsizeKey
metaHeaderSpanKey   db "header_span "
metaHeaderSpanKeyLen = $ - metaHeaderSpanKey
metaLoadOffsetKey   db "load_offset "
metaLoadOffsetKeyLen = $ - metaLoadOffsetKey
metaLoadVaddrKey    db "load_vaddr "
metaLoadVaddrKeyLen = $ - metaLoadVaddrKey
metaLoadFileszKey   db "load_filesz "
metaLoadFileszKeyLen = $ - metaLoadFileszKey
metaLoadMemszKey    db "load_memsz "
metaLoadMemszKeyLen = $ - metaLoadMemszKey
metaLoadFlagsKey    db "load_flags "
metaLoadFlagsKeyLen = $ - metaLoadFlagsKey
metaDynamicVaddrKey db "dynamic_vaddr "
metaDynamicVaddrKeyLen = $ - metaDynamicVaddrKey
metaDynamicMemszKey db "dynamic_memsz "
metaDynamicMemszKeyLen = $ - metaDynamicMemszKey
metaTlsVaddrKey     db "tls_vaddr "
metaTlsVaddrKeyLen  = $ - metaTlsVaddrKey
metaTlsFileszKey    db "tls_filesz "
metaTlsFileszKeyLen = $ - metaTlsFileszKey
metaTlsMemszKey     db "tls_memsz "
metaTlsMemszKeyLen  = $ - metaTlsMemszKey
metaTlsAlignKey     db "tls_align "
metaTlsAlignKeyLen  = $ - metaTlsAlignKey
metaPhdrHexKey      db "phdr_hex "
metaPhdrHexKeyLen   = $ - metaPhdrHexKey

openFailedMsg       db "Failed to open file", 0xa
openFailedMsgLen    = $ - openFailedMsg
fstatFailedMsg      db "Failed to stat file", 0xa
fstatFailedMsgLen   = $ - fstatFailedMsg
fileTooLargeMsg     db "Input ELF is larger than the tool buffer", 0xa
fileTooLargeMsgLen  = $ - fileTooLargeMsg
fileReadFailedMsg   db "Failed to read input ELF", 0xa
fileReadFailedMsgLen = $ - fileReadFailedMsg
fileWriteFailedMsg  db "Failed to write output file", 0xa
fileWriteFailedMsgLen = $ - fileWriteFailedMsg
invalidElfMsg       db "Input is not a supported ET_DYN ELF64 image", 0xa
invalidElfMsgLen    = $ - invalidElfMsg
invalidShelfMsg     db "Input ELF is not shaped like a one PT_LOAD SHELF image", 0xa
invalidShelfMsgLen  = $ - invalidShelfMsg
closeFailedMsg      db "Failed to close output file", 0xa
closeFailedMsgLen   = $ - closeFailedMsg
nl                  db 0xa
hexDigits           db "0123456789abcdef" 

; scratch state for one run: parsed header/phdr fields, the three path pointers
; taken from argv, open fds, and the read buffer. none of it needs to survive
; past process exit, there's no cleanup pass at the end that relies on it
segment readable writeable
fileStat        STAT 
inputFd         rq 1 
payloadFd       rq 1
metaFd          rq 1
inputPath       rq 1 ; raw argv pointers, not copies, the strings they point at live in the process's own argv block for the whole run
payloadPath     rq 1
metaPath        rq 1
entryValue      rq 1
phoffValue      rq 1
phnumValue      rq 1
phentsizeValue  rq 1
headerSpan      rq 1
loadOffsetValue rq 1
loadVaddrValue  rq 1
loadFileszValue rq 1
loadMemszValue  rq 1
loadFlagsValue  rq 1
dynamicVaddrValue rq 1
dynamicMemszValue rq 1
tlsVaddrValue   rq 1
tlsFileszValue  rq 1
tlsMemszValue   rq 1
tlsAlignValue   rq 1
payloadSize     rq 1 
loadCount       rq 1 
modeBin         rb 1 
hexBuf          rb 2 
hexLineBuf      rb 17
u64leBuf        rq 1 
buf             rb BUFFER_SIZE 
