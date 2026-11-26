SYS_MEMFD_CREATE  = 0x13f 
SYS_READ        = 0x0
SYS_WRITE       = 0x1
SYS_OPEN        = 0x2
SYS_CLOSE       = 0x3
SYS_PREAD64     = 0x11 
SYS_FSTAT       = 0x5
SYS_MMAP        = 0x9
SYS_MPROTECT    = 0xa 
SYS_EXIT        = 0x3c
SYS_ARCH_PRCTL  = 0x9e

STDIN   = 0x0
STDOUT  = 0x1
STDERR  = 0x2

O_RDONLY  = 0x0
; mmap/mprotect flags used while staging files, laying out PT_LOAD segments,
; and building a fake stack/TLS area
MAP_PRIVATE     = 0x2
MAP_ANON        = 0x20 
MAP_FIXED       = 0x10 
PROT_READ       = 0x1
PROT_WRITE      = 0x2
PROT_EXEC       = 0x4
PT_LOAD         = 0x1
PT_INTERP       = 0x3 
PT_DYNAMIC      = 0x2
PT_TLS          = 0x7 
PT_GNU_STACK    = 0x6474e551 
PF_X            = 0x1
PF_W            = 0x2
PF_R            = 0x4
PAGE_SIZE       = 0x1000 

ELFCLASS64      = 0x2
ELFDATA2LSB     = 0x1
ET_DYN          = 0x3 
ET_EXEC         = 0x2
EM_X86_64       = 0x3e
EV_CURRENT      = 0x1 ; the only version the ELF spec has ever defined (so far!)

BUFFER_SIZE     = 1048576 ; shared staging cap, oversized input fails fast
; Auxv entries we either keep or patch while rebuilding the target stack
AT_NULL           = 0x0
AT_PHDR           = 0x3 ; with AT_PHENT/AT_PHNUM describes the main executable's own program headers in memory, so its libc can find them without re-reading the file
AT_PHENT          = 0x4
AT_PHNUM          = 0x5
AT_BASE           = 0x7 ; nonzero only when an interpreter is loaded, the interpreter's own load bias
AT_ENTRY          = 0x9
AT_PLATFORM       = 0xf 
AT_BASE_PLATFORM  = 0x18 
AT_RANDOM         = 0x19 
AT_EXECFN         = 0x1f 

ARCH_SET_FS     = 0x1002 ; arch_prctl(2) subcommand that sets %fs base, used to point the target at its own TLS block
; PT_DYNAMIC tags for the tiny relocation subset this loader handles itself
DT_NULL         = 0x0
DT_PLTRELSZ     = 0x2 ; size in bytes of the PLT/GOT relocation table pointed to by DT_JMPREL
DT_RELA         = 0x7
DT_RELASZ       = 0x8
DT_RELAENT      = 0x9
DT_PLTREL       = 0x14    ; says whether the PLT/GOT table at DT_JMPREL uses REL or RELA-shaped entries
DT_JMPREL       = 0x17  ; PLT/GOT relocations live in a table separate from DT_RELA
DT_RELACOUNT    = 0x6ffffff9  ; count of leading R_X86_64_RELATIVE entries in the RELA table, so the common case can be applied without checking every entry's type

; the only relocation kinds this loader actually resolves, anything else in a
; target's RELA table is out of scope and would need a real dynamic linker
R_X86_64_RELATIVE   = 0x8
R_X86_64_IRELATIVE  = 0x25
; The stack reservation is bigger than the part we use to stash copied
; argv/envp/auxv payloads. STACK_STORAGE_SIZE marks the  storage area for
; duplicated strings and aux blobs
STACK_SIZE          = 8388608 ; 8*1024*1024
TLS_TCB_SIZE        = 0x1000    ; space reserved for the thread control block that sits just before the %fs base this loader points at
TLS_DTV_SIZE        = 0x30     ; dynamic thread vector header, only the generation counter and slot 0 are ever populated since this loader never calls dlopen
STACK_STORAGE_SIZE  = 0x5000
STACK_STRING_SIZE   = 0x40000 ; 256 KB of argv/env strings, even all 1 byte strings need only 2 MB of pointer tables, which stay clear of the string area
; Convert ELF PF_* bits into Linux PROT_* bits.
;
; The numbering does not line up, which is an easy way to ruin a loader on a
; sleepy night, so this macro keeps the translation in one place
macro ELF_FLAGS_TO_PROT flags_reg, out_reg
{
  local .no_read, .no_write, .done
    xor out_reg, out_reg
    test flags_reg, PF_R
    jz .no_read
    or out_reg, PROT_READ
  .no_read:
    test flags_reg, PF_W
    jz .no_write
    or out_reg, PROT_WRITE
  .no_write:
    test flags_reg, PF_X
    jz .done
    or out_reg, PROT_EXEC
  .done:
}
; Expand the tracked PT_LOAD span with one more segment.
;
; min_sym starts at -1. Callers pass already rounded addresses, so the final
; span can go straight into mmap logic
macro UPDATE_LOAD_SPAN start_reg, end_reg, min_sym, max_sym
{
  local .check_min, .check_max, .done
    cmp qword [min_sym], -1
    jne .check_min
    mov [min_sym], start_reg
    jmp .check_max
  .check_min:
    cmp start_reg, [min_sym]
    jae .check_max
    mov [min_sym], start_reg
  .check_max:
    cmp end_reg, [max_sym]
    jbe .done
    mov [max_sym], end_reg
  .done:
}
; Enter a fully prepared image.
;
; By the time this runs, the stack is ready and the entry point is known. We
; just restore the usual entry state and get out of the way
macro ENTER_PREPARED_IMAGE stack_sym, entry_reg
{
    mov rsp, [stack_sym]
    xor ebp, ebp
    xor eax, eax
    xor edx, edx
    jmp entry_reg
}
; Only a subset is consumed, but fstat(2) writes all 144 bytes, including the
; trailing reserved words
struc STAT {
  .st_dev         rq 1
  .st_ino         rq 1
  .st_nlink       rq 1
  .st_mode        rd 1
  .st_uid         rd 1
  .st_gid         rd 1
  .pad0           rb 4
  .st_rdev        rq 1
  .st_size        rq 1 ; the one field this loader actually reads back out
  .st_blksize     rq 1
  .st_blocks      rq 1
  .st_atime       rq 1
  .st_atime_nsec  rq 1
  .st_mtime       rq 1
  .st_mtime_nsec  rq 1
  .st_ctime       rq 1
  .st_ctime_nsec  rq 1
  .reserved       rq 3
}

virtual at 0
  STAT STAT
  sizeof.STAT = $ - STAT
end virtual
; ELF header and PHDR layouts used by the main image and PT_INTERP
; section header fields are only carried along for completeness, a runtime
; loader never has a reason to look at them
struc EHDR {
    .magic      rd  1
    .class      rb  1
    .data       rb  1
    .elfversion rb  1
    .os         rb  1
    .abiversion rb  1
    .pad        rb  7 ; our little favorite offset for signatures hehehe
    .type       rb  2
    .machine    rb  2
    .version    rb  4 
    .entry      rq  1
    .phoff      rq  1
    .shoff      rq  1
    .flags      rb  4 
    .ehsize     rb  2
    .phentsize  rb  2
    .phnum      rb  2
    .shentsize  rb  2
    .shnum      rb  2
    .shstrndx   rb  2
}
virtual at 0
  EHDR EHDR
  sizeof.EHDR = $ - EHDR
end virtual

struc PHDR {
    .type   rb  4
    .flags  rd  1
    .offset rq  1
    .vaddr  rq  1
    .paddr  rq  1 
    .filesz rq  1
    .memsz  rq  1 
    .align  rq  1 
}
virtual at 0
  PHDR PHDR
  sizeof.PHDR = $ - PHDR
end virtual
; DYN mirrors one on-disk Elf64_Dyn tag/value pair, RELA mirrors Elf64_Rela.
; x64 only ever uses RELA relocations (explicit addend), so there is
; no REL variant here and none of the DT_REL* tags are defined
struc DYN {
    .tag rq 1
    .val rq 1 ; either a pointer or a plain integer depending on .tag
}
virtual at 0
  DYN DYN
  sizeof.DYN = $ - DYN
end virtual

struc RELA {
    .offset rq 1
    .info   rq 1
    .addend rq 1
}
virtual at 0
  RELA RELA
  sizeof.RELA = $ - RELA
end virtual
