/*
 * Freestanding SHELF test. With no libc nothing in the target redoes the
 * relocations, rebuilds TLS or realigns the stack, so this only exits 7 when
 * the loader got all three right by itself.
 *
 *   103  rsp was not 16 byte aligned at entry
 *   104  RELATIVE relocations after the first one were not applied
 *   105  the TLS block sits at the wrong offset from %fs
 */

static int a = 3, b = 4, c = 5;

/* Absolute pointers in a static PIE become R_X86_64_RELATIVE entries. volatile
   keeps the compiler from folding the loads away. */
static int *volatile tbl[] = { &a, &b, &c };

/* An int and a char give p_memsz 5 with p_align 4, so placing the block at
   tp minus p_memsz instead of tp minus roundup(p_memsz, p_align) shifts both. */
static volatile __thread int tls_int = 11;
static volatile __thread char tls_char = 1;

int cmain(void);

int cmain(void)
{
    if (*tbl[0] + *tbl[1] + *tbl[2] != 12)
        return 104;
    if (tls_int != 11 || tls_char != 1)
        return 105;
    return 7;
}

__asm__(
    ".globl _start\n"
    "_start:\n"
    "    test $15, %rsp\n"
    "    jnz 1f\n"
    "    call cmain\n"
    "    mov %eax, %edi\n"
    "    jmp 2f\n"
    "1:  mov $103, %edi\n"
    "2:  mov $60, %eax\n"
    "    syscall\n");
