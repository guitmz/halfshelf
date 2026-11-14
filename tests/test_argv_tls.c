#include <stdio.h>
#include <string.h>

__thread int tls_counter = 17;

int main(int argc, char **argv)
{
    if (argc != 3) {
        return 101;
    }

    if (strcmp(argv[1], "alpha") != 0 || strcmp(argv[2], "beta") != 0) {
        return 102;
    }

    tls_counter += argc;
    printf("argv/tls ok %d\n", tls_counter);
    return 7;
}
