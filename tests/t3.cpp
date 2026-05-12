#include <stdlib.h>

int main()
{
    void *a = malloc(64);
    void *b = malloc(128);
    void *c = malloc(256);

    free(a);
    free(b);
    free(c);

    return 0;
}