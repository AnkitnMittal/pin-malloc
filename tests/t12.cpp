#include <stdlib.h>

int main()
{
    void *a = malloc(64);
    void *b = malloc(128);
    void *c = malloc(256);

    free(b);

    void *d = malloc(100);

    free(a);
    free(c);
    free(d);

    return 0;
}