#include <stdlib.h>

int main()
{
    void *a = malloc(64);
    void *b = malloc(128);

    free(a);

    return 0;
}