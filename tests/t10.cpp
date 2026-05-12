#include <stdlib.h>

int main()
{
    void *a = malloc(100);
    void *b = calloc(20, 8);

    a = realloc(a, 500);

    free(a);
    free(b);

    return 0;
}