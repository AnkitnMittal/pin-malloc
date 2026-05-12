#include <stdlib.h>

int main()
{
    void *p = malloc(1024 * 1024 * 50);

    free(p);
    return 0;
}