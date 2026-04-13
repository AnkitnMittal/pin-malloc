#include <stdlib.h>

int main()
{
    int *a = (int *)malloc(100);
    int *b = (int *)calloc(50, sizeof(int));

    a = (int *)realloc(a, 200);
    free(a);

    return 0;
}