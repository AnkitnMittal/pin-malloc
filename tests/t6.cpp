#include <stdlib.h>

int main()
{
    int *arr = (int *)malloc(10);
    arr = (int *)realloc(arr, 100);

    free(arr);
    return 0;
}