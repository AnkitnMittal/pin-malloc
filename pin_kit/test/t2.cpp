#include <stdio.h>
#include <stdlib.h>

void funcA()
{
    int *arr = (int *)malloc(5 * sizeof(int));
    arr[0] = 10;

    arr = (int *)realloc(arr, 10 * sizeof(int));

    free(arr);
}

void funcB()
{
    int *arr = (int *)calloc(4, sizeof(int));
    arr[1] = 20;
}

int main()
{
    funcA();
    funcB();

    int *p = (int *)malloc(100);
    free(p);

    return 0;
}
