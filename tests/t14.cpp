#include <stdlib.h>

int main()
{
    int *arr = (int *)malloc(sizeof(int) * 1000);
    arr[0] = 42;

    return 0;
}