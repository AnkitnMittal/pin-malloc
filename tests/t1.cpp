#include <stdlib.h>

int main()
{
    int *arr = (int *)malloc(100);

    free(arr);
    return 0;
}