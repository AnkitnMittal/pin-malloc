#include <stdlib.h>

int main()
{
    int *arr = (int *)calloc(50, sizeof(int));

    free(arr);
    return 0;
}