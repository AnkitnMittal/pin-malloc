#include <stdlib.h>

int main()
{
    int *a = (int *)malloc(100);
    free(a);
    free(a);
}
