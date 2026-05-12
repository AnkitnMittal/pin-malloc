#include <stdlib.h>

int main()
{
    char *ptr = (char *)malloc(32);
    ptr = (char *)realloc(ptr, 128);

    return 0;
}