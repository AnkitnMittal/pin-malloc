#include <stdlib.h>

void foo()
{
    malloc(100);
}

void bar()
{
    int *x = (int *)malloc(50);
    free(x);
}

int main()
{
    foo();
    bar();

    return 0;
}