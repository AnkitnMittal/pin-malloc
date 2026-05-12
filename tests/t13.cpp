#include <stdlib.h>

int main()
{
    for (int i = 0; i < 10000; i++)
    {
        void *p = malloc(128);
        free(p);
    }

    return 0;
}