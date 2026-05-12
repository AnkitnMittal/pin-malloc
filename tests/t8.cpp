#include <stdlib.h>

int main()
{
    for (int i = 0; i < 100; i++)
    {
        void *p = malloc(64);
        free(p);
    }

    return 0;
}