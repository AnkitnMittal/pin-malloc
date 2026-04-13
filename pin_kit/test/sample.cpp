#include <iostream>
#include <cstdlib>

void foo() {
    int* a = (int*)malloc(100 * sizeof(int));
    int* b = (int*)malloc(200 * sizeof(int));

    free(a);   // freed
    // b is intentionally NOT freed (to simulate active allocation)
}

void bar() {
    double* x = (double*)malloc(50 * sizeof(double));
    free(x);
}

int main() {
    std::cout << "Running test program...\n";

    int* p = (int*)malloc(10 * sizeof(int));
    free(p);

    foo();
    bar();

    // One more allocation not freed
    char* leak = (char*)malloc(500);

    return 0;
}
