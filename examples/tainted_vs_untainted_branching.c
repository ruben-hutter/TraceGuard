#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


void foo(int* x) {
    *x *= 2;
}


void bar(int x) {
    if (x > 10) {
        printf("%d is > 10\n", x);
    } else {
        printf("%d is <= 10\n", x);
    }
}


int main() {
    int x;
    int y = 3;
    int z;
    char buf[10];

    while (true) {
        gets(buf);
        if (strcmp(buf, "exit") == 0) {
            break;
        }

        x = atoi(buf); // unconstrained

        if (x > 10) {
            foo(&x); // tainted
            z = x;
            x = 7; // x becomes constrained

            if (z > 20) {
                foo(&x); // untainted
            } else {
                bar(z); // tainted
            }
        } else {
            bar(y); // untainted
        }
    }

    return 0;
}

