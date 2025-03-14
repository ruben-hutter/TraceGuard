#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void foo(int *x) { *x *= 2; }

void bar(int x) {
    if (x > 5) {
        printf("%d is > 5\n", x);
    } else {
        printf("%d is <= 5\n", x);
    }
}

int main(void) {
    int x;
    int y = 3;
    int z;
    char buf[10]; // TODO: maybe malloc this

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

            if (z > 30) {
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
