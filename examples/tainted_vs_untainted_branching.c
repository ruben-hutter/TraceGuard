#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void foo(int x) { printf("foo: %d\nunconstrained\n", x); }

void bar(int x) { printf("bar: %d\nconstrained\n", x); }

void foo1(int x) { printf("foo1: %d\nconstrained\n", x); }

void bar1(int x) { printf("bar1: %d\nunconstrained\n", x); }

int main(void) {
    int x;
    int y = 3;
    int z;
    char buf[10];

    while (true) {
        gets(buf);
        if (strcmp(buf, "exit") == 0) {
            break;
        }

        x = atoi(buf); // x is unconstrained

        if (x > 10) {
            foo(x);
            z = x; // z becomes unconstrained
            x = 7; // x becomes constrained

            if (z > 30) {
                foo1(x); // x is constrained
            } else {
                bar1(z); // z is unconstrained
            }
        } else {
            bar(y); // y is constrained
        }
    }

    return 0;
}
