// test_conditional_explosion.c - Many conditional branches on untainted data
#include <stdio.h>
#include <string.h>

void complex_conditions(int a, int b, int c, int d) {
    if (a > 0) {
        if (b > 10) {
            if (c > 20) {
                if (d > 30) {
                    printf("Path 1\n");
                } else {
                    printf("Path 2\n");
                }
            } else {
                if (d > 30) {
                    printf("Path 3\n");
                } else {
                    printf("Path 4\n");
                }
            }
        } else {
            if (c > 20) {
                if (d > 30) {
                    printf("Path 5\n");
                } else {
                    printf("Path 6\n");
                }
            } else {
                if (d > 30) {
                    printf("Path 7\n");
                } else {
                    printf("Path 8\n");
                }
            }
        }
    } else {
        // Mirror structure for negative case
        if (b > 10) {
            if (c > 20) {
                if (d > 30) {
                    printf("Path 9\n");
                } else {
                    printf("Path 10\n");
                }
            } else {
                if (d > 30) {
                    printf("Path 11\n");
                } else {
                    printf("Path 12\n");
                }
            }
        } else {
            if (c > 20) {
                if (d > 30) {
                    printf("Path 13\n");
                } else {
                    printf("Path 14\n");
                }
            } else {
                if (d > 30) {
                    printf("Path 15\n");
                } else {
                    printf("Path 16\n");
                }
            }
        }
    }
}

void buffer_overflow_vuln(char *user_data) {
    char vulnerable_buffer[40];
    strcpy(vulnerable_buffer, user_data);
    printf("Vulnerability triggered with: %s\n", vulnerable_buffer);
}

int main() {
    // These values are not tainted (not from user input)
    int a = 5, b = 15, c = 25, d = 35;

    // This creates 16 different execution paths, but none involve tainted data
    complex_conditions(a, b, c, d);

    char user_input[200];
    printf("Enter your data: ");
    if (fgets(user_input, sizeof(user_input), stdin)) {
        // Only this path involves tainted data
        buffer_overflow_vuln(user_input);
    }

    return 0;
}
