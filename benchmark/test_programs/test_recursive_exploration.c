// test_recursive_exploration.c - Recursive calls that create state explosion
#include <stdio.h>
#include <string.h>

int fibonacci_untainted(int n) {
    if (n <= 1)
        return n;
    return fibonacci_untainted(n - 1) + fibonacci_untainted(n - 2);
}

void factorial_untainted(int n) {
    if (n <= 1)
        return;
    factorial_untainted(n - 1);
}

void deep_recursion_untainted(int depth) {
    if (depth <= 0)
        return;
    deep_recursion_untainted(depth - 1);
}

void vulnerable_with_tainted_data(char *input) {
    char buffer[50];
    strcpy(buffer, input); // Vulnerability
    printf("Vulnerable function: %s\n", buffer);
}

int main() {
    char user_input[100];

    // These create many states but don't involve tainted data
    int result1 = fibonacci_untainted(8);
    factorial_untainted(6);
    deep_recursion_untainted(10);

    printf("Computations done. Enter input: ");
    if (fgets(user_input, sizeof(user_input), stdin)) {
        // Only this should be prioritized
        vulnerable_with_tainted_data(user_input);
    }

    return 0;
}
