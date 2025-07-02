// test_recursive_exploration_fixed.c - Recursive explosion on untainted data
#include <stdio.h>
#include <string.h>

int recursive_factorial(int n) {
    if (n <= 1) return 1;
    return n * recursive_factorial(n - 1);
}

int recursive_fibonacci(int n) {
    if (n <= 1) return n;
    return recursive_fibonacci(n - 1) + recursive_fibonacci(n - 2);
}

void recursive_countdown(int n) {
    if (n <= 0) return;
    printf("Countdown: %d\n", n);
    recursive_countdown(n - 1);
}

void process_untainted_data() {
    int static_value = 8;  // NOT from user input
    
    // These create many recursive states but don't involve tainted data
    int fact = recursive_factorial(static_value);
    int fib = recursive_fibonacci(static_value);
    recursive_countdown(static_value);
    
    printf("Factorial: %d, Fibonacci: %d\n", fact, fib);
}

void obvious_buffer_overflow(char *tainted_input) {
    char small_buffer[12];  // Small buffer
    strcpy(small_buffer, tainted_input);  // Direct vulnerability
    printf("Overflow target: %s\n", small_buffer);
}

int main() {
    char user_data[300];

    // Classical angr gets stuck exploring recursive paths
    // TraceGuard should skip this since it's not tainted
    process_untainted_data();

    printf("Enter your payload: ");
    if (fgets(user_data, sizeof(user_data), stdin)) {
        // TraceGuard should prioritize this path
        obvious_buffer_overflow(user_data);
    }

    return 0;
}
