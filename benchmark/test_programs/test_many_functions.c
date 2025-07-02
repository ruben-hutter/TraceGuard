// test_many_functions.c - Many functions, but only one path leads to
// vulnerability
#include <stdio.h>
#include <string.h>

void dummy_func_1() { int x = 1 * 2 * 3 * 4 * 5; }
void dummy_func_2() { int x = 2 * 3 * 4 * 5 * 6; }
void dummy_func_3() { int x = 3 * 4 * 5 * 6 * 7; }
void dummy_func_4() { int x = 4 * 5 * 6 * 7 * 8; }
void dummy_func_5() { int x = 5 * 6 * 7 * 8 * 9; }
void dummy_func_6() { int x = 6 * 7 * 8 * 9 * 10; }
void dummy_func_7() { int x = 7 * 8 * 9 * 10 * 11; }
void dummy_func_8() { int x = 8 * 9 * 10 * 11 * 12; }
void dummy_func_9() { int x = 9 * 10 * 11 * 12 * 13; }
void dummy_func_10() { int x = 10 * 11 * 12 * 13 * 14; }

void process_untainted_data(int value) {
    if (value > 100) {
        dummy_func_1();
        dummy_func_2();
        dummy_func_3();
    } else if (value > 50) {
        dummy_func_4();
        dummy_func_5();
        dummy_func_6();
    } else {
        dummy_func_7();
        dummy_func_8();
        dummy_func_9();
        dummy_func_10();
    }
}

void hidden_vulnerability(char *tainted_input) {
    char small_buffer[32];
    strcpy(small_buffer, tainted_input); // Vulnerability
    printf("Hidden vulnerability triggered: %s\n", small_buffer);
}

int main() {
    int untainted_value = 75; // Not from user input
    char user_data[128];

    // Process untainted data - creates many paths
    process_untainted_data(untainted_value);

    printf("Enter sensitive data: ");
    if (fgets(user_data, sizeof(user_data), stdin)) {
        // Only this path should be prioritized by TraceGuard
        hidden_vulnerability(user_data);
    }

    return 0;
}
