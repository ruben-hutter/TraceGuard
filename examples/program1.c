/*
 * Program: program1.c
 * Description: This program demonstrates basic taint analysis.
 * It takes user input using fgets and passes it to various functions
 * (process_data, analyze_string, untainted_function) to show how taint
 * propagates through arguments and memory.
 */
#include <stdio.h>
#include <string.h>

void helper_function(const char *data) {
    printf("Helper function received: %s\n", data);
}

void process_data(const char *input, const char *fixed) {
    printf("Processing input: %s and fixed: %s\n", input, fixed);
    helper_function(input);
}

void analyze_string(const char *str) {
    printf("Analyzing string: %s\n", str);
    helper_function("constant string in analyze");
}

void untainted_function(const char *fixed_str) {
    printf("This function only uses constant data: %s\n", fixed_str);
}

int main() {
    char buffer[256];

    printf("Enter some data: ");
    if (!fgets(buffer, sizeof(buffer), stdin)) {
        return 1;
    }

    // Remove newline if present
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    // Call functions with stdin data and constants
    process_data(buffer, "fixed string");
    analyze_string(buffer);

    // Call function with only constant data
    untainted_function("constant data only");

    return 0;
}
