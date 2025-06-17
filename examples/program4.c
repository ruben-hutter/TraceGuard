/*
 * Program: program4.c
 * Description: This program demonstrates taint analysis where
 * user input is not directly introduced in main. Instead,
 * the tainted data is read within the 'get_input' function,
 * and then passed to 'process_data'. This highlights how
 * taint propagates from a helper input function to other
 * processing functions, even if an intermediate function
 * primarily handles fixed data.
 */
#include <stdio.h>
#include <string.h>

void untainted_function(const char *input) {
    printf("Untainted function called with input: %s\n", input);
}

void process_data(const char *input, const char *fixed) {
    printf("Processing input: %s and fixed: %s\n", input, fixed);
    untainted_function(fixed);
}

void get_input() {
    char buffer[256];

    printf("Enter some data: ");
    if (!fgets(buffer, sizeof(buffer), stdin)) {
        return;
    }

    // Remove newline if present
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    process_data(buffer, "fixed_data");
}

int main() {
    get_input();

    return 0;
}
