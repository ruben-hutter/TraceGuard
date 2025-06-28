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
    if (!fgets(buffer, sizeof(buffer) * 2, stdin)) {
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
