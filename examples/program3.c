#include <stdio.h>
#include <string.h>

void deep_function(const char *param1, const char *param2) {
    printf("Deep function called with: %s and %s\n", param1, param2);
}

void middle_function(const char *data) {
    printf("Middle function received: %s\n", data);
    deep_function(data, "constant in middle");
}

void another_path(const char *input) {
    printf("Another path with: %s\n", input);
    deep_function("fixed in another", input);
}

void top_level(const char *user_input, const char *fixed_input) {
    printf("Top level with user input: %s and fixed: %s\n", user_input,
           fixed_input);
    middle_function(user_input);
    another_path(fixed_input);
}

int main() {
    char name[64];
    char id[32];
    char comment[128];

    printf("Enter your name: ");
    if (fgets(name, sizeof(name), stdin) != NULL) {
        // Remove newline
        size_t len = strlen(name);
        if (len > 0 && name[len - 1] == '\n') {
            name[len - 1] = '\0';
        }

        printf("Enter ID: ");
        if (fgets(id, sizeof(id), stdin) != NULL) {
            // Remove newline
            len = strlen(id);
            if (len > 0 && id[len - 1] == '\n') {
                id[len - 1] = '\0';
            }

            printf("Enter comment: ");
            if (fgets(comment, sizeof(comment), stdin) != NULL) {
                // Remove newline
                len = strlen(comment);
                if (len > 0 && comment[len - 1] == '\n') {
                    comment[len - 1] = '\0';
                }

                // Various function calls with different parameter combinations
                top_level(name, "constant string");
                middle_function(id);
                another_path(comment);
                deep_function(name, id);
            }
        }
    }

    return 0;
}