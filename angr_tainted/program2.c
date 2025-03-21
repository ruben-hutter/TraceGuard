#include <stdio.h>
#include <string.h>

void transform_data(const char *data, const char *suffix) {
    char result[512];
    sprintf(result, "%s_%s", data, suffix);
    printf("Transformed data: %s\n", result);
}

void secondary_process(const char *input) {
    printf("Secondary processing: %s\n", input);
    transform_data(input, "processed");
}

void final_operation(const char *str1, const char *str2) {
    printf("Final operation with %s and %s\n", str1, str2);
    secondary_process(str1);
}

int main() {
    char input1[128];
    char input2[128];
    
    printf("Enter first string: ");
    if (fgets(input1, sizeof(input1), stdin) != NULL) {
        // Remove newline
        size_t len = strlen(input1);
        if (len > 0 && input1[len-1] == '\n') {
            input1[len-1] = '\0';
        }
        
        printf("Enter second string: ");
        if (fgets(input2, sizeof(input2), stdin) != NULL) {
            // Remove newline
            len = strlen(input2);
            if (len > 0 && input2[len-1] == '\n') {
                input2[len-1] = '\0';
            }
            
            // Function calls with combinations of inputs and constants
            transform_data(input1, input2);
            secondary_process("constant string");
            final_operation(input1, "fixed parameter");
        }
    }
    
    return 0;
}