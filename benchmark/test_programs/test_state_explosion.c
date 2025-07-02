// test_state_explosion.c - String input instead of integer
#include <stdio.h>
#include <string.h>

void create_many_string_states(char *input) {
    // Create branching based on string content (tainted)
    if (strlen(input) > 10) {
        printf("Long input\n");
    } else {
        printf("Short input\n");
    }
    
    if (input[0] == 'A') {
        printf("Starts with A\n");
    } else if (input[0] == 'B') {
        printf("Starts with B\n");
    } else {
        printf("Starts with other\n");
    }
}

void untainted_integer_branching() {
    int static_val = 25;  // Hardcoded, not tainted
    
    // Classical angr will explore these, TraceGuard should skip
    if (static_val > 20) {
        printf("Static val > 20\n");
    }
    if (static_val % 5 == 0) {
        printf("Static val divisible by 5\n");
    }
    if (static_val < 30) {
        printf("Static val < 30\n");
    }
}

void critical_vulnerability(char *dangerous_input) {
    char tiny_buffer[6];  // Extremely small
    strcpy(tiny_buffer, dangerous_input);  // Obvious overflow
    printf("Critical: %s\n", tiny_buffer);
}

int main() {
    char user_input[400];
    
    // Untainted branching - TraceGuard should skip
    untainted_integer_branching();
    
    printf("Enter string input: ");
    if (fgets(user_input, sizeof(user_input), stdin)) {
        // Remove newline
        user_input[strcspn(user_input, "\n")] = 0;
        
        // This creates tainted string-based branching
        create_many_string_states(user_input);
        
        // Clear vulnerability with tainted data
        critical_vulnerability(user_input);
    }

    return 0;
}
