/*
 * Simple Vulnerable Program for Testing
 * This program has a clear buffer overflow vulnerability
 * that should be easier for both approaches to find.
 */

#include <stdio.h>
#include <string.h>

void vulnerable_copy(char *input) {
    char small_buffer[16];  // Small buffer - easy to overflow
    strcpy(small_buffer, input);  // Direct vulnerability
    printf("Copied: %s\n", small_buffer);
}

int main() {
    char user_input[256];
    
    printf("Enter text: ");
    
    // Get user input - this is our taint source
    if (fgets(user_input, sizeof(user_input), stdin)) {
        // Remove newline
        user_input[strcspn(user_input, "\n")] = 0;
        
        // Direct call to vulnerable function
        vulnerable_copy(user_input);
    }
    
    return 0;
}
