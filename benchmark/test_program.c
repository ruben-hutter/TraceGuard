/*
 * Benchmark Program for TraceGuard vs Classical Angr Evaluation
 * Author: Ruben Hutter
 * University of Basel - Bachelor Thesis
 * 
 * This program demonstrates a scenario where TraceGuard should outperform
 * classical symbolic execution by focusing on taint-guided paths.
 * The vulnerability is deep in the call chain, requiring multiple function
 * calls to reach from the taint source (fgets).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Untainted helper functions that don't process user input
void untainted_helper1() {
    printf("Performing untainted operation 1\n");
    // Some computation that doesn't involve user data
    int result = 42 * 17 + 128;
    printf("Computed value: %d\n", result);
}

void untainted_helper2() {
    printf("Performing untainted operation 2\n");
    // Another computation with only constants
    int value = 314 * 2;
    printf("Pi * 2 = %d\n", value);
}

void untainted_helper3() {
    printf("Performing untainted operation 3\n");
    // More untainted operations
    char fixed_str[] = "This is a constant string";
    printf("Fixed string: %s\n", fixed_str);
}

// Deep function that eventually contains the vulnerability
void deep_vulnerable_function(char *user_data) {
    char small_buffer[32];  // Vulnerable buffer - only 32 bytes
    
    printf("Processing user data in vulnerable function\n");
    
    // This is the vulnerability - strcpy can overflow small_buffer
    // if user_data is longer than 31 characters
    strcpy(small_buffer, user_data);
    
    printf("Buffer contents: %s\n", small_buffer);
}

// Intermediate function in the taint flow
void process_user_input(char *data) {
    printf("Processing user input through intermediate function\n");
    
    // Some processing that maintains taint
    if (strlen(data) > 0) {
        printf("Data length: %zu\n", strlen(data));
        
        // Call the vulnerable function with tainted data
        deep_vulnerable_function(data);
    }
}

// Another intermediate function
void validate_and_process(char *input) {
    printf("Validating input\n");
    
    // Some validation logic (but doesn't prevent overflow)
    if (input != NULL) {
        printf("Input is not null, proceeding\n");
        process_user_input(input);
    } else {
        printf("Input is null, skipping\n");
    }
}

// Function that branches based on user choice
void handle_user_choice(int choice, char *user_input) {
    printf("Handling user choice: %d\n", choice);
    
    switch (choice) {
        case 1:
            printf("Choice 1: Processing user input\n");
            validate_and_process(user_input);
            break;
            
        case 2:
            printf("Choice 2: Untainted operations only\n");
            untainted_helper1();
            untainted_helper2();
            break;
            
        case 3:
            printf("Choice 3: More untainted operations\n");
            untainted_helper3();
            break;
            
        default:
            printf("Invalid choice, doing nothing\n");
            break;
    }
}

int main() {
    char user_buffer[256];
    int user_choice = 1;  // Default to vulnerable path
    
    printf("=== TraceGuard Benchmark Program ===\n");
    
    // First, call some untainted functions to create "noise"
    printf("Performing initial setup...\n");
    untainted_helper1();
    untainted_helper2();
    untainted_helper3();
    
    // Simplified: always take the vulnerable path for testing
    // In a real scenario, this would be user input
    user_choice = 1;
    
    printf("Enter some text: ");
    
    // This is the taint source - fgets introduces tainted data
    if (!fgets(user_buffer, sizeof(user_buffer), stdin)) {
        printf("Failed to read input\n");
        return 1;
    }
    
    // Remove newline if present
    size_t len = strlen(user_buffer);
    if (len > 0 && user_buffer[len - 1] == '\n') {
        user_buffer[len - 1] = '\0';
    }
    
    printf("You entered: %s\n", user_buffer);
    
    // More untainted operations after getting input
    printf("Performing post-input processing...\n");
    untainted_helper1();
    
    // Handle the user choice with the tainted input
    // Force choice = 1 to always take vulnerable path
    handle_user_choice(user_choice, user_buffer);
    
    // More untainted cleanup
    printf("Cleaning up...\n");
    untainted_helper3();
    
    printf("Program completed successfully\n");
    return 0;
}

/*
 * VULNERABILITY ANALYSIS:
 * 
 * Taint Source: fgets(user_buffer, sizeof(user_buffer), stdin)
 * 
 * Taint Flow Path (only when choice == 1):
 * main() -> handle_user_choice() -> validate_and_process() -> 
 * process_user_input() -> deep_vulnerable_function() -> strcpy()
 * 
 * Vulnerability: Buffer overflow in deep_vulnerable_function()
 * - small_buffer[32] can be overflowed by strcpy(small_buffer, user_data)
 * - Triggered when user_data length > 31 characters
 * 
 * TraceGuard Advantage:
 * - Should prioritize the taint-carrying path (choice == 1)
 * - Should avoid exploring untainted paths (choice == 2, 3)
 * - Should reach vulnerability faster than exhaustive exploration
 * 
 * Classical Angr Behavior:
 * - Will explore all paths uniformly
 * - Will spend time on untainted_helper functions
 * - May explore choice == 2 and choice == 3 paths extensively
 * - Will eventually find vulnerability but less efficiently
 */
