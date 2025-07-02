// test_deep_exploration_fixed.c - Forces classical angr to explore many irrelevant paths
#include <stdio.h>
#include <string.h>

void expensive_computation_1(int x) {
    // Create multiple branching paths based on untainted data
    if (x > 0) {
        if (x % 2 == 0) {
            printf("Even positive: %d\n", x);
        } else {
            printf("Odd positive: %d\n", x);
        }
    } else {
        if (x % 2 == 0) {
            printf("Even negative: %d\n", x);
        } else {
            printf("Odd negative: %d\n", x);
        }
    }
}

void expensive_computation_2(int y) {
    // More branching on untainted data
    switch (y % 4) {
        case 0: printf("Divisible by 4\n"); break;
        case 1: printf("Remainder 1\n"); break;
        case 2: printf("Remainder 2\n"); break;
        case 3: printf("Remainder 3\n"); break;
    }
}

void expensive_computation_3(int z) {
    // Even more branching
    if (z < 10) {
        printf("Single digit\n");
    } else if (z < 100) {
        printf("Double digit\n");
    } else {
        printf("Triple digit or more\n");
    }
}

void untainted_branch_1(int val) {
    expensive_computation_1(val);
    expensive_computation_2(val);
    expensive_computation_3(val);
}

void untainted_branch_2(int val) {
    expensive_computation_1(val + 1);
    expensive_computation_2(val + 2);
    expensive_computation_3(val + 3);
}

void untainted_branch_3(int val) {
    expensive_computation_1(val * 2);
    expensive_computation_2(val * 3);
    expensive_computation_3(val * 4);
}

void clear_vulnerability(char *user_input) {
    char tiny_buffer[8];  // Very small buffer
    strcpy(tiny_buffer, user_input);  // Guaranteed overflow with long input
    printf("Vulnerable result: %s\n", tiny_buffer);
}

int main() {
    char user_input[200];
    int hardcoded_choice = 42;  // NOT from user input

    // Classical angr will explore all these branches
    // TraceGuard should skip them since hardcoded_choice is not tainted
    if (hardcoded_choice > 40) {
        untainted_branch_1(hardcoded_choice);
    } else if (hardcoded_choice > 20) {
        untainted_branch_2(hardcoded_choice);
    } else {
        untainted_branch_3(hardcoded_choice);
    }

    printf("Enter dangerous input: ");
    if (fgets(user_input, sizeof(user_input), stdin)) {
        // Only this path should be prioritized by TraceGuard
        clear_vulnerability(user_input);
    }

    return 0;
}
