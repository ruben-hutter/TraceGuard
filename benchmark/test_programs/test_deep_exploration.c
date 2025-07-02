// test_deep_exploration.c - Forces classical angr to explore many irrelevant
// paths
#include <stdio.h>
#include <string.h>

void expensive_computation_1() {
    // Simulate complex computation that symbolic execution will explore
    int x = 42;
    for (int i = 0; i < 100; i++) {
        x = x * 2 + i;
        if (x > 1000000)
            x = x % 1000;
    }
}

void expensive_computation_2() {
    int y = 13;
    for (int i = 0; i < 150; i++) {
        y = y * 3 + i * 2;
        if (y > 2000000)
            y = y % 1500;
    }
}

void expensive_computation_3() {
    int z = 7;
    for (int i = 0; i < 200; i++) {
        z = z * 5 + i * 3;
        if (z > 3000000)
            z = z % 2000;
    }
}

void untainted_branch_1() {
    expensive_computation_1();
    printf("Branch 1 executed\n");
}

void untainted_branch_2() {
    expensive_computation_2();
    printf("Branch 2 executed\n");
}

void untainted_branch_3() {
    expensive_computation_3();
    printf("Branch 3 executed\n");
}

void vulnerable_function(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input); // Vulnerability here
    printf("Processed: %s\n", buffer);
}

int main() {
    char user_input[256];
    int choice;

    printf("Enter choice (1-3): ");
    scanf("%d", &choice);

    // These branches don't use tainted data - classical will explore all
    // TraceGuard should skip them
    if (choice == 1) {
        untainted_branch_1();
    } else if (choice == 2) {
        untainted_branch_2();
    } else if (choice == 3) {
        untainted_branch_3();
    }

    printf("Enter data: ");
    if (fgets(user_input, sizeof(user_input), stdin)) {
        vulnerable_function(
            user_input); // This should be prioritized by TraceGuard
    }

    return 0;
}
