// test_state_explosion.c - Designed to cause maximum state explosion in
// classical
#include <stdio.h>
#include <string.h>

void create_many_states(int x) {
    // This will create many symbolic states
    if (x == 1)
        printf("State 1\n");
    else if (x == 2)
        printf("State 2\n");
    else if (x == 3)
        printf("State 3\n");
    else if (x == 4)
        printf("State 4\n");
    else if (x == 5)
        printf("State 5\n");
    else if (x == 6)
        printf("State 6\n");
    else if (x == 7)
        printf("State 7\n");
    else if (x == 8)
        printf("State 8\n");
    else if (x == 9)
        printf("State 9\n");
    else if (x == 10)
        printf("State 10\n");
    else
        printf("Other state\n");
}

void more_branching(int y) {
    for (int i = 0; i < 5; i++) {
        if (y + i > 0) {
            create_many_states(y + i);
        }
    }
}

void critical_vulnerability(char *tainted) {
    char tiny_buffer[16];
    strcpy(tiny_buffer, tainted); // Easily exploitable
    printf("Critical vuln: %s\n", tiny_buffer);
}

int main() {
    // Symbolic value will create many states
    int symbolic_val;
    printf("Enter a number: ");
    scanf("%d", &symbolic_val);

    // This creates exponential state explosion but doesn't involve tainted
    // strings
    more_branching(symbolic_val);

    char dangerous_input[500];
    printf("Enter dangerous input: ");
    if (fgets(dangerous_input, sizeof(dangerous_input), stdin)) {
        // TraceGuard should prioritize this tainted path
        critical_vulnerability(dangerous_input);
    }

    return 0;
}
