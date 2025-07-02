// This is designed to show maximum TraceGuard advantage
#include <stdio.h>
#include <string.h>

// Simulate expensive analysis WITHOUT printf calls
void complex_untainted_analysis_1(int val) {
    int result = 0;
    for (int i = 0; i < 5; i++) {
        if ((val + i) % 2 == 0) {
            result += i;  // Computation without printf
        } else {
            result -= i;
        }
    }
}

void complex_untainted_analysis_2(int val) {
    int total = 0;
    for (int j = 0; j < 3; j++) {
        for (int k = 0; k < 3; k++) {
            if ((val + j + k) > 10) {
                total += j * k;  // Computation without printf
            }
        }
    }
}

void complex_untainted_analysis_3(int val) {
    int switch_result = 0;
    switch (val % 6) {
        case 0: switch_result = 10; break;
        case 1: switch_result = 20; break;
        case 2: switch_result = 30; break;
        case 3: switch_result = 40; break;
        case 4: switch_result = 50; break;
        case 5: switch_result = 60; break;
    }
}

void mega_untainted_computation() {
    int constant_value = 37;  // Hardcoded - NOT tainted
    
    // Classical angr will create many states exploring these
    complex_untainted_analysis_1(constant_value);
    complex_untainted_analysis_2(constant_value);
    complex_untainted_analysis_3(constant_value);
    
    // More branching without printf
    if (constant_value > 30) {
        complex_untainted_analysis_1(constant_value / 2);
        if (constant_value % 7 == 0) {
            complex_untainted_analysis_2(constant_value * 2);
        }
    }
}

void immediate_vulnerability(char *tainted_data) {
    char buffer[4];  // Ridiculously small
    strcpy(buffer, tainted_data);  // Instant overflow
}

int main() {
    char user_payload[500];
    
    // Massive untainted computation - classical will waste time here
    // TraceGuard should completely skip this
    mega_untainted_computation();
    
    // Direct input without printf that blocks execution
    fgets(user_payload, sizeof(user_payload), stdin);
    
    // Direct path to vulnerability - TraceGuard should find this fast
    immediate_vulnerability(user_payload);
    
    return 0;
}
