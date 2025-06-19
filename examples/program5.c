#include <stdio.h>
#include <string.h>

void bar_l(const char *input, const char *fixed_str) {
    char combined[512];
    snprintf(combined, sizeof(combined), "%s_%s", input, fixed_str);
    printf("bar_l received tainted data and fixed string: %s\n", combined);
}

void bar(const char *fixed_str) {
    char buffer[256];

    printf("Enter some data: ");
    if (!fgets(buffer, sizeof(buffer), stdin)) {
        return;
    }

    // Remove newline if present
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    bar_l(buffer, fixed_str);
}

void main_l() { bar("A fixed string"); }

void foo_l_l(const char *data) {
    printf("foo_l_l received tainted data: %s\n", data);
}

void foo_l_r() { printf("foo_l_r is not tainted"); }

void foo_l(const char *data) {
    foo_l_l(data);
    foo_l_r();
}

void foo_r(const char *data) {
    printf("foo_r received tainted data: %s\n", data);
}

void foo(const char *data) {
    foo_l(data);
    foo_r(data);
}

void main_r_r(const char *data) {
    printf("main_r_r received tainted data: %s\n", data);
}

void main_r(const char *data) {
    main_r_r(data);
    foo("A fixed string");
}

int main() {
    char buffer[256];

    printf("Enter some data: ");
    if (!fgets(buffer, sizeof(buffer), stdin)) {
        return 1;
    }

    // Remove newline if present
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    main_l();
    main_r(buffer);

    return 0;
}
