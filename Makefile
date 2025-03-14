CC = clang
CSTD = c99
CFLAGS = -Wall -Wextra -Wpedantic -std=$(CSTD) -O2 -fno-stack-protector
EXAMPLES_DIR = examples
SOURCES = $(wildcard $(EXAMPLES_DIR)/*.c)
EXAMPLES = $(SOURCES:.c=)

all: format $(EXAMPLES)

$(EXAMPLES): %: %.c
	$(CC) $(CFLAGS) $< -o $@

format:
	clang-format -i $(SOURCES)

tidy:
	clang-tidy $(SOURCES) -- -std=$(CSTD)

clean:
	rm -f $(EXAMPLES)

