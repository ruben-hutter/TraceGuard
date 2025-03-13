CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c99 -O2
EXAMPLES_DIR = examples
SOURCES = $(wildcard $(EXAMPLES_DIR)/*.c)
EXAMPLES = $(SOURCES:.c=)

all: $(EXAMPLES)

$(EXAMPLES): %: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXAMPLES)

