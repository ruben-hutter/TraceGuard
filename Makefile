CC = gcc
CSTD = c99
CFLAGS = -Wall -Wextra -Wpedantic -std=$(CSTD) -g

TARGETS_DIR = examples
TARGETS_SRC = $(wildcard $(TARGETS_DIR)/*.c)
TARGETS_BIN = $(TARGETS_SRC:.c=)

all: $(TARGETS_BIN)

$(TARGETS_DIR)/%: $(TARGETS_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@

format:
	clang-format -i $(TARGETS_SRC)

tidy:
	clang-tidy $(TARGETS_SRC) -- -std=$(CSTD)

clean:
	rm -f $(TARGETS_BIN)

.PHONY: all format tidy clean
