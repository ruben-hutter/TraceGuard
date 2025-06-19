CC = gcc
CSTD = c99
CFLAGS = -Wall -Wextra -Wpedantic -std=$(CSTD) -g

TARGETS_DIR = examples
TARGETS_SRC = $(wildcard $(TARGETS_DIR)/*.c)
TARGETS_BIN = $(TARGETS_SRC:.c=)

SCRIPTS_DIR = scripts
PYTHON_ANALYZER = $(SCRIPTS_DIR)/main.py

all: format $(TARGETS_BIN)

$(TARGETS_DIR)/%: $(TARGETS_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@

format:
	clang-format -i $(TARGETS_SRC)

tidy:
	clang-tidy $(TARGETS_SRC) -- -std=$(CSTD)

clean:
	rm -f $(TARGETS_BIN)

BINARY ?=
ANALYSIS_FLAGS ?=

analyze: all
	@if [ -z "$(BINARY)" ]; then \
		echo "Error: No binary specified. Usage: make analyze BINARY=examples/program1 [ANALYSIS_FLAGS=\"--some-flag\"]" >&2; \
		exit 1; \
	fi; \
	if [ ! -f "$(BINARY)" ]; then \
		echo "Error: Binary '$(BINARY)' not found." >&2; \
		exit 1; \
	fi; \
	uv run $(PYTHON_ANALYZER) "$(BINARY)" $(ANALYSIS_FLAGS)

.PHONY: all format tidy clean analyze
