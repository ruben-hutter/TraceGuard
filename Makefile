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

analyze: all
	uv run $(PYTHON_ANALYZER) $(TARGETS_DIR)/program1
	
analyze-quiet: all
	uv run $(PYTHON_ANALYZER) $(TARGETS_DIR)/program1 --quiet
	
analyze-all: all
	uv run $(PYTHON_ANALYZER) $(TARGETS_DIR)/program1
	uv run $(PYTHON_ANALYZER) $(TARGETS_DIR)/program2
	uv run $(PYTHON_ANALYZER) $(TARGETS_DIR)/program3
	
analyze-all-quiet: all
	uv run $(PYTHON_ANALYZER) $(TARGETS_DIR)/program1 --quiet
	uv run $(PYTHON_ANALYZER) $(TARGETS_DIR)/program2 --quiet
	uv run $(PYTHON_ANALYZER) $(TARGETS_DIR)/program3 --quiet

.PHONY: all format tidy clean analyze analyze-quiet analyze-all analyze-all-quiet
