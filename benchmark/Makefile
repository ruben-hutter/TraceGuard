CC = gcc
CSTD = c99
CFLAGS = -Wall -Wextra -std=$(CSTD) -g -O0 -fno-stack-protector -no-pie

TEST_DIR = test_programs
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN = $(TEST_SRC:.c=)

all: $(TEST_BIN)

$(TEST_DIR)/%: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@

format:
	clang-format -i $(TEST_SRC) --style=file:../.clang-format

tidy:
	clang-tidy $(TEST_SRC) -- -std=$(CSTD)

clean:
	rm -f $(TEST_BIN)

clean-results:
	rm -rf results/
	rm -rf evaluation_results/

clean-all: clean clean-results

.PHONY: all format tidy clean clean-results clean-all
