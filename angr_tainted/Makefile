CC = gcc
CFLAGS = -Wall -Wextra -g
TARGETS = program1 program2 program3

all: $(TARGETS)

program1: program1.c
	$(CC) $(CFLAGS) -o program1 program1.c

program2: program2.c
	$(CC) $(CFLAGS) -o program2 program2.c

program3: program3.c
	$(CC) $(CFLAGS) -o program3 program3.c

install-deps:
	pip install angr claripy

clean:
	rm -f $(TARGETS)

analyze: all
	uv run simple_taint.py ./program1
	
analyze-quiet: all
	uv run simple_taint.py ./program1 --quiet
	
analyze-all: all
	uv run simple_taint.py ./program1
	uv run simple_taint.py ./program2
	uv run simple_taint.py ./program3
	
analyze-all-quiet: all
	uv run simple_taint.py ./program1 --quiet
	uv run simple_taint.py ./program2 --quiet
	uv run simple_taint.py ./program3 --quiet

.PHONY: all clean install-deps analyze analyze-quiet analyze-all analyze-all-quiet
