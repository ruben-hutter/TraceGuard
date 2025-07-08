# Makefile for LaTeX Beamer Presentation

# Configuration
LATEX = pdflatex
PRESENTATION = Presentation
TEX_FILE = $(PRESENTATION).tex
PDF_FILE = $(PRESENTATION).pdf

# Build flags
LATEX_FLAGS = -interaction=nonstopmode -halt-on-error

# Auxiliary file extensions to clean
AUX_EXTENSIONS = aux bbl blg fdb_latexmk fls log nav out snm toc vrb

# Default target
.PHONY: all
all: $(PDF_FILE)

# Build the presentation PDF
$(PDF_FILE): $(TEX_FILE)
	@echo "Building presentation..."
	$(LATEX) $(LATEX_FLAGS) $(TEX_FILE)
	$(LATEX) $(LATEX_FLAGS) $(TEX_FILE)  # Second run for references
	@echo "Presentation built successfully: $(PDF_FILE)"

# Clean auxiliary files
.PHONY: clean
clean:
	@echo "Cleaning auxiliary files..."
	@for ext in $(AUX_EXTENSIONS); do \
		rm -f $(PRESENTATION).$$ext; \
	done
	@echo "Auxiliary files cleaned"

# Clean everything including PDF
.PHONY: clean-all
clean-all: clean
	@echo "Cleaning all generated files..."
	@rm -f $(PDF_FILE)
	@echo "All files cleaned"

# Show help
.PHONY: help
help:
	@echo "TraceGuard Presentation Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build the presentation (default)"
	@echo "  clean      - Remove auxiliary files"
	@echo "  clean-all  - Remove all generated files"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build presentation"
	@echo "  make clean        # Clean up auxiliary files"

# Ensure target isn't confused with files
.PHONY: $(PDF_FILE)
