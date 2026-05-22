# TARDUS spec build
# pdflatex + bibtex pipeline + EasyCrypt proof check placeholder

LATEX        := pdflatex
LATEX_FLAGS  := -interaction=nonstopmode -halt-on-error
BIBTEX       := bibtex
MAIN         := SPEC
SECTIONS     := $(wildcard sections/*.tex)
PROOFS_DIR   := ../proofs
PROOFS       := $(wildcard $(PROOFS_DIR)/*.ec)

.PHONY: all clean proofs help

all: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex refs.bib $(SECTIONS)
	$(LATEX) $(LATEX_FLAGS) $(MAIN).tex
	$(BIBTEX) $(MAIN)
	$(LATEX) $(LATEX_FLAGS) $(MAIN).tex
	$(LATEX) $(LATEX_FLAGS) $(MAIN).tex

proofs:
	@echo "EasyCrypt proof check (placeholder — Phase 0 signature-only)"
	@for f in $(PROOFS); do echo "  $$f"; done
	@echo "Mechanization deferred to Phase 4 via easycrypt CLI."

clean:
	rm -f *.aux *.log *.toc *.bbl *.blg *.synctex.gz *.out *.fls *.fdb_latexmk
	rm -f $(MAIN).pdf

help:
	@echo "Targets:"
	@echo "  all       — build $(MAIN).pdf (default)"
	@echo "  proofs    — list EasyCrypt files in ../proofs/"
	@echo "  clean     — remove build artifacts"
