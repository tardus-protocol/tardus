PAPER = PAPER

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex sections/*.tex refs.bib
	pdflatex -interaction=nonstopmode $(PAPER).tex
	bibtex $(PAPER) || true
	pdflatex -interaction=nonstopmode $(PAPER).tex
	pdflatex -interaction=nonstopmode $(PAPER).tex

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg \
	      $(PAPER).log $(PAPER).out $(PAPER).toc \
	      sections/*.aux

.PHONY: all clean
