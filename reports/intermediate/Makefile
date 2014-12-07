.PHONY: intermediate

all: intermediate
intermediate:
	pdflatex report.tex
	pdflatex report.tex
	evince intermediate-report.pdf &
compile:
	pdflatex report.tex
	pdflatex report.tex
curate:
	rm -f *.aux
	rm -f *.log
	rm -f *.out
clean:
	rm -f *.pdf 
	rm -f *.aux 
	rm -f *.out
	rm -f *.log 