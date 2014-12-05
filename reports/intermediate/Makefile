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
	rm *.aux
	rm *.log
clean:
	rm *.pdf 
	rm *.aux 
	rm *.log 