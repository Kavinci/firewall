.PHONY: intermediate

all: intermediate
intermediate:
	pdflatex report.tex
	pdflatex report.tex
	evince report.pdf &
curate:
	rm *.aux
	rm *.log
clean:
	rm *.pdf 
	rm *.aux 
	rm *.log