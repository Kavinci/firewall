.PHONY: final

all: final
final:
	pdflatex final-report.tex
	pdflatex final-report.tex
	evince final-report.pdf &
compile:
	pdflatex final-report.tex
	pdflatex final-report.tex
curate:
	rm -f *.aux
	rm -f *.log
	rm -f *.out
clean:
	rm -f *.pdf 
	rm -f *.aux 
	rm -f *.log 
	rm -f *.out