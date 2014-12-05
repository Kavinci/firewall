.PHONY: final

all: final
final:
	pdflatex final-report.tex
	pdflatex final-report.tex
	evince final-report.pdf &
firewall: $(FILES)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
curate:
	rm *.aux
	rm *.log
clean:
	rm *.pdf 
	rm *.aux 
	rm *.log 