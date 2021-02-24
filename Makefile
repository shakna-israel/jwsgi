.PHONY: doc
doc:
	makeinfo docs/manual.texi
	makeinfo --pdf docs/manual.texi
	makeinfo --html --no-split docs/manual.texi
	makeinfo --plaintext docs/manual.texi > manual.txt
	@make docclean

.PHONY: docclean
docclean:
	-rm $(filter-out manual.info, $(filter-out manual.txt, $(filter-out manual.html, $(filter-out manual.pdf, $(wildcard manual.*)))))
