.PHONY:	all metadata test clean

all:	test

test:
	make -C testing
