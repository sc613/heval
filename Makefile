TFHE_PREFIX = # tfhe installation directory
FFT_OBJ = tfhe-spqlios-fma
TARGET = test

CC = gcc
CFLAGS = -Wall -I$(TFHE_PREFIX)/include

$(TARGET): he_utils.o he_stubs.o he.ml prog.ml $(TARGET).ml
	ocamlc -custom -o $@ $^ -cclib -l$(FFT_OBJ) \
	-ccopt '-L$(TFHE_PREFIX)/lib -Wl,-rpath=$(TFHE_PREFIX)/lib'

he_utils.o: he_utils.h

he_stubs.o: he_utils.h

.PHONY: clean
clean:
	@rm -f *.o *.cmi *.cmo
