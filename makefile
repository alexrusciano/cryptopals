CC = gcc
IDIR = .
LDIR = 
LIBS = -lcrypto
CFLAGS = -I $(IDIR)$

DEPS = 
OBJ = set1_test.o set1.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

set1_test: $(OBJ)
	$(CC) -o $@ $^ $(CLFAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
