.PHONY: all clean
BIN=kk
CC=gcc
CFLAGS=-Wall -g -I/home/ryan/workspace/secp256k1/include
LDLIBS=-lsecp256k1
all:$(BIN)
%.c:%.o
	$(CC) -c $(CFLAGS) $^ -o $@ $(LDLIBS) 
clean:
	rm -rf *.o $(BIN)
