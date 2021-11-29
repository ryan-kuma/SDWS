.PHONY: all clean 
CC=gcc
LDLIBS=-lsss
CFLAG=-Wall -g -I/home/ryan/test/cryptoTest
BIN=2test
all:$(BIN)
%.o:%.c 
	$(CC) -c $(CFLAG) $^ -o $@
clean:
	rm -rf *.o $(BIN)

