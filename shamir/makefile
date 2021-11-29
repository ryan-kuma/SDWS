.PHONY: all clean 
CC=gcc
LDLIBS=-lsss
CFLAGS=-Wall -g -I/home/ryan/test/cryptoTest/SDWS/shamir/sss
BIN=2test
all:$(BIN)
%.o:%.c 
	$(CC) -c $(CFLAGS) $^ -o $@
clean:
	rm -rf *.o $(BIN)

