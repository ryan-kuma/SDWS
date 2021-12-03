.PHONY: all clean 
CC=gcc
CXX=g++
LDLIBS=-lcryptopp
CFLAGS=-Wall -g
CXXFLAGS=-Wall -g
BIN=secretShare
all:$(BIN)
%.o:%.cpp 
	$(CXX) -c $(CXXFLAGS) $^ -o $@
clean:
	rm -rf *.o $(BIN)

