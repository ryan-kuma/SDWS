.PHONY: all clean 
CC=gcc
CXX=g++
LDLIBS=-lcryptopp
CFLAGS=-Wall -g
CXXFLAGS=-Wall -g
#BIN=byteshare integerShare
BIN=multiShare
all:$(BIN)
%.o:%.cpp 
	$(CXX) -c $(CXXFLAGS) $^ -o $@
clean:
	rm -rf *.o $(BIN)

