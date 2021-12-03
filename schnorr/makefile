.PHONY: all clean
BIN=key
CC=gcc
CXX=g++
CXXFLAGS=-Wall -g 
LDLIBS=-lcryptopp
all:$(BIN)
%.cpp:%.o
	$(CXX) -c $(CXXFLAGS) $^ -o $@ $(LDLIBS) 
clean:
	rm -rf *.o $(BIN)
