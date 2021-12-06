.PHONY: all clean
BIN=client server
CXX=g++
CXXFLAGS=-Wall -g -I/home/ryan/workspace/muduo
#INCLUDES=-I/home/ryan/workspace/muduo
LDLIBS=-lmuduo_net -lmuduo_base -lpthread -lcryptopp
all:$(BIN)
%.cc:%.o
	$(CXX) -c $(CXXFLAGS) $^ -o $@ $(LDLIBS)
clean:
	rm -rf *.o $(BIN)
