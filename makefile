

all: netfilter-test

main.o: main.cpp

netfilter-test: main.o

clean:
	rm -f netfilter-test *.o
