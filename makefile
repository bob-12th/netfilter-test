LDLIBS=-lpcap

all: netfilter-test

main.o: main.cpp

netfilter-test: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f netfilter-test *.o
