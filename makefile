CC=g++
CFLAGS=-I.
DEPS = 
OBJ =sniffer.o 
LIBS=-lpcap

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sniffer: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o *~ core sniffer