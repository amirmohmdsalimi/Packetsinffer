CC=g++
CFLAGS=-I.
DEPS = 
OBJ = mysniffer.o 
LIBS=-lpcap

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

mysniffer: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o *~ core mysniffer