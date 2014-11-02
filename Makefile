CC=g++
CFLAGS=-Wno-deprecated -I include/
LDFLAGS=-static -lpcap
LIBS=$(shell pwd)/lib
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=paco

SOURCES=\
		main.cpp\
		context.cpp\
                DNSops.cpp\
                tcpflowstat.cpp\
		TraceAnalyze.cpp\
		packet_analyzer.cpp
		

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(CFLAGS) -L$(LIBS) $(LDFLAGS) -o $@


.cpp.o:
	$(CC) -c $< $(CFLAGS) -o $@  

clean:
	rm -f $(EXECUTABLE) $(OBJECTS) *~
