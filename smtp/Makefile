CC = $(shell curl-config --cc --cflags)
CCFLAGS = -Wall -O3 -fpic -g3
LIBS = $(shell curl-config --libs)

SOURCES = $(wildcard *.c)
OBJS = $(SOURCES:%.c=%.o)
EXE = smtp

all: $(OBJS) $(SOURCES)
	$(CC) -o $(EXE) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CCFLAGS) -c $< -o $@

.PHONY: clean
clean: 
	rm -f $(OBJS) *.o $(EXE)
