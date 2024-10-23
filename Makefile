CC = cc
AR = ar
CFLAGS = -g -O2 -Iinclude

OBJS = arena.o protomalloc.o

all: libprotomalloc.a

libprotomalloc.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: all clean
.SUFFIXES: .c
