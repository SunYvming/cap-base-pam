CC = gcc

CFLAGS = -O3 -std=c99 -Wall -Wextra -Ideps

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))

all: $(OBJS)

$(OBJS): $(SRCS)
	$(CC) -c $(SRCS) $(CFLAGS)

clean:
	rm -f $(OBJS)