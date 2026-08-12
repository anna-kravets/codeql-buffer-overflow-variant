CC     ?= gcc
CFLAGS ?= -Wall -Wextra -O0 -g

all: tlv_server

tlv_server: tlv_server.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f tlv_server

.PHONY: all clean
