CC=gcc
CFLAGS=-Wall -Werror
LDFLAGS=-lcrypto

test: tests/test_main
	./tests/test_main

tests/test_main: tests/test_main.c jsean.c
	$(CC) $(CFLAGS) -DJSEAN_NO_MAIN -I. tests/test_main.c -o tests/test_main $(LDFLAGS)

clean:
	rm -f tests/test_main
