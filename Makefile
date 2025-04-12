.PHONY: run

main: main.c
	cc -g -o main main.c -Werror -Wall -Wextra -pedantic \
		$(shell pkg-config --cflags openssl --libs openssl) \
		-fsanitize=signed-integer-overflow \
		-fsanitize=unsigned-integer-overflow \
		-fsanitize=address

run: main
	./main

