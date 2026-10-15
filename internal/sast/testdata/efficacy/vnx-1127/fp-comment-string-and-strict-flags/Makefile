CFLAGS += -O2 -Wall -Wextra -Werror -Wformat-security -Wno-unused-parameter
# CFLAGS += -w   (never: it hides format-string bugs)

tune:
	sudo sysctl -w net.core.somaxconn=1024

build:
	$(CC) $(CFLAGS) -o app main.c
