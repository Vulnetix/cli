CC ?= cc
CFLAGS += -O2 -Wall -Wextra -Wformat=2 -Werror=format-security

all: app

app: main.o
	$(CC) $(CFLAGS) -o $@ $^

check:
	grep -w TODO src/*.c || true
	sysctl -w net.core.somaxconn=1024
	wget -w 2 https://example.com/data.txt
