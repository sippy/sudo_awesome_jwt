CC ?= cc
CFLAGS ?= -O2
CFLAGS += -fPIC -Wall -Wextra -Werror -flto
CPPFLAGS ?=
CPPFLAGS += -I/usr/local/include
LDFLAGS ?=
LDFLAGS += -shared
LDLIBS ?= -lcrypto

SRC := src/sudo_jwt_policy.c src/jsmn.c
OUT := sudo_jwt_approval.so

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(OUT)

.PHONY: all clean
