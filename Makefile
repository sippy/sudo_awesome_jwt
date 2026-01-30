CC ?= cc
CFLAGS ?= -O2
CFLAGS += -fPIC -Wall -Wextra -Werror -flto -fvisibility=hidden
CPPFLAGS ?=
CPPFLAGS += -I/usr/local/include
LDFLAGS ?=
LDFLAGS += -shared
EXPORTS_FILE ?= src/exports.map
LDFLAGS += -Wl,--version-script=$(EXPORTS_FILE)
OPENSSL_STATIC ?= 0
OPENSSL_LIBS ?= -lcrypto
.if ${OPENSSL_STATIC} == 1
OPENSSL_LIBS = -Wl,-Bstatic -lcrypto -Wl,-Bdynamic
.endif
LDLIBS ?=
LDLIBS += $(OPENSSL_LIBS)

SRC := src/sudo_jwt_common.c src/sudo_jwt_policy.c src/sudo_jwt_approval.c src/jsmn.c
OUT := sudo_awesome_jwt.so

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(OUT)

.PHONY: all clean
