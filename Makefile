CC = clang
CFLAGS = -Wall -Werror -Wextra -Wpedantic $(shell pkg-config --cflags gmp) -g
LDFLAGS = $(shell pkg-config --libs gmp) -lm
COMMON_OBJS = rsa.o randstate.o numtheory.o

all: keygen encrypt decrypt

keygen: keygen.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

encrypt: encrypt.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

decrypt: decrypt.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f keygen encrypt decrypt *.o

cleankeys:
	rm -f *. {pub,priv}

format:
	clang-format -i -style=file *.[ch]

# debug: CFLAGS += -g
# debug: all


# $@ --> the most recent target
# $^ --> ALL the prerequisutes
# $< --> First repreq (the most relevant)
