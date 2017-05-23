debug = 0

OBJS = src/ns_msg.o \
       src/log.o \
       src/rbtree.o \
       src/stream.o

ifneq ($(debug), 0)
    CFLAGS += -g -DDEBUG -D_DEBUG
    LDFLAGS += -g
endif

all: cleandns unit-test

cleandns: src/cleandns.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

unit-test: test/test.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean
clean:
	-rm -f src/*.o cleandns unit-test 


