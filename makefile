SOURCES=$(wildcard src/*.c)
OBJECTS=$(patsubst src/%,build/%.o,$(SOURCES))

CFLAGS += -std=c11 -Wall -Wextra -pedantic
CFLAGS += -Iinclude
CFLAGS += -ffunction-sections -fdata-sections
#CFLAGS += -Oz
CFLAGS += -O0 -g
LDFLAGS += -Wl,--gc-sections

all: bin/hotdove

build/%.c.o: src/%.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

bin/hotdove: build/main/hotdove.c.o $(OBJECTS)
	mkdir -p $(dir $@)
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

clean:
	rm -rf bin build
