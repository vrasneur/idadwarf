DBGFLAGS := -O0 -ggdb3
CFLAGS := -m32 $(DBGFLAGS)

BIN := testfpo testnotfpo teststripdbg test2

.PHONY: clean

all: $(BIN)

# with frame pointer omission
testfpo: test.c
	gcc $(CFLAGS) -fomit-frame-pointer $^ -o $@

# normal
testnotfpo: test.c
	gcc $(CFLAGS) $^ -o $@

# debug symbols in another file
teststripdbg: testnotfpo
	cp $< $@
	objcopy --only-keep-debug $< $@.dbg
	objcopy --strip-debug $@

# normal, with enums and structs
test2: test2.c
	gcc $(CFLAGS) $^ -o $@

clean:
	-rm -f $(BIN) *.dbg
