DBGFLAGS := -O0 -ggdb3

BIN := testfpo testnotfpo teststripdbg

.PHONY: clean

all: $(BIN)

# with frame pointer omission
testfpo: test.c
	gcc $(DBGFLAGS) -fomit-frame-pointer $^ -o $@

# normal
testnotfpo: test.c
	gcc $(DBGFLAGS) $^ -o $@

# debug symbols in another file
teststripdbg: testnotfpo
	cp $< $@
	objcopy --only-keep-debug $< $@.dbg
	objcopy --strip-debug $@

clean:
	-rm -f $(BIN) *.dbg
