# mingw C++ cross-compiler
CC := i386-mingw32-g++
# libelf source path
ELFDIR := /home/vincent/prog/idadwarf/archives/libelf-0.8.11
# libdwarf source path
DWARFDIR := /home/vincent/prog/idadwarf/archives/dwarf-20090710/libdwarf
# include path for IDA sdk
IDAINC := /home/vincent/sources/idasdk/include
# ida.a library path
# ... why ida.a and not libida.a?
IDALIB := /home/vincent/sources/idasdk/libgcc.w32/ida.a
# IDA path
IDADIR := /home/vincent/.wine/drive_c/Program\ Files/IDA
# libelf and libdwarf prefix paths
# you can keep the default value
DEPSDIR := deps
# include paths for IDA sdk, libelf and libdwarf
# you can keep the default value
INCLUDES := $(IDAINC) $(DEPSDIR)/include

# predicate functions
inpath = $(shell which $(1) >/dev/null 2>&1; echo $$?)
isdir = $(shell test -d $(1); echo $$?)
isfile = $(shell test \( -r $(1) -a \! -d $(1) \); echo $$?)

# error checking functions
clean = $(strip $(subst 0,,$(1)))
check = $(if $(call clean,$(call $(1),$(2))),$(error $(2): $(3)))
checks = $(foreach a,$(2),$(call check,$(1),$(a),$(3)))
test = $(if $(call clean,$(call $(1),$(2))),$(4),$(3))

ABSDEPSDIR := $(abspath $(DEPSDIR))
LIBDIR := $(ABSDEPSDIR)/lib
LIBELF := $(LIBDIR)/libelf.a
LIBDWARF := $(LIBDIR)/libdwarf.a

# do some checks
$(call check,inpath,$(CC),compiler not in your path)
$(call check,isdir,$(IDAINC),IDA SDK include path not found)
$(call check,isfile,$(IDALIB),IDA library not found)

CFLAGS := -std=gnu++98 -Wall -Wextra -Wformat=2 -Wold-style-cast -DNDEBUG -D__NT__ -D__IDP__ -Wl,--dll -shared -mno-cygwin
MACHINE := $(strip $(shell $(CC) -dumpmachine))
BIN := idadwarf.plw

$(shell mkdir -p $(ABSDEPSDIR))

.PHONY: clean cleandeps distclean install test

all: $(LIBELF) $(LIBDWARF) $(BIN)

$(ELFDIR):
	$(call check,isdir,$(ELFDIR),libelf source path not found)

$(DWARFDIR):
	$(call check,isdir,$(DWARFDIR),libdwarf source path not found)

$(IDADIR):
	$(call check,isdir,$(IDADIR),IDA path not found)

define compdep
(cd $< && patch -N -p1 < $(CURDIR)/$(1) || autoconf && \
CC="$(MACHINE)-gcc" $(2) ./configure --prefix="$(ABSDEPSDIR)" \
--host="$(MACHINE)" --disable-shared $(3) && make $(4))
endef

$(LIBELF): $(ELFDIR)
	$(call compdep,patch/libelf.patch,,\
	--disable-nls --enable-compat --enable-elf64,all install)

$(LIBDWARF): $(DWARFDIR)
	$(call compdep,patch/libdwarf.patch,\
	CPPFLAGS="-I$(ABSDEPSDIR)/include" LDFLAGS="-L$(ABSDEPSDIR)/lib",\
	--enable-nonshared,libdwarf.a install)

$(BIN): %.plw: %.cpp
	$(CC) $(CFLAGS) $(addprefix -I,$(INCLUDES)) -L$(LIBDIR) $< -o $@ $(IDALIB) -ldwarf -lelf

install: all $(IDADIR)
	cp $(BIN) $(IDADIR)/plugins

test: install
	-wine $(IDADIR)/idag.exe&

distclean: clean cleandeps

clean:
	-rm -f $(BIN) *~

cleandeps:
	-$(call test,isfile,$(ELFDIR)/Makefile,make -C $(ELFDIR) distclean)
	-$(call test,isfile,$(DWARFDIR)/Makefile,make -C $(DWARFDIR) distclean)
	-rm -rf $(ABSDEPSDIR)/include $(ABSDEPSDIR)/lib
