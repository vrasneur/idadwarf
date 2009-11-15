# mingw C++ (cross-)compiler
CC := i386-mingw32-g++
# ranlib
RANLIB := i386-mingw32-ranlib
# autoconf
AUTOCONF := autoconf
# libelf source path
ELFDIR := /home/vincent/prog/idadwarf/archives/libelf-0.8.13
# libdwarf source path
DWARFDIR := /home/vincent/prog/idadwarf/archives/dwarf-20091012/libdwarf
# include path for IDA sdk
IDAINC := /home/vincent/sources/idasdk55/include
# ida.a library path
# ... why ida.a and not libida.a?
IDALIB := /home/vincent/sources/idasdk55/libgcc.w32/ida.a
# IDA path
IDADIR := /home/vincent/.wine/drive_c/Program\ Files/IDA55
# libelf and libdwarf prefix paths
# you can keep the default value
DEPSDIR := deps
# include paths for IDA sdk, libelf and libdwarf
# you can keep the default value
INCLUDES := $(IDAINC) $(DEPSDIR)/include
# where to put the plugin when doing a dist
# you can keep the default value
DISTDIR := ../bin

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

CFLAGS = -std=gnu++98 -Wall -Wextra -Wformat=2 -Wold-style-cast -Wcast-qual -Wcast-align -D__NT__ -D__IDP__
ifeq ($(DEBUG),)
CFLAGS += -DNDEBUG
endif

LIBS := -Wl,--dll -shared -mno-cygwin
MACHINE := $(strip $(shell $(CC) -dumpmachine))
BIN := idadwarf.plw
STEMS := ida_utils registers die_cache die_utils iterators type_utils type_retrieval func_retrieval global_retrieval macro_retrieval idadwarf
OBJS := $(addsuffix .o,$(STEMS))

$(shell mkdir -p $(ABSDEPSDIR))

.PHONY: clean cleandeps distclean dist install test 

all: $(LIBELF) $(LIBDWARF) $(BIN)

$(ELFDIR):
	$(call check,isdir,$(ELFDIR),libelf source path not found)

$(DWARFDIR):
	$(call check,isdir,$(DWARFDIR),libdwarf source path not found)

$(IDADIR):
	$(call check,isdir,$(IDADIR),IDA path not found)

define compdep
(cd $< && $(1) && \
CC="$(MACHINE)-gcc" $(2) ./configure --prefix="$(ABSDEPSDIR)" \
--host="$(MACHINE)" --disable-shared $(3) && make $(4) && \
$(RANLIB) $(ABSDEPSDIR)/lib/$(5))
endef

$(LIBELF): $(ELFDIR)
	$(call compdep,:,,\
	--disable-nls --enable-compat --enable-elf64,all install,libelf.a)

$(LIBDWARF): $(DWARFDIR)
	$(call compdep,patch -N -p1 < $(CURDIR)/patch/libdwarf.patch && $(AUTOCONF),\
	CPPFLAGS="-I$(ABSDEPSDIR)/include" LDFLAGS="-L$(ABSDEPSDIR)/lib",\
	--enable-nonshared,libdwarf.a install,libdwarf.a)

$(OBJS): %.o: %.cpp
	$(CC) $(CFLAGS) -c $< $(addprefix -I,$(INCLUDES))

$(BIN): $(OBJS)
	$(CC) -L$(LIBDIR) $^ -o $@ $(LIBS) $(IDALIB) -ldwarf -lelf

install: all $(IDADIR)
	cp $(BIN) $(IDADIR)/plugins

test: install
	-wine $(IDADIR)/idag.exe&

dist: $(BIN)
	cp $< $(DISTDIR)

distclean: clean cleandeps

clean:
	-rm -f $(BIN) $(OBJS) *.gch *~

cleandeps:
	-$(call test,isfile,$(ELFDIR)/Makefile,make -C $(ELFDIR) distclean)
	-$(call test,isfile,$(DWARFDIR)/Makefile,make -C $(DWARFDIR) distclean)
	-rm -rf $(ABSDEPSDIR)/include $(ABSDEPSDIR)/lib

copydeps:
	-cp -r $(DEPSDIR) ..
