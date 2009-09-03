/* idadwarf
 * IDA plugin for retrieving DWARF debugging symbols
 * handles DWARF 2 and 3 symbols (C language focus)

 * Copyright (c) 2009 Vincent Rasneur <vrasneur@free.fr>

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 only.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

// only to overcome a namespace problem
// I swear I don't use dangerous functions
#define USE_DANGEROUS_FUNCTIONS

// IDA headers
#include <ida.hpp>
#include <loader.hpp> // plugin stuff

// additional libs headers
#include <libelf.h>
#include <dwarf.h>
#include <libdwarf.h>

// local headers
#include "gcc_defs.hpp"
#include "defs.hpp"
#include "ida_utils.hpp"
#include "die_cache.hpp"
#include "die_utils.hpp"
#include "type_retrieval.hpp"
#include "func_retrieval.hpp"
#include "macro_retrieval.hpp"

using namespace std;

// global DIE cache
DieCache diecache;

// retrieve compilation units
void retrieve_cus(CUsHolder &cus_holder)
{
  Dwarf_Debug dbg = cus_holder.get_dbg();
  Dwarf_Unsigned cu_header_length = 0;
  Dwarf_Unsigned abbrev_offset = 0;
  Dwarf_Unsigned next_cu_offset = 0;
  Dwarf_Half version_stamp = 0;
  Dwarf_Half address_size = 0;
  Dwarf_Error err = NULL;
  int ret = DW_DLV_ERROR;

  while((ret = dwarf_next_cu_header(dbg, &cu_header_length, &version_stamp,
                                    &abbrev_offset, &address_size,
                                    &next_cu_offset, &err)) == DW_DLV_OK)
  {
    Dwarf_Die cu_die = NULL;

    ret = dwarf_siblingof(dbg, NULL, &cu_die, &err);
    if(ret == DW_DLV_OK)
    {
      try
      {
        DieHolder cu_holder(dbg, cu_die, false);
        Dwarf_Half const tag = cu_holder.get_tag();

        if(tag == DW_TAG_compile_unit)
        {
          cus_holder.push_back(cu_die);
        }
        else if(tag != DW_TAG_partial_unit)
        {
          MSG("got %d tag instead of compile unit (skipping)\n", tag);
        }
      }
      catch(DieException const &exc)
      {
        MSG("cannot retrieve compilation unit: %s (skipping)\n", exc.what());
      }
    }

    if(ret == DW_DLV_ERROR)
    {
      MSG("error getting compilation unit: %s (skipping)\n", dwarf_errmsg(err));
    }
  }
}

// plugin callbacks

int idaapi init(void)
{
  int ret = PLUGIN_SKIP;

  if(inf.filetype == f_ELF)
  {
    if(elf_version(EV_CURRENT) == EV_NONE)
    {
      MSG("libelf out of date\n");
    }
    else
    {
      ret = PLUGIN_OK;
    }
  }

  return ret;
}

void idaapi run(GCC_UNUSED int arg)
{
  int fd = -1;
  static char elf_path[QMAXPATH];

  (void)get_input_file_path(elf_path, sizeof(elf_path));

  fd = open(elf_path, O_RDONLY | O_BINARY, 0);
  if(fd < 0)
  {
    WARNING("cannot open elf file '%s'\n", elf_path);
  }
  else
  {
    Dwarf_Debug dbg = NULL;
    Dwarf_Error err = NULL;
    // init libdwarf
    int ret = dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, &err);

    if(ret == DW_DLV_NO_ENTRY)
    {
      MSG("no DWARF infos in ELF file '%s'\n", elf_path);
    }
    else if(ret != DW_DLV_OK)
    {
      MSG("error during libdwarf init: %s\n", dwarf_errmsg(err));
    }
    else
    {
      // dbg will be freed by the CUs holder
      CUsHolder cus_holder(dbg);

      retrieve_cus(cus_holder);
      retrieve_types(cus_holder);
      retrieve_funcs(cus_holder);
#if 0
      retrieve_macros(dbg);
#endif
    }
  }

  if(fd >= 0)
  {
    (void)close(fd);
  }
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,             // plugin flags
  init,                   // initialize
  NULL,                   // terminate. this pointer may be NULL.
  run,                    // invoke plugin
  NULL,                   // long comment about the plugin
  // it could appear in the status line
  // or as a hint
  NULL,                   // multiline help about the plugin
  PLUGIN_NAME,            // the preferred short name of the plugin
  PLUGIN_HOTKEY           // the preferred hotkey to run the plugin
};
