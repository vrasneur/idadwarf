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
#include <enum.hpp>

// additional libs headers
#include <libelf.h>
#include <dwarf.h>
#include <libdwarf.h>

// local headers
#include "gcc_defs.hpp"
#include "defs.hpp"
#include "utils.hpp"
#include "ida_utils.hpp"
#include "die_cache.hpp"
#include "die_utils.hpp"
#include "type_retrieval.hpp"

using namespace std;

// global DIE cache
DieCache diecache;

void process_macros(Dwarf_Debug dbg)
{
  // create an anonymous enum to store the macros' integer constants
  enum_t enum_id = add_enum(BADADDR, NULL, 0);

  if(enum_id == BADNODE)
  {
    MSG("cannot create an enum to store constants from macros\n");
  }
  else
  {
    Dwarf_Off offset = 0;
    Dwarf_Unsigned max = 0;
    Dwarf_Signed count = 0;
    Dwarf_Macro_Details *maclist = NULL;
    Dwarf_Error err = NULL;
    int ret = DW_DLV_ERROR;

    while((ret = dwarf_get_macro_details(dbg, offset, max, &count,
                                         &maclist, &err)) == DW_DLV_OK)
    {
      for(Dwarf_Signed idx = 0; idx < count; ++idx)
      {
        struct Dwarf_Macro_Details_s *dmd = &maclist[idx];

        if(dmd->dmd_type == DW_MACINFO_define)
        {
          long val = 0;
          char *macro = dmd->dmd_macro;
          char *value_start = dwarf_find_macro_value_start(macro);
          int res = my_strict_strtol(value_start, &val);

          // TODO: check if it is a function-like macro
          // TODO: a strdup might be better?
          value_start[-1] = '\0';
          if(res == 0)
          {
            add_const(enum_id, macro, static_cast<uval_t>(val));
          }
          else
          {
            // number conversion failed
            // maybe the value was another macro name
            const_t const_id = get_const_by_name(value_start);

            if(const_id != BADADDR && get_const_enum(const_id) == enum_id)
            {
              add_const(enum_id, value_start, get_const_value(const_id));
            }
          }
        }
      }

      offset = maclist[count - 1].dmd_offset + 1;
      dwarf_dealloc(dbg, maclist, DW_DLA_STRING);
    }

    if(ret == DW_DLV_ERROR)
    {
      MSG("error getting macro details: %s\n", dwarf_errmsg(err));
    }
  }
}

void do_dies_traversal(Dwarf_Debug dbg, Dwarf_Die root_die)
{
  qvector<Dwarf_Die> queue;

  queue.push_back(root_die);

  while(!queue.empty())
  {
    Dwarf_Die other_die = NULL;
    DieHolder holder(dbg, queue.back());

    queue.pop_back();

    try_visit_type_die(holder);

    try
    {
      other_die = holder.get_sibling();
      if(other_die != NULL)
      {
        queue.push_back(other_die);
      }
    }
    catch(DieException const &exc)
    {
      MSG("cannot retrieve current DIE sibling (skipping): %s\n", exc.what());
    }

    try
    {
      other_die = holder.get_child();
      if(other_die != NULL)
      {
        queue.push_back(other_die);
      }
    }
    catch(DieException const &exc)
    {
      MSG("cannot retrieve current DIE child (skipping): %s\n", exc.what());
    }
  }
}

// process compilation units
void process_cus(Dwarf_Debug dbg)
{
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
      Dwarf_Half tag = 0;

      ret = dwarf_tag(cu_die, &tag, &err);
      if(ret == DW_DLV_OK)
      {
        if(tag == DW_TAG_compile_unit)
        {
          // CU die will be dealloc'ed when doing the traversal
          // TODO: handle DW_AT_base_types
          do_dies_traversal(dbg, cu_die);
        }
        else
        {
          MSG("got %d tag instead of compile unit (skipping)\n", tag);
        }
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
      WARNING("error during libdwarf init: %s\n", dwarf_errmsg(err));
    }
    else
    {
      process_cus(dbg);
      do_second_pass(dbg);
      update_ptr_types(dbg);
#if 0
      process_macros(dbg);
#endif

      ret = dwarf_finish(dbg, &err);
      if(ret != DW_DLV_OK)
      {
        WARNING("libdwarf cleanup failed: %s\n", dwarf_errmsg(err));
      }
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
