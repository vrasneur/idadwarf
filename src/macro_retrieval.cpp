#include "macro_retrieval.hpp"

// IDA headers
#include <ida.hpp>
#include <enum.hpp>

// local headers
#include "ida_utils.hpp"
// number conversion utils
#include "utils.hpp"

void retrieve_macros(Dwarf_Debug dbg)
{
  // create an anonymous enum to store the macros' integer constants
  // TODO: looks like we put too much data inside this enum...
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

