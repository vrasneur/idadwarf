#include "macro_retrieval.hpp"

// IDA headers
#include <ida.hpp>
#include <kernwin.hpp>

// local headers
#include "ida_utils.hpp"

typedef struct
{
  char *macro;
  size_t name_len;
} macro_details;

class MacroInfos: public qvector<macro_details *>
{
public:
  virtual ~MacroInfos(void) throw()
  {
    clean();
  }

private:
  void clean(void) throw()
  {
    for(size_t idx = 0; idx < size(); ++idx)
    {
      macro_details *details = (*this)[idx];

      if(details != NULL)
      {
        delete details->macro, details->macro = NULL;
        delete details;
        (*this)[idx] = NULL;
      }
    }
  }
};

int const macro_widths[2] = { 24, 32 };
char const * const macro_headers[2] = { "Name", "Value" };
char const macro_title[] = "Macros";

uint32 idaapi get_nb_macros(void *obj)
{
  MacroInfos *macros = static_cast<MacroInfos *>(obj);

  return macros->size();
}

static void idaapi get_macro(void *obj, uint32 n, char * const *cells)
{
  MacroInfos *macros = static_cast<MacroInfos *>(obj);

  if(n == 0)
  {
    qstrncpy(cells[0], macro_headers[0], macro_widths[0]);
    qstrncpy(cells[1], macro_headers[1], macro_widths[1]);
  }
  else
  {
    macro_details const *details = (*macros)[n - 1];
    char const *macro = details->macro;
    size_t const name_len = details->name_len;

    if(macro != NULL)
    {
      qstrncpy(cells[0], macro, name_len);
      qstrncpy(cells[1], macro + name_len, MAXSTR);
    }
  }
}

static void idaapi destroy_macros(void *obj)
{
  MacroInfos *macros = static_cast<MacroInfos *>(obj);

  delete macros;
}

void retrieve_macros(Dwarf_Debug dbg)
{
  Dwarf_Off offset = 0;
  Dwarf_Unsigned max = 0;
  Dwarf_Signed count = 0;
  Dwarf_Macro_Details *maclist = NULL;
  MacroInfos *macros = new MacroInfos;
  Dwarf_Error err = NULL;
  int ret = DW_DLV_ERROR;

  while((ret = dwarf_get_macro_details(dbg, offset, max, &count,
                                       &maclist, &err)) == DW_DLV_OK)
  {
    for(Dwarf_Signed idx = 0; idx < count; ++idx)
    {      
      struct Dwarf_Macro_Details_s const *dmd = &maclist[idx];

      if(dmd->dmd_type == DW_MACINFO_define)
      {
        char *macro = dmd->dmd_macro;

        if(macro != NULL)
        {
          char *value_start = dwarf_find_macro_value_start(macro);

          if(value_start != NULL)
          {
            macro_details *details = new macro_details;
            size_t const name_len = static_cast<size_t>(value_start - macro);

            details->macro = qstrdup(macro);
            details->name_len = (name_len < MAXSTR) ? name_len : MAXSTR;
            macros->push_back(details);
          }
        }
      }

      offset = maclist[count - 1].dmd_offset + 1;
    }

    dwarf_dealloc(dbg, maclist, DW_DLA_STRING);
  }

  if(ret == DW_DLV_ERROR)
  {
    MSG("error getting macro details: %s\n", dwarf_errmsg(err));
  }

  choose2(false, -1, -1, -1, -1, macros,
          2, macro_widths, get_nb_macros, get_macro, "Macros", -1, 1,
          NULL, NULL, NULL, NULL, NULL, destroy_macros);
}
