/* idadwarf: IDA plugin for retrieving DWARF debugging symbols
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

#include <map>
#include <sstream>
#include <iostream>
// IDA headers
#include <ida.hpp>
#include <loader.hpp> // plugin stuff
#include <nalt.hpp>
#include <typeinf.hpp>
#include <enum.hpp>

// additional libs headers
#include <libelf.h>
#include <dwarf.h>
#include <libdwarf.h>

// local headers
#include "gcc_defs.h"

using namespace std;

#define PLUGIN_NAME "ELF/DWARF plugin"

// enable format string warnings
extern int msg(char const *format, ...) GCC_PRINTF(1, 2);
extern void warning(char const *message, ...) GCC_PRINTF(1, 2);
extern void error(char const *format, ...) GCC_PRINTF(1, 2);

#define MSG(fmt, ...) msg("[" PLUGIN_NAME "] " fmt, ## __VA_ARGS__)

#ifndef NDEBUG
# define DEBUG(fmt, ...) msg("[" PLUGIN_NAME " at %s (%s:%d)] " fmt, __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)
#else
# define DEBUG(...) do {} while(0)
#endif

#define WARNING(fmt, ...) warning("[" PLUGIN_NAME " at %s (%s:%d)] " fmt, __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)

#define ERROR(fmt, ...) error("[" PLUGIN_NAME " at %s (%s:%d)] " fmt, __FUNCTION__, __FILE__, __LINE__, ## __VA_ARGS__)

#define CHECK_DWERR2(cond, err, fmt, ...) if(cond) { throw DieException(__FILE__, __LINE__, err, fmt, ## __VA_ARGS__); }
#define CHECK_DWERR(cond, err, fmt, ...) CHECK_DWERR2((cond) != DW_DLV_OK, err, fmt, ## __VA_ARGS__)

// DIE caching struct

enum die_type { DIE_USELESS, DIE_TYPE, DIE_VAR };

struct die_cache
{
  die_type type;
  ulong ordinal;
};

// utility funs

int get_small_encoding_value(Dwarf_Attribute attrib, Dwarf_Signed *val, Dwarf_Error *err)
{
  Dwarf_Unsigned uval = 0;
  int ret = dwarf_formudata(attrib, &uval, err);
  if(ret != DW_DLV_OK)
  {
    Dwarf_Signed sval = 0;
    ret = dwarf_formsdata(attrib, &sval, err);
    if(ret == DW_DLV_OK)
    {
      *val = sval;
    }
  }
  else
  {
    *val = uval;
  }

  return ret;
}

class DieException : public exception
{
public:
  DieException(char const *file, int const line, Dwarf_Error err, char const *fmt, ...)
  {
    ostringstream oss;
    va_list ap;
    char buffer[MAXSTR];

    va_start(ap, fmt);
    (void)qvsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);

    oss << '(' << file << ':' << line << ") " <<
      buffer << " (" << dwarf_errno(err) << ": " << dwarf_errmsg(err) << ')';
    m_msg = oss.str();
  }

  virtual ~DieException(void) throw()
  {

  }

  virtual char const * what(void) const throw()
  {
    return m_msg.c_str();
  }

private:
  string m_msg;
};

// RAII-powered DIE holder to avoid dwarf_dealloc nightmare
class DieHolder
{
public:
  DieHolder(Dwarf_Debug dbg, Dwarf_Die die, bool dealloc_die=true)
  {
    init(dbg, die, dealloc_die);
  }

  DieHolder(Dwarf_Debug dbg, Dwarf_Off offset, bool dealloc_die=true)
  {
    Dwarf_Die die = NULL;
    Dwarf_Error err = NULL;

    CHECK_DWERR(dwarf_offdie(dbg, offset, &die, &err), err,
                "cannot retrieve DIE from offset 0x%" DW_PR_DUx, offset);

    init(dbg, die, dealloc_die);
  }

  ~DieHolder(void) throw()
  {
    if(m_name != NULL)
    {
      dwarf_dealloc(m_dbg, m_name, DW_DLA_STRING);
      m_name = NULL;
    }

    for(map<int, Dwarf_Attribute>::iterator iter = m_attrs.begin();
        iter != m_attrs.end(); iter++)
    {
      if(iter->second != NULL)
      {
        dwarf_dealloc(m_dbg, iter->second, DW_DLA_ATTR);
        iter->second = NULL;
      }
    }

    if(m_dealloc_die)
    {
      dwarf_dealloc(m_dbg, m_die, DW_DLA_DIE);
      m_die = NULL;
    }
  }

  // common getters

  Dwarf_Die get_die(void) const throw()
  {
    return m_die;
  }

  Dwarf_Debug get_dbg(void) const throw()
  {
    return m_dbg;
  }

  char *get_name(void)
  {
    if(m_name == NULL)
    {
      Dwarf_Error err = NULL;

      // name may be NULL
      CHECK_DWERR2(dwarf_diename(m_die, &m_name, &err) == DW_DLV_ERROR, err,
                   "cannot get DIE name");
    }

    return m_name;
  }

  Dwarf_Attribute get_attr(int attr)
  {
    Dwarf_Attribute attrib = NULL;
    map<int, Dwarf_Attribute>::const_iterator iter = m_attrs.find(attr);

    if(iter == m_attrs.end())
    {
      Dwarf_Error err = NULL;

      // atribute may be NULL
      CHECK_DWERR2(dwarf_attr(m_die, attr, &attrib, &err) == DW_DLV_ERROR, err,
                   "cannot get DIE attribute %d", attr);
      m_attrs[attr] = attrib;
    }
    else
    {
      attrib = iter->second;
    }

    return attrib;
  }

  Dwarf_Signed get_attr_small_val(int attr)
  {
    Dwarf_Attribute attrib = NULL;
    Dwarf_Signed val = 0;
    Dwarf_Error err = NULL;

    attrib = get_attr(attr);
    CHECK_DWERR(get_small_encoding_value(attrib, &val, &err), err,
                "cannot get value of a DIE attribute %d", attr);

    return val;
  }

  Dwarf_Unsigned get_bytesize(void)
  {
    Dwarf_Unsigned bytesize = 0;
    Dwarf_Error err = NULL;

    CHECK_DWERR(dwarf_bytesize(m_die, &bytesize, &err), err,
                "cannot get DIE byte size");

    return bytesize;
  }

  Dwarf_Off get_offset(void)
  {
    if(!m_offset_used)
    {
      Dwarf_Error err = NULL;

      CHECK_DWERR(dwarf_dieoffset(m_die, &m_offset, &err), err,
                  "cannot get DIE offset");
      m_offset_used = true;
    }

    return m_offset;
  }

  Dwarf_Off get_CU_offset_range(Dwarf_Off *cu_length)
  {
    Dwarf_Off cu_offset = 0;
    Dwarf_Error err = NULL;

    CHECK_DWERR(dwarf_die_CU_offset_range(m_die, &cu_offset, cu_length, &err), err,
                "cannot get DIE CU offset range");

    return cu_offset;
  }

  Dwarf_Half get_tag(void)
  {
    Dwarf_Half tag = 0;
    Dwarf_Error err = NULL;

    CHECK_DWERR(dwarf_tag(m_die, &tag, &err), err,
                "cannot get DIE tag");

    return tag;
  }

  Dwarf_Die get_child(void)
  {
    Dwarf_Die child_die = NULL;
    Dwarf_Error err = NULL;

    // there may be no child
    CHECK_DWERR2(dwarf_child(m_die, &child_die, &err) == DW_DLV_ERROR, err,
                 "error when asking for a DIE child");

    return child_die;
  }

  Dwarf_Die get_sibling(void)
  {
    Dwarf_Die sibling_die = NULL;
    Dwarf_Error err = NULL;

    // there may be no sibling
    CHECK_DWERR2(dwarf_siblingof(m_dbg, m_die, &sibling_die, &err) == DW_DLV_ERROR, err,
                 "error when asking for a DIE sibling");

    return sibling_die;
  }

  // caching stuff

  static void init_cache(void)
  {
    m_dies_node = new netnode("$ " PLUGIN_NAME, 0, true);
  }

  static void destroy_cache(void)
  {
    if(m_dies_node != NULL)
    {
      m_dies_node->kill();
      delete m_dies_node;
      m_dies_node = NULL;
    }
  }

  bool in_cache()
  {
    return (m_dies_node->supval(static_cast<sval_t>(get_offset()), NULL,
                                sizeof(die_cache)) != -1);
  }

  void cache_useless(void)
  {
    if(!in_cache())
    {
      die_cache cache = { DIE_USELESS, 0 };

      m_dies_node->supset(static_cast<sval_t>(get_offset()), &cache, sizeof(cache));
    }
  }

  void cache_type(ulong const ordinal)
  {
    if(!in_cache())
    {
      die_cache cache = { DIE_TYPE, ordinal };

      m_dies_node->supset(static_cast<sval_t>(get_offset()), &cache, sizeof(cache));
    }
  }

  bool get_cache(die_cache *cache)
  {
    bool ret = false;
    ssize_t size = m_dies_node->supval(static_cast<sval_t>(get_offset()), cache, sizeof(*cache));

    // found?
    if(size != -1)
    {
      ret = true;
    }

    return ret;
  }

private:
  Dwarf_Debug m_dbg;
  Dwarf_Die m_die;
  Dwarf_Off m_offset;
  char *m_name;
  map<int, Dwarf_Attribute> m_attrs;
  bool m_dealloc_die;
  bool m_offset_used;
  // DIEs cache (ordered by offset in .debug_info)
  static netnode *m_dies_node;

  // no copying or assignment
  DieHolder(DieHolder const &);
  DieHolder & operator= (DieHolder const &);

  // common member vars init for the constructors
  void init(Dwarf_Debug dbg, Dwarf_Die die, bool const dealloc_die)
  {
    m_dbg = dbg;
    m_die = die;
    m_offset = 0;
    m_name = NULL;
    m_dealloc_die = dealloc_die;
    m_offset_used = false;
  };
};

// init static member vars so the linker will be happy
netnode *DieHolder::m_dies_node = NULL;

void visit_die(DieHolder &die);

// misc IDA utility funs

// simple == no fields or C++ class infos
bool get_simple_type(char const *name, qtype const &ida_type, ulong *ordinal)
{
  bool ret = false;

  // don't look for an anonymous type in the database
  if(name != NULL)
  {
    type_t const *type = NULL;
    ulong existing_ordinal = 0;
    int found = get_named_type(idati, name, NTF_TYPE, &type,
                             NULL, NULL, NULL, NULL, &existing_ordinal);

    // found an existing type with same name?
    if(found != 0)
    {
      // TODO: check if the found type is really simple
      // same name, same type_t?
      if(typcmp(type, ida_type.c_str()) == 0)
      {
        *ordinal = existing_ordinal;
        ret = true;
      }
    }
  }

  return ret;
}

bool set_simple_die_type(char const *name, qtype const &ida_type, ulong *ordinal)
{
  ulong alloced_ordinal = 0;
  bool saved = get_simple_type(name, ida_type, &alloced_ordinal);

  if(!saved)
  {
    qstring new_name(name);

    alloced_ordinal = alloc_type_ordinal(idati);

    while(!saved)
    {
      saved = set_numbered_type(idati, alloced_ordinal, 0, new_name.c_str(), ida_type.c_str());
      if(!saved)
      {
        // try an approx name to avoid collision
        new_name.append('_');
        // look if a type with same name exists for the new generated name
        saved = get_simple_type(new_name.c_str(), ida_type, &alloced_ordinal);
      }
    }
  }

  if(saved)
  {
    *ordinal = alloced_ordinal;
  }

  return saved;
}

// DIE processing begins here

// size is in bytes
static flags_t get_enum_size(Dwarf_Unsigned const size)
{
  flags_t flag = 0;

  switch(size)
  {
  case 1:
    flag = byteflag();
    break;
  case 2:
    flag = wordflag();
    break;
  case 4:
    flag = dwrdflag();
    break;
  case 8:
    flag = qwrdflag();
    break;
  case 16:
    flag = owrdflag();
    break;
  default:
    MSG("wrong size for enum (got %" DW_PR_DUu " bytes), assuming 4 bytes...\n", size);
    flag = dwrdflag();
    break;
  }

  return flag;
}

void process_enum(DieHolder &enumeration_die)
{
  char *name = NULL;
  Dwarf_Unsigned byte_size = 0;
  Dwarf_Die child_die = NULL;
  enum_t enum_type = 0;
  ulong ordinal = 0;

  name = enumeration_die.get_name();
  // bytesize is mandatory
  byte_size = enumeration_die.get_bytesize();

  // TODO: check if enum has already been defined (hard?)
  enum_type = add_enum(BADADDR, name, get_enum_size(byte_size));
  DEBUG("added an enum name='%s' bytesize=%" DW_PR_DUu "\n", name, byte_size);

  child_die = enumeration_die.get_child();
  while(child_die != NULL)
  {
    DieHolder child_holder(enumeration_die.get_dbg(), child_die);
    Dwarf_Half tag = child_holder.get_tag();

    if(tag == DW_TAG_enumerator)
    {
      char *child_name = NULL;
      Dwarf_Signed value = 0;

      child_name = child_holder.get_name();
      value = child_holder.get_attr_small_val(DW_AT_const_value);
      add_const(enum_type, child_name, static_cast<uval_t>(value));
      DEBUG("added an enumerator name='%s' value=%" DW_PR_DSd "\n", child_name, value);

      child_holder.cache_useless();
    }

    child_die = child_holder.get_sibling();
  }

  ordinal = get_enum_type_ordinal(enum_type);
  enumeration_die.cache_type(ordinal);
}

void process_base_type(DieHolder &type_die)
{
  char *name = NULL;
  Dwarf_Unsigned byte_size = 0;
  Dwarf_Signed encoding = 0;
  bool saved = false;
  qtype ida_type;

  // mandatory name for a base type
  name = type_die.get_name();
  byte_size = type_die.get_bytesize();
  encoding = type_die.get_attr_small_val(DW_AT_encoding);

  // TODO: handle bitsize/bitoffset

  // TODO: use ida unknown/void types for unrecognized types?
  switch(encoding)
  {
  case DW_ATE_address:
// ???
    break;
  case DW_ATE_boolean:
    ida_type.append(BT_BOOL);
    switch(byte_size)
    {
    case 1:
      ida_type[0] |= BTMT_BOOL1;
      break;
    case 2:
      ida_type[0] |= BTMT_BOOL2;
      break;
    case 4:
      ida_type[0] |= BTMT_BOOL4;
      break;
    default:
      msg("base type: unknown boolean size %" DW_PR_DUu ", assuming size is model specific\n", byte_size);
      ida_type[0] |= BTMT_DEFBOOL;
      break;
    }
    break;
  case DW_ATE_complex_float:
// ???
    break;
  case DW_ATE_float:
    ida_type.append(BT_FLOAT);
    switch(byte_size)
    {
    case 2:
      ida_type[0] |= BTMT_SHRTFLT;
      break;
    case 4:
      ida_type[0] |= BTMT_FLOAT;
      break;
    case 8:
      ida_type[0] |= BTMT_DOUBLE;
      break;
    case 10:
      ida_type[0] |= BTMT_LNGDBL;
      break;
    default:
      msg("unknown float byte size %" DW_PR_DUu "\n", byte_size);
      break;
    }
    break;
  case DW_ATE_signed:
    ida_type.append(BTMT_SIGNED);
    // FALLTHROUGH
  case DW_ATE_unsigned:
    if(ida_type.empty())
    {
      ida_type.append(BTMT_USIGNED);
    }
    switch(byte_size)
    {
    case 1:
      ida_type[0] |= BT_INT8;
      break;
    case 2:
      ida_type[0] |= BT_INT16;
      break;
    case 4:
      ida_type[0] |= BT_INT32;
      break;
    case 8:
      ida_type[0] |= BT_INT64;
      break;
    case 16:
      ida_type[0] |= BT_INT128;
      break;
    default:
      msg("unknown byte size %" DW_PR_DUu ", assuming natural int\n", byte_size);
      ida_type[0] |= BT_INT;
      break;
    }
    break;
  case DW_ATE_unsigned_char:
    ida_type.append(BTMT_USIGNED);
    // FALLTHROUGH
  case DW_ATE_signed_char:
    if(ida_type.empty())
    {
      ida_type.append(BTMT_SIGNED);
    }
    ida_type[0] |= BT_INT8 | BTMT_CHAR;
    if(byte_size != 1)
    {
      msg("got a char with bte size %" DW_PR_DUu " (!= 1), assuming 1 anyway...\n", byte_size);
    }
    break;
  default:
    msg("unknown base type encoding %" DW_PR_DSd "\n", encoding);
    break;
  }

  if(!ida_type.empty())
  {
    ulong ordinal = 0;
    saved = set_simple_die_type(name, ida_type, &ordinal);
    if(!saved)
    {
      msg("failed to save base type name='%s' ordinal=%lu\n", name, ordinal);
    }
    else
    {
      type_die.cache_type(ordinal);
    }
  }

  if(!saved)
  {
    type_die.cache_useless();
  }
}

void process_typedef(DieHolder &typedef_die)
{
  char *name = NULL;
  Dwarf_Attribute type_attrib = NULL;
  Dwarf_Off offset = 0;
  Dwarf_Half form = 0;
  Dwarf_Error err = NULL;

  name = typedef_die.get_name();
  type_attrib = typedef_die.get_attr(DW_AT_type);
  CHECK_DWERR(dwarf_whatform(type_attrib, &form, &err), err,
              "cannot get form for the type attribute of a typedef DIE");

  switch(form)
  {
  case DW_FORM_ref_addr:
    CHECK_DWERR(dwarf_global_formref(type_attrib, &offset, &err), err,
                "cannot get global reference address for a typedef DIE type");
    break;
  case DW_FORM_ref1:
  case DW_FORM_ref2:
  case DW_FORM_ref4:
  case DW_FORM_ref8:
  case DW_FORM_ref_udata:
  {
    Dwarf_Off cu_offset = 0;
    Dwarf_Off cu_length = 0;

    CHECK_DWERR(dwarf_formref(type_attrib, &offset, &err), err,
                "cannot get reference address for a typedef DIE type");
    cu_offset = typedef_die.get_CU_offset_range(&cu_length);
    offset += cu_offset;
  }
    break;
  default:
    break;
  }

  if(offset != 0)
  {
    DieHolder new_die(typedef_die.get_dbg(), offset);
    die_cache cache;
    bool ok = false;

    // found die may not be in cache
    visit_die(new_die);
    ok = new_die.get_cache(&cache);
    if(ok)
    {
      char const *type_name = get_numbered_type_name(idati, cache.ordinal);
      if(type_name == NULL)
      {
        MSG("cannot get type name from ordinal=%lu\n", cache.ordinal);
        ok = false;
      }
      else
      {
        qtype ida_type;
        ulong ordinal = 0;

        ida_type.append(BTF_TYPEDEF);
        append_name(&ida_type, type_name);
        ok = set_simple_die_type(name, ida_type, &ordinal);
        if(ok)
        {
          DEBUG("typedef name='%s' original type ordinal=%lu\n", name, cache.ordinal);
          typedef_die.cache_type(ordinal);
        }
      }
    }

    if(!ok)
    {
      offset = 0;
    }
  }

  if(offset == 0)
  {
    MSG("cannot process typedef name='%s'\n", name);
    typedef_die.cache_useless();
  }
}

void visit_die(DieHolder &die)
{
  if(!die.in_cache())
  {
    Dwarf_Half tag = die.get_tag();

    // TODO: no switch
    switch(tag)
    {
    case DW_TAG_enumeration_type:
      process_enum(die);
      break;
    case DW_TAG_base_type:
      process_base_type(die);
      break;
    case DW_TAG_typedef:
      process_typedef(die);
      break;
    default:
      break;
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

    try
    {
      visit_die(holder);
    }
    catch(DieException const &exc)
    {
      MSG("cannot process current DIE (skipping): %s\n", exc.what());
    }

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
      MSG("libelf out of date");
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
    WARNING("cannot open elf file '%s'", elf_path);
  }
  else
  {
    Dwarf_Debug dbg = NULL;
    Dwarf_Error err = NULL;
    // init libdwarf
    int ret = dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, &err);

    if(ret == DW_DLV_NO_ENTRY)
    {
      MSG("no DWARF infos in ELF file '%s'", elf_path);
    }
    else if(ret != DW_DLV_OK)
    {
      WARNING("error during libdwarf init: %s", dwarf_errmsg(err));
    }
    else
    {
      DieHolder::init_cache();

      process_cus(dbg);

      ret = dwarf_finish(dbg, &err);
      if(ret != DW_DLV_OK)
      {
        WARNING("libdwarf cleanup failed: %s", dwarf_errmsg(err));
      }

      DieHolder::destroy_cache();
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
  PLUGIN_NAME,         // the preferred short name of the plugin
  "ALT-F9"                // the preferred hotkey to run the plugin
};
