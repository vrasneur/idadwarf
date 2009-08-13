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

#include <exception>
#include <iterator>
#include <map>
#include <memory>
#include <sstream>
#include <utility>

// IDA headers
#include <ida.hpp>
#include <loader.hpp> // plugin stuff
#include <nalt.hpp>
#include <typeinf.hpp>
#include <enum.hpp>
#include <struct.hpp>

// additional libs headers
#include <libelf.h>
#include <dwarf.h>
#include <libdwarf.h>

// local headers
#include "gcc_defs.h"
#include "utils.h"

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
#define THROW_DWERR(fmt, ...) throw DieException(__FILE__, __LINE__, NULL, fmt, ## __VA_ARGS__);

// DIE caching struct

enum die_type { DIE_USELESS, DIE_TYPE, DIE_VAR };

struct die_cache
{
  die_type type;
  ulong ordinal;
  bool second_pass;
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
  DieException(char const *file, int const line, Dwarf_Error err, char const *fmt, ...) throw()
    : m_err(err)
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

  virtual char const *what(void) const throw()
  {
    return m_msg.c_str();
  }

  Dwarf_Error get_error(void) const throw()
  {
    return m_err;
  }

private:
  Dwarf_Error m_err;
  string m_msg;
};

// RAII dwarf_dealloc wrapper for multiple deallocs
class DwarfDealloc
{
public:
  DwarfDealloc(Dwarf_Debug dbg) throw()
    : m_dbg(dbg)
  {

  }

  ~DwarfDealloc(void) throw()
  {
    for(size_t idx = m_deallocs.size(); idx > 0; --idx)
    {
      DeallocPair &dealloc_pair = m_deallocs[idx - 1];

      dwarf_dealloc(m_dbg, dealloc_pair.first, dealloc_pair.second);
      dealloc_pair.first = NULL;
    }
  }

  void add(void *ptr, Dwarf_Unsigned dealloc_type) throw()
  {
    m_deallocs.push_back(make_pair(ptr, dealloc_type));
  }

private:
  Dwarf_Debug m_dbg;
  typedef pair<void *, Dwarf_Unsigned> DeallocPair;
  qvector<DeallocPair> m_deallocs;

  // no copying or assignment
  DwarfDealloc(DwarfDealloc const &);
  DwarfDealloc &operator=(DwarfDealloc const &);
};

class CachedDieIterator;

// RAII-powered DIE holder to avoid dwarf_dealloc nightmare
class DieHolder
{
public:
  DieHolder(Dwarf_Debug dbg, Dwarf_Die die) throw()
  {
    init(dbg, die);
  }

  DieHolder(Dwarf_Debug dbg, Dwarf_Off offset)
  {
    Dwarf_Die die = NULL;
    Dwarf_Error err = NULL;

    CHECK_DWERR(dwarf_offdie(dbg, offset, &die, &err), err,
                "cannot retrieve DIE from offset 0x%" DW_PR_DUx, offset);

    init(dbg, die);
  }

  ~DieHolder(void) throw()
  {
    if(m_name != NULL)
    {
      dwarf_dealloc(m_dbg, m_name, DW_DLA_STRING);
      m_name = NULL;
    }

    for(MapAttrs::iterator iter = m_attrs.begin();
        iter != m_attrs.end(); ++iter)
    {
      if(iter->second != NULL)
      {
        dwarf_dealloc(m_dbg, iter->second, DW_DLA_ATTR);
        iter->second = NULL;
      }
    }

    dwarf_dealloc(m_dbg, m_die, DW_DLA_DIE);
    m_die = NULL;
  }

  // operators

  bool operator==(DieHolder const &other)
  {
    return (m_dbg == other.m_dbg && m_die == other.m_die);
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
    MapAttrs::const_iterator iter = m_attrs.find(attr);

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

  Dwarf_Off get_ref_from_attr(int attr)
  {
    Dwarf_Off offset = 0;
    Dwarf_Half form = 0;
    Dwarf_Error err = NULL;
    Dwarf_Attribute attrib = get_attr(attr);

    CHECK_DWERR2(attrib == NULL, NULL, "cannot find DIE attribute %d\n", attr);
    CHECK_DWERR(dwarf_whatform(attrib, &form, &err), err,
                "cannot get form of the DIE attribute %d", attr);

    switch(form)
    {
    case DW_FORM_ref_addr:
      CHECK_DWERR(dwarf_global_formref(attrib, &offset, &err), err,
                  "cannot get global reference address");
      break;
    case DW_FORM_ref1:
    case DW_FORM_ref2:
    case DW_FORM_ref4:
    case DW_FORM_ref8:
    case DW_FORM_ref_udata:
    {
      Dwarf_Off cu_offset = 0;
      Dwarf_Off cu_length = 0;

      CHECK_DWERR(dwarf_formref(attrib, &offset, &err), err,
                  "cannot get reference address");
      cu_offset = get_CU_offset_range(&cu_length);
      offset += cu_offset;
    }
    break;
    default:
      THROW_DWERR("unknown reference form=%d\n", form);
      break;
    }

    return offset;
  }

  Dwarf_Unsigned get_member_offset(void)
  {
    Dwarf_Attribute attrib = get_attr(DW_AT_data_member_location);
    Dwarf_Locdesc **llbuf = NULL;
    Dwarf_Loc *loc = NULL;
    Dwarf_Signed count = 0;
    Dwarf_Error err = NULL;
    DwarfDealloc dealloc(m_dbg);

    CHECK_DWERR2(attrib == NULL, NULL,
                 "retrieving a member offset implies a 'DW_AT_data_member_location' attribute");

    CHECK_DWERR(dwarf_loclist_n(attrib, &llbuf, &count, &err), err,
                "cannot get location descriptions");

    // handle deallocation
    dealloc.add(llbuf, DW_DLA_LIST);
    for(Dwarf_Signed idx = 0; idx < count; ++idx)
    {
      dealloc.add(llbuf[idx], DW_DLA_LOCDESC);
      dealloc.add(llbuf[idx]->ld_s, DW_DLA_LOC_BLOCK);
    }

    CHECK_DWERR2(count != 1, NULL,
                 "only 1 location description is supported");
    CHECK_DWERR2(llbuf[0]->ld_cents != 1, NULL,
                "only 1 location in a location description is supported");

    loc = &llbuf[0]->ld_s[0];
    CHECK_DWERR2(loc->lr_atom != DW_OP_plus_uconst, NULL,
                 "only the DW_OP_plus_count atom is supported");

    return loc->lr_number;
  }

  Dwarf_Signed get_attr_small_val(int attr)
  {
    Dwarf_Attribute attrib = NULL;
    Dwarf_Signed val = 0;
    Dwarf_Error err = NULL;

    attrib = get_attr(attr);
    CHECK_DWERR2(attrib == NULL, NULL, "cannot find DIE attribute %d\n", attr);
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
      die_cache cache = { DIE_USELESS, 0, false };

      m_dies_node->supset(static_cast<sval_t>(get_offset()), &cache, sizeof(cache));
    }
  }

  void cache_type(ulong const ordinal, bool second_pass=false)
  {
    if(ordinal != 0 && ordinal != BADADDR)
    {
      die_cache cache;
      bool do_cache = true;

      // override an useless cache type
      if(get_cache(&cache) && cache.type != DIE_USELESS)
      {
        do_cache = false;
      }

      if(do_cache)
      {
        cache.type = DIE_TYPE;
        cache.ordinal = ordinal;
        cache.second_pass = second_pass;

        m_dies_node->supset(static_cast<sval_t>(get_offset()), &cache, sizeof(cache));
      }
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

  bool get_cache_type(die_cache *cache)
  {
    bool ret = get_cache(cache);

    if(ret && cache->type != DIE_TYPE)
    {
      DEBUG("tried to access type from ordinal=%lu, but it is not a type!\n", cache->ordinal);
      ret = false;
    }

    return ret;
  }

  typedef auto_ptr<DieHolder> Ptr;

private:
  Dwarf_Debug m_dbg;
  Dwarf_Die m_die;
  Dwarf_Off m_offset;
  char *m_name;
  typedef map<int, Dwarf_Attribute> MapAttrs;
  MapAttrs m_attrs;
  bool m_offset_used;
  // DIEs cache (ordered by offset in .debug_info)
  static netnode *m_dies_node;

  friend  class CachedDieIterator;

  // no copying or assignment
  DieHolder(DieHolder const &);
  DieHolder &operator=(DieHolder const &);

  // common member vars init for the constructors
  void init(Dwarf_Debug dbg, Dwarf_Die die)
  {
    m_dbg = dbg;
    m_die = die;
    m_offset = 0;
    m_name = NULL;
    m_offset_used = false;
  };
};

// init static member vars so the linker will be happy
netnode *DieHolder::m_dies_node = NULL;

class DieChildIterator : public iterator<input_iterator_tag, DieHolder *>
{
public:
  DieChildIterator(DieHolder &die_holder, Dwarf_Half const tag)
    : m_tag(tag)
  {
    Dwarf_Debug dbg = die_holder.get_dbg();
    Dwarf_Die child_die = die_holder.get_child();

    set_current_child(dbg, child_die);
  }

  DieChildIterator(DieChildIterator &other) throw()
    : m_tag(other.m_tag), m_current_child(other.m_current_child)
  {

  }

  virtual ~DieChildIterator(void) throw()
  {
    m_current_child.reset();
  }

  bool operator==(DieChildIterator const &other) const throw()
  {
    value_type current_child = m_current_child.get();
    value_type other_child = other.m_current_child.get();
    bool ret = false;

    // same tag?
    if(m_tag != other.m_tag)
    {
      ret = false;
    }
    // got DieHolder and same one?
    else if(current_child != NULL && other_child != NULL)
    {
      ret = (current_child->get_dbg() == other_child->get_dbg() &&
             current_child->get_die() == other_child->get_die());
    }
    // does one have a NULL DieHolder?
    else
    {
      ret = (current_child == NULL && other_child == NULL);
    }

    return ret;
  }

  value_type operator*(void) const throw()
  {
    return m_current_child.get();
  }

  DieChildIterator &operator++(void)
  {
    if(m_current_child.get() != NULL)
    {
      Dwarf_Debug dbg = m_current_child->get_dbg();
      Dwarf_Die sibling_die = m_current_child->get_sibling();

      set_current_child(dbg, sibling_die);
    }

    return *this;
  }

  DieChildIterator operator++(GCC_UNUSED int dummy)
  {
    DieChildIterator iter(*this);

    ++iter;
    return iter;
  }

private:
  Dwarf_Half const m_tag;
  DieHolder::Ptr m_current_child;

  void set_current_child(Dwarf_Debug dbg, Dwarf_Die child_die)
  {
    while(child_die != NULL)
    {
      DieHolder::Ptr child_holder(new DieHolder(dbg, child_die));

      if(child_holder->get_tag() == m_tag)
      {
        m_current_child = child_holder;
        break;
      }

      child_die = child_holder->get_sibling();
    }

    if(child_die == NULL)
    {
      m_current_child.reset();
    }
  }
};

class CachedDieIterator : public iterator<input_iterator_tag, DieHolder *>
{
public:
  CachedDieIterator(Dwarf_Debug dbg)
    : m_dbg(dbg), m_current_idx(DieHolder::m_dies_node->sup1st())
  {
    set_current_die();
  }

  CachedDieIterator(CachedDieIterator &other) throw()
    : m_dbg(other.m_dbg), m_current_idx(other.m_current_idx), m_current_die(other.m_current_die)
  {

  }

  virtual ~CachedDieIterator(void) throw()
  {
    m_current_die.reset();
  }

  bool operator==(CachedDieIterator const &other) const throw()
  {
    value_type current_die = m_current_die.get();
    value_type other_die = other.m_current_die.get();
    bool ret = false;

    // same current offset?
    if(m_current_idx != other.m_current_idx)
    {
      ret = false;
    }
    // got DieHolder and same one?
    else if(current_die != NULL && other_die != NULL)
    {
      ret = (current_die->get_dbg() == other_die->get_dbg() &&
             current_die->get_die() == other_die->get_die());
    }
    // does one have a NULL DieHolder?
    else
    {
      ret = (current_die == NULL && other_die == NULL);
    }

    return ret;
  }

  value_type operator*(void) const throw()
  {
    return m_current_die.get();
  }

  CachedDieIterator &operator++(void)
  {
    if(m_current_die.get() != NULL)
    {
      m_current_idx = DieHolder::m_dies_node->supnxt(m_current_idx);

      set_current_die();
    }

    return *this;
  }

  CachedDieIterator operator++(GCC_UNUSED int dummy)
  {
    CachedDieIterator iter(*this);

    ++iter;
    return iter;
  }

private:
  Dwarf_Debug m_dbg;
  nodeidx_t m_current_idx;
  DieHolder::Ptr m_current_die;

  void set_current_die(void)
  {
    m_current_die.reset((m_current_idx == BADNODE) ?
                        NULL : new DieHolder(m_dbg, static_cast<Dwarf_Off>(m_current_idx)));
  }
};

struct less_strcmp
{
  bool operator()(char const *s1, char const *s2) const throw()
  {
    return strcmp(s1, s2) < 0;
  }
};

class EnumCmp : public const_visitor_t
{
public:
  EnumCmp(enum_t enum_id) throw()
    : m_enum_id(enum_id)
  {
    // find the enum by its id
    if(m_enum_id != BADNODE)
    {
      for_all_consts(m_enum_id, *this);
    }
  }

  EnumCmp(char const *enum_name) throw()
    : m_enum_id(BADNODE)
  {
    // find the enum by its (non null) name
    if(enum_name != NULL)
    {
      m_enum_id = get_enum(enum_name);

      if(m_enum_id != BADNODE)
      {
        for_all_consts(m_enum_id, *this);
      }
    }
  }

  EnumCmp(DieHolder &enumeration_holder)
    : m_enum_id(BADNODE)
  {
    // find the enum by its first constant name
    DieChildIterator iter(enumeration_holder, DW_TAG_enumerator);

    if(*iter != NULL)
    {
      DieHolder *const_holder = *iter;
      const_t const_id = get_const_by_name(const_holder->get_name());

      m_enum_id = get_const_enum(const_id);

      if(m_enum_id != BADNODE)
      {
        for_all_consts(m_enum_id, *this);
      }
    }
  }

  virtual ~EnumCmp() throw()
  {
    while(!m_consts.empty())
    {
      MapConsts::iterator iter = m_consts.begin();
      char *str = const_cast<char *>(iter->first);

      m_consts.erase(iter);
      qfree(str), str = NULL;
    }
  }

  enum_t get_enum_id(void) const throw()
  {
    return m_enum_id;
  }

  bool equal(DieHolder &enumeration_holder)
  {
    bool ret = false;

    if(m_enum_id != BADNODE)
    {
      for(DieChildIterator iter(enumeration_holder, DW_TAG_enumerator);
          *iter != NULL; ++iter)
      {
        DieHolder *child_holder = *iter;
        char *child_name = NULL;
        Dwarf_Signed value = 0;

        child_name = child_holder->get_name();
        value = child_holder->get_attr_small_val(DW_AT_const_value);
        if(!find(child_name, static_cast<uval_t>(value)))
        {
          break;
        }
      }

      ret = m_consts.empty();
    }

    return ret;
  }

  typedef auto_ptr<EnumCmp> Ptr;

private:
  typedef map<char const *, uval_t, less_strcmp> MapConsts;
  MapConsts m_consts;
  enum_t m_enum_id; // can be BADNODE

  // no copying or assignment
  EnumCmp(EnumCmp const &);
  EnumCmp & operator= (EnumCmp const &);

  virtual int visit_const(const_t cid, uval_t value) throw()
  {
    int ret = 1;
    ssize_t len =  get_const_name(cid, NULL, 0);

    if(len != -1)
    {
      char *buf = static_cast<char *>(qalloc(len));

      (void)get_const_name(cid, buf, len);
      m_consts[buf] = value;
      ret = 0;
    }

    return ret;
  }

  bool find(char const *name, uval_t value)
  {
    bool ret = false;
    MapConsts::iterator iter = m_consts.find(name);

    if(iter != m_consts.end() && iter->second == value)
    {
      char *str = const_cast<char *>(iter->first);

      m_consts.erase(iter);
      qfree(str), str = NULL;
      ret = true;
    }

    return ret;
  }
};

// forward declarations

void try_visit_die(DieHolder &die);

// misc IDA utility funs

void append_ordinal_name(qtype &type, ulong const ordinal)
{
  type.append('#');
  append_de(&type, ordinal);
}

void append_complex_type(qtype &new_type, qtype const *complex_type)
{
  char const *complex_name = NULL;

  complex_name = reinterpret_cast<char const *>(complex_type->c_str());
  append_name(&new_type, complex_name);
}

void append_complex_type(qtype &new_type, ulong const ordinal)
{
  qtype complex_type;
  char const *complex_name = NULL;

  append_ordinal_name(complex_type, ordinal);
  complex_name = reinterpret_cast<char const *>(complex_type.c_str());
  append_name(&new_type, complex_name);
}

void make_new_type(qtype &new_type, type_t const *type, ulong const ordinal)
{
  type_t const type_header = type[0];

  // use the "'#' + ordinal" name for complex types
  if(is_type_complex(type_header))
  {
    new_type.append(type_header);
    if(!is_type_typedef(type_header))
    {
      append_dt(&new_type, 0);
    }

    append_complex_type(new_type, ordinal);
  }
  else
  {
    new_type = type;
  }
}

// simple == no fields or C++ class infos
bool get_simple_type(char const *name, qtype const &ida_type, ulong *ordinal)
{
  bool ret = false;

  // don't look for an anonymous type in the database
  if(name != NULL)
  {
    type_t const *type = NULL;
    ulong existing_ordinal = 0;
    int found = get_named_type(idati, name, NTF_TYPE | NTF_NOBASE, &type,
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
  flags_t flag = get_flags_by_size(static_cast<size_t>(size));

  if(size == 0)
  {
    MSG("wrong size for enum (got %" DW_PR_DUu " bytes), assuming 4 bytes...\n", size);
    flag = dwrdflag();
  }

  return flag;
}

void process_enum(DieHolder &enumeration_holder)
{
  char const *name = enumeration_holder.get_name();
  enum_t enum_id = BADNODE;
  ulong ordinal = 0;
  EnumCmp::Ptr enum_cmp;

  if(name != NULL)
  {
    enum_cmp.reset(new EnumCmp(name));
  }
  else
  {
    // anonymous enum, find by first const name
    enum_cmp.reset(new EnumCmp(enumeration_holder));
  }

  if(enum_cmp.get() != NULL &&
     enum_cmp->equal(enumeration_holder))
  {
    enum_id = enum_cmp->get_enum_id();
  }

  // enum not already processed?
  if(enum_id == BADNODE)
  {
    // bytesize is mandatory
    Dwarf_Unsigned byte_size = enumeration_holder.get_bytesize();

    enum_id = add_enum(BADADDR, name, get_enum_size(byte_size));
    DEBUG("added an enum name='%s' bytesize=%" DW_PR_DUu "\n", name, byte_size);

    for(DieChildIterator iter(enumeration_holder, DW_TAG_enumerator);
        *iter != NULL; ++iter)
    {
      DieHolder *child_holder = *iter;
      char *child_name = NULL;
      Dwarf_Signed value = 0;

      child_name = child_holder->get_name();
      value = child_holder->get_attr_small_val(DW_AT_const_value);
      add_const(enum_id, child_name, static_cast<uval_t>(value));
      DEBUG("added an enumerator name='%s' value=%" DW_PR_DSd "\n", child_name, value);
      child_holder->cache_useless();
    }
  }

  ordinal = get_enum_type_ordinal(enum_id);
  enumeration_holder.cache_type(ordinal);
}

void process_base_type(DieHolder &type_holder)
{
  // mandatory name for a base type
  char *name = type_holder.get_name();
  Dwarf_Unsigned byte_size = type_holder.get_bytesize();
  Dwarf_Signed encoding = type_holder.get_attr_small_val(DW_AT_encoding);
  bool saved = false;
  qtype ida_type;

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
      type_holder.cache_type(ordinal);
    }
  }

  if(!saved)
  {
    type_holder.cache_useless();
  }
}

bool add_unspecified_type(ulong *ordinal)
{
  qtype type;
  ulong new_ordinal = 0;
  bool saved = false;

  type.append(BTF_VOID);
  saved = set_simple_die_type("void", type, &new_ordinal);
  if(saved)
  {
    DEBUG("added unspecified type ordinal=%lu\n", new_ordinal);
    *ordinal = new_ordinal;
  }
  else
  {
    MSG("cannot add unspecified type\n");
  }

  return saved;
}

void process_unspecified(GCC_UNUSED DieHolder &unspecified_holder)
{
  ulong ordinal = 0;

  (void)add_unspecified_type(&ordinal);
}

bool look_ref_type(DieHolder &modifier_holder, ulong *ordinal)
{
  bool found = true;

  if(modifier_holder.get_attr(DW_AT_type) == NULL)
  {
    // add an unspecified type for modifiers without type attribute
    found = add_unspecified_type(ordinal);
  }
  else
  // need no find the original type?
  {
    Dwarf_Off offset = modifier_holder.get_ref_from_attr(DW_AT_type);
    DieHolder new_die(modifier_holder.get_dbg(), offset);
    die_cache cache;

    // found die may not be in cache
    try_visit_die(new_die);
    found = new_die.get_cache_type(&cache);
    if(found)
    {
      *ordinal = cache.ordinal;
    }
  }

  return found;
}

void process_typed_modifier(DieHolder &modifier_holder, ulong type_ordinal)
{
  type_t const *type = NULL;
  char const *type_name = get_numbered_type_name(idati, type_ordinal);
  bool ok = false;

  ok = get_numbered_type(idati, type_ordinal, &type);
  if(type_name == NULL || !ok)
  {
    MSG("cannot get type from ordinal=%lu\n", type_ordinal);
    ok = false;
  }
  else
  {
    Dwarf_Half const tag = modifier_holder.get_tag();
    qtype new_type;

    make_new_type(new_type, type, type_ordinal);

    switch(tag)
    {
    case DW_TAG_const_type:
      new_type[0] |= BTM_CONST;
      break;
    case DW_TAG_volatile_type:
      new_type[0] |= BTM_VOLATILE;
      break;
    case DW_TAG_pointer_type:
      new_type.before(BT_PTR);
    break;
    default:
      MSG("unknown modifier tag %d\n", tag);
      ok = false;
      break;
    }

    // elements from const and volatile arrays must have the same modifiers
    if(is_type_array(type[0]))
    {
      type_t *elem_type = const_cast<type_t *>(skip_array_type_header(new_type.c_str()));

      switch(tag)
      {
      case DW_TAG_const_type:
        elem_type[0] |= BTM_CONST;
        break;
      case DW_TAG_volatile_type:
        elem_type[0] |= BTM_VOLATILE;
        break;
      default:
        break;
      } 
    }

    if(ok)
    {
      ulong ordinal = 0;

      ok = set_simple_die_type(NULL, new_type, &ordinal);
      if(ok)
      {
        DEBUG("added modifier from original type='%s' ordinal=%lu\n", type_name, ordinal);
        modifier_holder.cache_type(ordinal);
      }
    }
  }

  if(!ok)
  {
    MSG("cannot process modifier type offset=0x%" DW_PR_DUx "\n",
        modifier_holder.get_offset());
    modifier_holder.cache_useless();
  }
}

void process_modifier(DieHolder &modifier_holder)
{
  ulong ordinal = 0;
  bool ok = look_ref_type(modifier_holder, &ordinal);

  if(ok)
  {
    process_typed_modifier(modifier_holder, ordinal);
  }
}

void process_typed_typedef(DieHolder &typedef_holder, ulong type_ordinal)
{
  char const *name = typedef_holder.get_name();
  char const *type_name = get_numbered_type_name(idati, type_ordinal);
  bool ok = true;

  if(type_name == NULL)
  {
    MSG("cannot get type name from ordinal=%lu\n", type_ordinal);
    ok = false;
  }
  else
  {
    ulong ordinal = 0;

    // typedef for an anonymous type?
    if(type_name[0] == '\0')
    {
      qtype old_name;

      append_ordinal_name(old_name, type_ordinal);
      rename_named_type(idati, reinterpret_cast<char const *>(old_name.c_str()),
                        name, NTF_TYPE);
      ordinal = type_ordinal;
    }
    else
    {
      type_t const typedef_header = BTF_TYPEDEF;
      qtype new_type;

      make_new_type(new_type, &typedef_header, type_ordinal);
      ok = set_simple_die_type(name, new_type, &ordinal);
    }

    if(ok)
    {
      DEBUG("typedef name='%s' original type ordinal=%lu\n", name, ordinal);
      typedef_holder.cache_type(ordinal);
    }
  }

  if(!ok)
  {
    MSG("cannot process typedef name='%s' offset=0x%" DW_PR_DUx "\n",
        name, typedef_holder.get_offset());
    typedef_holder.cache_useless();
  }
}

void process_typedef(DieHolder &typedef_holder)
{
  ulong ordinal = 0;
  bool ok = look_ref_type(typedef_holder, &ordinal);

  if(ok)
  {
    process_typed_typedef(typedef_holder, ordinal);
  }
}

// TODO: handle multimensional arrays
void process_array(DieHolder &array_holder)
{
  Dwarf_Off offset = array_holder.get_ref_from_attr(DW_AT_type);
  DieHolder new_die(array_holder.get_dbg(), offset);
  die_cache cache;
  bool ok = false;

  // found die may not be in cache
  try_visit_die(new_die);
  ok = new_die.get_cache_type(&cache);
  if(ok)
  {
    char const *type_name = get_numbered_type_name(idati, cache.ordinal);
    type_t const *type = NULL;

    ok = get_numbered_type(idati, cache.ordinal, &type);
    if(type_name == NULL || !ok)
    {
      MSG("cannot get type from ordinal=%lu\n", cache.ordinal);
      ok = false;
    }
    else
    {
      DieChildIterator iter(array_holder, DW_TAG_subrange_type);
      qtype new_type = NULL;
      Dwarf_Signed size = 0;

      if(*iter != NULL)
      {
        DieHolder *subrange_holder = *iter;

        try
        {
          // get the array (max) size
          // TODO: handle DW_AT_count too
          size = subrange_holder->get_attr_small_val(DW_AT_upper_bound) + 1;
        }
        catch(DieException const &exc)
        {
          if(exc.get_error() != NULL)
          {
            throw;
          }

          // no size...
          size = 0;
        }
      }

      ok = build_array_type(&new_type, type, static_cast<int>(size));
      if(!ok)
      {
        MSG("cannot build array type from original type='%s' ordinal=%lu\n",
            type_name, cache.ordinal);
      }
      else
      {
        ulong ordinal = 0;

        ok = set_simple_die_type(NULL, new_type, &ordinal);
        if(ok)
        {
          DEBUG("added array from original type='%s' ordinal=%lu\n", type_name, cache.ordinal);
          array_holder.cache_type(ordinal);
        }
      }
    }
  }

  if(!ok)
  {
    MSG("cannot process array type offset=0x%" DW_PR_DUx "\n",
        array_holder.get_offset());
    array_holder.cache_useless();
  }
}

void add_structure_member(DieHolder *member_holder, struc_t *sptr,
                          bool *second_pass)
{
  char const *member_name = member_holder->get_name();
  Dwarf_Off const offset = member_holder->get_ref_from_attr(DW_AT_type);
  DieHolder new_die(member_holder->get_dbg(), offset);
  ea_t moffset = sptr->is_union() ? 0 : static_cast<ea_t>(member_holder->get_member_offset());
  die_cache cache;
  bool ok = false;

  try_visit_die(new_die);
  ok = new_die.get_cache_type(&cache);
  if(!ok)
  {
    // member type not in cache
    // maybe caused by a forward declaration?
    // TODO: add an unknown member anyway?
    *second_pass = true;
  }
  else
  {
    char const *type_name = get_numbered_type_name(idati, cache.ordinal);
    type_t const *type = NULL;

    ok = get_numbered_type(idati, cache.ordinal, &type);
    if(type_name == NULL || !ok)
    {
      MSG("cannot get member type from ordinal=%lu\n", cache.ordinal);
    }
    else
    {
      size_t size = get_type_size0(idati, type);

      if(size == BADSIZE)
      {
        MSG("cannot get size of member name='%s'\n", member_name);
      }
      else
      {
        if(is_type_enum(*type))
        {
          enum_t enum_id = getn_enum(cache.ordinal);
          uval_t serial = get_enum_idx(cache.ordinal);
          typeinfo_t mt;

          mt.ec.tid = enum_id;
          mt.ec.serial = serial;
          add_struc_member(sptr, member_name, moffset, enumflag(), &mt, size);
        }
        else if(is_type_struni(*type))
        {
          tid_t mstruc_id = get_struc_id(type_name);
          typeinfo_t mt;
          int res = 0;

          // override type size (we got an error if we don't do that...)
          size = get_struc_size(mstruc_id);
          mt.tid = mstruc_id;
          res = add_struc_member(sptr, member_name, moffset, struflag(), &mt, size);
          if(res != 0)
          {
            MSG("failed to add struct/union member res=%d name='%s' offset=0x%" DW_PR_DUx "\n",
                res, member_name, offset);
          }
        }
        else
        {
          add_struc_member(sptr, member_name, moffset, 0, NULL, size);
          member_t *mptr = get_member_by_name(sptr, member_name);
          set_member_tinfo(idati, sptr, mptr, 0, type, NULL, 0);
        }
        
        DEBUG("adding one member name='%s'\n", member_name);
      }
    }
  }
}

// structure/union processing (no incomplete type)
void process_complete_structure(DieHolder &structure_holder, char const *name,
                                ulong *ordinal, bool *second_pass)
{
  bool const is_union = structure_holder.get_tag() == DW_TAG_union_type;
  tid_t struc_id = add_struc(BADADDR, name, is_union);

  if(struc_id != BADNODE)
  {
    struc_t *sptr = get_struc(struc_id);

    for(DieChildIterator iter(structure_holder, DW_TAG_member);
        *iter != NULL; ++iter)
    {
      add_structure_member(*iter, sptr, second_pass);
    }

    // TODO: how to set the final struct/union size?

    *ordinal = sptr->ordinal;

    if(*ordinal == BADADDR)
    {
      MSG("cannot process complete %s offset=0x%" DW_PR_DUx "\n",
          is_union ? "union" : "structure",
          structure_holder.get_offset());
    }
  }
}

void process_structure(DieHolder &structure_holder)
{
  char const *name = structure_holder.get_name();
  Dwarf_Attribute declaration = structure_holder.get_attr(DW_AT_declaration);
  ulong ordinal = 0;
  bool const is_union = structure_holder.get_tag() == DW_TAG_union_type;
  bool second_pass = false;

  // got an incomplete type?
  if(declaration != NULL)
  {
    qtype new_type;

    new_type.append(BTF_VOID);
    set_simple_die_type(name, new_type, &ordinal);
  }
  else
  {
    process_complete_structure(structure_holder, name,
                               &ordinal, &second_pass);
  }

  if(ordinal != 0)
  {
    DEBUG("added %s name='%s' ordinal=%lu\n",
          is_union ? "union" : "structure", name, ordinal);
    structure_holder.cache_type(ordinal, second_pass);
  }
  else
  {
    // do not print an error for a recursive member
    if(get_struc_id(name) == BADNODE)
    {
      MSG("cannot process %s offset=0x%" DW_PR_DUx "\n",
          is_union ? "union" : "structure",
          structure_holder.get_offset());
    }

    structure_holder.cache_useless();
  }  
}

void add_subroutine_parameter(DieHolder *param_holder, qtype &params_type,
                              bool *second_pass)
{
  Dwarf_Off offset = param_holder->get_ref_from_attr(DW_AT_type);
  DieHolder new_die(param_holder->get_dbg(), offset);
  type_t const *type = NULL;
  qtype new_type;
  die_cache cache;
  bool ok = false;

  // found die may not be in cache
  try_visit_die(new_die);
  ok = new_die.get_cache_type(&cache);

  if(ok)
  {
    ok = get_numbered_type(idati, cache.ordinal, &type);
    if(!ok)
    {
      MSG("cannot get parameter type from ordinal=%lu\n", cache.ordinal);
    }
  }

  if(!ok)
  {
    // maybe caused by the structure being currently processed
    new_type.append(BT_UNKNOWN);
    *second_pass = true;
  }
  else
  {
    make_new_type(new_type, type, cache.ordinal);
  }

  type = new_type.c_str();
  params_type.append(type);
}

void add_subroutine_return(DieHolder &subroutine_holder, qtype &func_type,
                           bool *second_pass)
{
  qtype new_type;

  // no return type?
  if(subroutine_holder.get_attr(DW_AT_type) == NULL)
  {
    // assume the function returns void
    new_type.append(BTF_VOID);
  }
  else
  {
    Dwarf_Off offset = subroutine_holder.get_ref_from_attr(DW_AT_type);
    DieHolder new_die(subroutine_holder.get_dbg(), offset);
    die_cache cache;
    bool ok = false;

    // found die may not be in cache
    try_visit_die(new_die);
    ok = new_die.get_cache_type(&cache);

    if(ok)
    {
      type_t const *type = NULL;

      ok = get_numbered_type(idati, cache.ordinal, &type);
      if(!ok)
      {
        MSG("cannot get return type from ordinal=%lu\n", cache.ordinal);
      }
      else
      {
        make_new_type(new_type, type, cache.ordinal);
      }
    }

    if(!ok)
    {
      // we will check again later
      new_type.append(BT_UNKNOWN);
      *second_pass = true;
    }
  }

  func_type.append(new_type.c_str());
}

void process_subroutine(DieHolder &subroutine_holder)
{
  qtype func_type;
  qtype params_type;
  int nb_params = 0;
  ulong ordinal = 0;
  bool second_pass = false;
  bool saved = false;

  func_type.append(BT_FUNC | BTMT_DEFCALL);
  func_type.append(static_cast<type_t>(CM_UNKNOWN | CM_M_NN));

  // look for the return type
  add_subroutine_return(subroutine_holder, func_type, &second_pass);

  // look for the parameters types
  for(DieChildIterator iter(subroutine_holder, DW_TAG_formal_parameter);
      *iter != NULL; ++iter)
  {
    add_subroutine_parameter(*iter, params_type, &second_pass);
    nb_params++;
  }

  if(nb_params == 0)
  {
    func_type[1] |= CM_CC_VOIDARG;
  }
  else
  {
    func_type[1] |= CM_CC_UNKNOWN;
    append_dt(&func_type, nb_params);
    func_type.append(params_type.c_str());
  }

  saved = set_simple_die_type(NULL, func_type, &ordinal);
  if(!saved)
  {
    MSG("cannot process function type offset=0x%" DW_PR_DUx "\n",
      subroutine_holder.get_offset());
  }
  else
  {
    DEBUG("added function ordinal=%lu\n", ordinal);
    subroutine_holder.cache_type(ordinal, second_pass);
  }
}

void visit_die(DieHolder &die_holder)
{
  if(!die_holder.in_cache())
  {
    Dwarf_Half const tag = die_holder.get_tag();

    switch(tag)
    {
    case DW_TAG_enumeration_type:
      process_enum(die_holder);
      break;
    case DW_TAG_base_type:
      process_base_type(die_holder);
      break;
    case DW_TAG_unspecified_type:
      process_unspecified(die_holder);
      break;
    case DW_TAG_volatile_type:
    case DW_TAG_const_type:
    case DW_TAG_pointer_type:
      process_modifier(die_holder);
      break;
    case DW_TAG_typedef:
      process_typedef(die_holder);
      break;
    case DW_TAG_array_type:
      process_array(die_holder);
      break;
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
      process_structure(die_holder);
      break;
    case DW_TAG_subroutine_type:
      process_subroutine(die_holder);
      break;
    default:
      break;
    }
  }
}

void try_visit_die(DieHolder &die_holder)
{
  try
  {
    visit_die(die_holder);
  }
  catch(DieException const &exc)
  {
    MSG("cannot process DIE (skipping): %s\n", exc.what());
  }
}

void second_process_structure(DieHolder &structure_holder,
                              ulong const ordinal)
{
  char const *type_name = get_numbered_type_name(idati, ordinal);
  tid_t struc_id = get_struc_id(type_name);
  struc_t *sptr = get_struc(struc_id);
  bool third_pass = false;

  for(DieChildIterator child_iter(structure_holder, DW_TAG_member);
      *child_iter != NULL; ++child_iter)
  {
    DieHolder *member_holder = *child_iter;
    char const *member_name = member_holder->get_name();
    member_t *member_id = get_member_by_name(sptr, member_name);

    // no member at this offset?
    if(member_id == NULL)
    {
      add_structure_member(member_holder, sptr, &third_pass);
    }
  }

  if(third_pass)
  {
    MSG("TODO: struct name='%s' ordinal=%lu needs a third pass\n", type_name, ordinal);
  }
}

void second_process_subroutine(GCC_UNUSED DieHolder &subroutine_holder,
                               GCC_UNUSED ulong const ordinal)
{
  // TODO
}

void do_second_pass(Dwarf_Debug dbg)
{
  for(CachedDieIterator cached_iter(dbg);
      *cached_iter != NULL; ++cached_iter)
  {
    DieHolder *die_holder = *cached_iter;
    die_cache cache;
    bool const found = die_holder->get_cache(&cache);

    // this DIE needs a second pass?
    if(found && cache.type == DIE_TYPE && cache.second_pass)
    {
      Dwarf_Half const tag = die_holder->get_tag();

      switch(tag)
      {
      case DW_TAG_structure_type:
      case DW_TAG_union_type:
        second_process_structure(*die_holder, cache.ordinal);
        break;
      case DW_TAG_subroutine_type:
        second_process_subroutine(*die_holder, cache.ordinal);
        break;
      default:
        break;
      }
    }
  }
}

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

    try_visit_die(holder);

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
      DieHolder::init_cache();

      process_cus(dbg);
      do_second_pass(dbg);
#if 0
      process_macros(dbg);
#endif

      ret = dwarf_finish(dbg, &err);
      if(ret != DW_DLV_OK)
      {
        WARNING("libdwarf cleanup failed: %s\n", dwarf_errmsg(err));
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
