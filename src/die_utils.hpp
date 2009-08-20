#ifndef IDADWARF_DIE_UTILS_HPP
#define IDADWARF_DIE_UTILS_HPP

#include <exception>
#include <map>
#include <memory>
#include <sstream>

// additional libs headers
#include <dwarf.h>
#include <libdwarf.h>

// local headers
#include "die_cache.hpp"

using namespace std;

#define CHECK_DWERR2(cond, err, fmt, ...) if(cond) { throw DieException(__FILE__, __LINE__, err, fmt, ## __VA_ARGS__); }
#define CHECK_DWERR(cond, err, fmt, ...) CHECK_DWERR2((cond) != DW_DLV_OK, err, fmt, ## __VA_ARGS__)
#define THROW_DWERR(fmt, ...) throw DieException(__FILE__, __LINE__, NULL, fmt, ## __VA_ARGS__);

int get_small_encoding_value(Dwarf_Attribute attrib, Dwarf_Signed *val, Dwarf_Error *err);

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

// RAII-powered DIE holder to avoid dwarf_dealloc nightmare
class DieHolder
{
public:
  DieHolder(Dwarf_Debug dbg, Dwarf_Die die) throw();

  DieHolder(Dwarf_Debug dbg, Dwarf_Off offset);

  ~DieHolder(void) throw();

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

  // warning: this is the real DIE name, not the one in idati!
  // these 2 names might be different if there was a conflict
  char const *get_name(void);

  Dwarf_Attribute get_attr(int attr);

  Dwarf_Off get_ref_from_attr(int attr);

  Dwarf_Unsigned get_member_offset(void);

  Dwarf_Signed get_attr_small_val(int attr);

  Dwarf_Unsigned get_bytesize(void);

  Dwarf_Off get_offset(void);

  Dwarf_Off get_CU_offset_range(Dwarf_Off *cu_length);

  Dwarf_Half get_tag(void);

  Dwarf_Die get_child(void);

  Dwarf_Die get_sibling(void);

  // DieCache wrappers

  bool in_cache();

  bool get_cache(die_cache *cache);

  bool get_cache_type(die_cache *cache);

  void cache_useless(void);

  void cache_type(ulong const ordinal, bool second_pass=false, ulong base_ordinal=0);

  bool get_ordinal(ulong *ordinal);

  typedef auto_ptr<DieHolder> Ptr;

private:
  Dwarf_Debug m_dbg;
  Dwarf_Die m_die;
  Dwarf_Off m_offset;
  char *m_name;
  typedef map<int, Dwarf_Attribute> MapAttrs;
  MapAttrs m_attrs;
  bool m_offset_used;

  // no copying or assignment
  DieHolder(DieHolder const &);
  DieHolder &operator=(DieHolder const &);

  // common member vars init for the constructors
  void init(Dwarf_Debug dbg, Dwarf_Die die);
};

#endif // IDADWARF_DIE_UTILS_HPP
