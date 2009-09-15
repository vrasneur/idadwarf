#ifndef IDADWARF_TYPE_UTILS_HPP
#define IDADWARF_TYPE_UTILS_HPP

// local definitions
#include "defs.hpp"

// IDA headers
#include <ida.hpp>
#include <typeinf.hpp>
#include <enum.hpp>
#include <struct.hpp>

// local headers
#include "die_utils.hpp"

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
  EnumCmp(enum_t enum_id) throw();

  EnumCmp(char const *enum_name) throw();

  EnumCmp(DieHolder &enumeration_holder);

  virtual ~EnumCmp(void) throw();

  enum_t get_enum_id(void) const throw()
  {
    return m_enum_id;
  }

  bool equal(DieHolder &enumeration_holder);

  typedef auto_ptr<EnumCmp> Ptr;

private:
  typedef map<char const *, uval_t, less_strcmp> MapConsts;
  MapConsts m_consts;
  enum_t m_enum_id; // can be BADNODE

  // no copying or assignment
  EnumCmp(EnumCmp const &);
  EnumCmp & operator= (EnumCmp const &);

  virtual int visit_const(const_t cid, uval_t value) throw();

  bool find(char const *name, uval_t const value);
};

// struct/union comparison
// we consider 2 structures equal if they have the same (processed) member
// names at the same offset
// we consider 2 unions equal if they have the same (processed) member names
// TODO: might be possible to do some member typechecking? (difficult)
class StrucCmp
{
public:
  StrucCmp(tid_t struc_id) throw();

  StrucCmp(char const *struc_name) throw();

  virtual ~StrucCmp(void) throw();

  tid_t get_struc_id(void) const throw()
  {
    return m_struc_id;
  }

  ulong get_ordinal(void) const throw()
  {
    struc_t *sptr = get_struc(m_struc_id);

    return (sptr == NULL) ? 0 : sptr->ordinal;
  }

  bool equal(DieHolder &structure_holder);

private:
  tid_t m_struc_id;
  bool m_is_union;
  // (unique) member name, member offset (0 for unions)
  typedef map<char const *, ea_t, less_strcmp> MapMembers;
  MapMembers m_members;

  void add_all_members(void) throw();

  void try_erase(char const *name, ea_t const offset);
};

enum_t add_dup_enum(DieHolder &enumeration_holder, char const *name,
                    flags_t flag);

tid_t add_dup_struc(DieHolder &structure_holder, char const *name,
                    ulong *ordinal);

bool apply_die_type(DieHolder &die_holder, ea_t const addr);

ulong get_equivalent_typedef_ordinal(DieHolder &typedef_holder, ulong const type_ordinal);

#endif // IDADWARF_TYPE_UTILS_HPP
