#include "type_utils.hpp"

// local headers
#include "die_cache.hpp"
#include "ida_utils.hpp"
#include "iterators.hpp"

#define USE_DANGEROUS_FUNCTIONS

extern DieCache diecache;

EnumCmp::EnumCmp(enum_t enum_id) throw()
  : m_enum_id(enum_id)
{
  // find the enum by its id
  // should only be used for debug purpose
  if(m_enum_id != BADNODE)
  {
    for_all_consts(m_enum_id, *this);
  }
}

EnumCmp::EnumCmp(char const *enum_name) throw()
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

EnumCmp::EnumCmp(DieHolder &enumeration_holder)
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

EnumCmp::~EnumCmp(void) throw()
{
  while(!m_consts.empty())
  {
    MapConsts::iterator iter = m_consts.begin();
    char *str = const_cast<char *>(iter->first);

    m_consts.erase(iter);
    qfree(str), str = NULL;
  }
}

bool EnumCmp::equal(DieHolder &enumeration_holder)
{
  bool ret = false;

  if(m_enum_id != BADNODE)
  {
    for(DieChildIterator iter(enumeration_holder, DW_TAG_enumerator);
        *iter != NULL; ++iter)
    {
      DieHolder *child_holder = *iter;
      char const *child_name = NULL;
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

int EnumCmp::visit_const(const_t cid, uval_t value) throw()
{
  int ret = 1;
  // '\0' character is included in len
  ssize_t len = get_const_name(cid, NULL, 0);

  if(len != -1)
  {
    char *buf = static_cast<char *>(qalloc(len));
    if(buf != NULL)
    {
      (void)get_const_name(cid, buf, len);
      m_consts[buf] = value;
      ret = 0;
    }
  }

  return ret;
}

bool EnumCmp::find(char const *name, uval_t const value)
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

StrucCmp::StrucCmp(tid_t struc_id) throw()
  : m_struc_id(struc_id), m_is_union(false)
{
  // find a struct/union by its id
  // should only be used for debug purpose
  if(struc_id != BADNODE)
  {
    m_is_union = is_union(struc_id);

    add_all_members();
  }
}

StrucCmp::StrucCmp(char const *struc_name) throw()
  : m_struc_id(BADNODE), m_is_union(false)
{
  // find a struct/union by its (non null) name
  if(struc_name != NULL)
  {
    m_struc_id = ::get_struc_id(struc_name);

    if(m_struc_id != BADNODE)
    {
      m_is_union = is_union(m_struc_id);

      add_all_members();
    }
  }
}

StrucCmp::~StrucCmp(void) throw()
{
  while(!m_members.empty())
  {
    MapMembers::iterator iter = m_members.begin();
    char *str = const_cast<char *>(iter->first);

    m_members.erase(iter);
    qfree(str), str = NULL;
  }
}

bool StrucCmp::equal(DieHolder &structure_holder)
{
  bool const is_union = structure_holder.get_tag() == DW_TAG_union_type;
  bool ret = false;

  if(!m_members.empty() &&
     m_is_union == is_union &&
     m_struc_id != BADNODE)
  {
    for(DieChildIterator iter(structure_holder, DW_TAG_member);
        *iter != NULL; ++iter)
    {
      DieHolder *member_holder =  *iter;
      char const *member_name = member_holder->get_name();
      ea_t moffset = m_is_union ? 0 : static_cast<ea_t>(member_holder->get_member_offset());

      // continue even if the name is not erased
      try_erase(member_name, moffset);
    }

    ret = m_members.empty();
  }

  return ret;
}

void StrucCmp::add_all_members(void) throw()
{
  if(m_struc_id != BADNODE)
  {
    struc_t *sptr = get_struc(m_struc_id);
    ssize_t const struc_len = get_struc_name(m_struc_id, NULL, 0);

    for(size_t idx = 0; idx < sptr->memqty; ++idx)
    {
      member_t *mptr = &(sptr->members[idx]);

      // get_member_name crashes when given a NULL pointer...
      // we need to get the "struct.field" name and
      // substract the "struct." part
      // len is without the '\0' character
      ssize_t len = get_member_fullname(mptr->id, NULL, 0);

      if(len != -1)
      {
        len -= struc_len;

        char *buf = static_cast<char *>(qalloc(len));
        if(buf != NULL)
        {
          (void)get_member_name(mptr->id, buf, len);
          m_members[buf] = m_is_union ? 0 : mptr->soff;
        }
      }
    }
  }
}

void StrucCmp::try_erase(char const *name, ea_t const offset)
{
  MapMembers::iterator iter = m_members.find(name);

  if(iter != m_members.end() && iter->second == offset)
  {
    char *str = const_cast<char *>(iter->first);

    m_members.erase(iter);
    qfree(str), str = NULL;
  }
}

// add an enum even if its name already exists
enum_t add_dup_enum(DieHolder &enumeration_holder, char const *name,
                    flags_t flag)
{
  enum_t enum_id = add_enum(BADADDR, name, flag);

  // failed to add?
  if(enum_id == BADNODE)
  {
    qstring new_name(name);

    while(enum_id == BADNODE)
    {
      new_name.append('_');
      EnumCmp enum_cmp(new_name.c_str());

      // check if there is an existing equal enum
      // with the same new name
      if(enum_cmp.equal(enumeration_holder))
      {
        enum_id = enum_cmp.get_enum_id();
      }
      else
      {
        enum_id = add_enum(BADADDR, new_name.c_str(), flag);
      }
    }
  }

  return enum_id;
}

// add a struct/union even if its name already exists
tid_t add_dup_struc(DieHolder &structure_holder, char const *name,
                    ulong *ordinal)
{
  bool const is_union = structure_holder.get_tag() == DW_TAG_union_type;
  tid_t struc_id = add_struc(BADADDR, name, is_union);

  // failed to add?
  if(struc_id == BADNODE)
  {
    qstring new_name(name);

    while(struc_id == BADNODE)
    {
      new_name.append('_');
      StrucCmp struc_cmp(new_name.c_str());

      // check if there is an existing equal struct/union
      // with the same new name
      if(struc_cmp.equal(structure_holder))
      {
        struc_id = struc_cmp.get_struc_id();
        *ordinal = struc_cmp.get_ordinal();
      }
      else
      {
        struc_id = add_struc(BADADDR, new_name.c_str(), is_union);
      }
    }
  }

  return struc_id;
}

bool apply_die_type(DieHolder &die_holder, ea_t const addr)
{
  bool ok = false;

  if(die_holder.get_attr(DW_AT_type) != NULL)
  {
    die_cache cache;
    Dwarf_Off const type_offset = die_holder.get_ref_from_attr(DW_AT_type);

    if(!diecache.get_cache_type(type_offset, &cache))
    {
      MSG("cannot retrieve type offset=0x%" DW_PR_DUx, type_offset);
      msg(" for DIE at offset=0x%" DW_PR_DUx "\n", 
          die_holder.get_offset());
    }
    else
    {
      ok = apply_type_ordinal(addr, cache.ordinal);
    }
  }

  return ok;
}
