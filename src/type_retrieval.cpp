#include "type_retrieval.hpp"

// IDA headers
#include <ida.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>
#include <enum.hpp>
#include <struct.hpp>

// local headers
#include "iterators.hpp"

extern DieCache diecache;

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
    // should only be used for debug purpose
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

  bool find(char const *name, uval_t const value)
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

// struct/union comparison
// we consider 2 structures equal if they have the same (processed) member
// names at the same offset
// we consider 2 unions equal if they have the same (processed) member names
// TODO: might be possible to do some member typechecking? (difficult)
class StrucCmp
{
public:
  StrucCmp(tid_t struc_id) throw():
    m_struc_id(struc_id), m_is_union(false)
  {
    // find a struct/union by its id
    // should only be used for debug purpose
    if(struc_id != BADNODE)
    {
      m_is_union = is_union(struc_id);

      add_all_members();
    }
  }

  StrucCmp(char const *struc_name) throw()
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

  virtual ~StrucCmp(void) throw()
  {
    while(!m_members.empty())
    {
      MapMembers::iterator iter = m_members.begin();
      char *str = const_cast<char *>(iter->first);

      m_members.erase(iter);
      qfree(str), str = NULL;
    }
  }

  tid_t get_struc_id(void) const throw()
  {
    return m_struc_id;
  }

  bool equal(DieHolder &structure_holder)
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

private:
  tid_t m_struc_id;
  bool m_is_union;
  // (unique) member name, member offset (0 for unions)
  typedef map<char const *, ea_t, less_strcmp> MapMembers;
  MapMembers m_members;

  void add_all_members(void) throw()
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

  void try_erase(char const *name, ea_t const offset)
  {
    MapMembers::iterator iter = m_members.find(name);

    if(iter != m_members.end() && iter->second == offset)
    {
      char *str = const_cast<char *>(iter->first);

      m_members.erase(iter);
      qfree(str), str = NULL;
    }
  }
};


// add an enum even if its name already exists
static enum_t add_dup_enum(DieHolder &enumeration_holder,
                           char const *name, flags_t flag)
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
static tid_t add_dup_struc(DieHolder &structure_holder, char const *name)
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
      }
      else
      {
        struc_id = add_struc(BADADDR, new_name.c_str(), is_union);
      }
    }
  }

  return struc_id;
}

// type DIE processing begins here

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

static void process_enum(DieHolder &enumeration_holder)
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

    enum_id = add_dup_enum(enumeration_holder, name, get_enum_size(byte_size));
    DEBUG("added an enum name='%s' bytesize=%" DW_PR_DUu "\n", name, byte_size);

    for(DieChildIterator iter(enumeration_holder, DW_TAG_enumerator);
        *iter != NULL; ++iter)
    {
      DieHolder *child_holder = *iter;
      char const *child_name = NULL;
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

static void process_base_type(DieHolder &type_holder)
{
  // mandatory name for a base type
  char const *name = type_holder.get_name();
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
      msg("base type: unknown boolean size=%" DW_PR_DUu ", assuming size is model specific\n", byte_size);
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
      msg("unknown float byte size=%" DW_PR_DUu "\n", byte_size);
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
      msg("unknown byte size=%" DW_PR_DUu ", assuming natural int\n", byte_size);
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
      msg("got a char with bte size=%" DW_PR_DUu " (!= 1), assuming 1 anyway...\n", byte_size);
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

static bool add_unspecified_type(die_cache *cache)
{
  qtype type;
  ulong new_ordinal = 0;
  bool saved = false;

  type.append(BTF_VOID);
  saved = set_simple_die_type("void", type, &new_ordinal);
  if(saved)
  {
    DEBUG("added unspecified type ordinal=%lu\n", new_ordinal);
    cache->type = DIE_USELESS;
    cache->ordinal = new_ordinal;
    cache->base_ordinal = 0;
    cache->second_pass = false;
  }
  else
  {
    MSG("cannot add unspecified type\n");
  }

  return saved;
}

static void process_unspecified(GCC_UNUSED DieHolder &unspecified_holder)
{
  die_cache cache;

  (void)add_unspecified_type(&cache);
}

static bool look_ref_type(DieHolder &modifier_holder, die_cache *cache)
{
  bool found = true;

  if(modifier_holder.get_attr(DW_AT_type) == NULL)
  {
    // add an unspecified type for modifiers without type attribute
    found = add_unspecified_type(cache);
  }
  else
  // need no find the original type?
  {
    Dwarf_Off offset = modifier_holder.get_ref_from_attr(DW_AT_type);
    DieHolder new_die(modifier_holder.get_dbg(), offset);

    // found die may not be in cache
    try_visit_type_die(new_die);
    found = new_die.get_cache_type(cache);
  }

  return found;
}

static void process_typed_modifier(DieHolder &modifier_holder, die_cache const *cache)
{
  type_t const *type = NULL;
  ulong const type_ordinal = cache->ordinal;
  ulong const base_ordinal = cache->base_ordinal;
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

    make_new_type(new_type, type, base_ordinal ?: type_ordinal);

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
        modifier_holder.cache_type(ordinal, false, base_ordinal ?: type_ordinal);
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

static void process_modifier(DieHolder &modifier_holder)
{
  die_cache cache;
  bool ok = look_ref_type(modifier_holder, &cache);

  if(ok)
  {
    process_typed_modifier(modifier_holder, &cache);
  }
}

static void process_typed_typedef(DieHolder &typedef_holder, ulong const type_ordinal)
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
      // there is no NTF_NOBASE support in rename_named_type
      // I need to do everything my way...
      type_t const *type = NULL;
      // there should be no complex types with an anonymous name
      // so, we can simply get the type here, not the fields
      ok = get_numbered_type(idati, type_ordinal, &type);
      if(ok)
      {
        qtype new_type(type);

        ok = del_numbered_type(idati, type_ordinal);
        if(ok)
        {
          ordinal = type_ordinal;
          ok = set_simple_die_type(name, new_type, &ordinal);
          // make the deleted type refer to the typedef type
          if(ok && type_ordinal != ordinal)
          {
            set_type_alias(idati, type_ordinal, ordinal);
          }
        }
      }
    }
    else
    {
      qtype new_type;

      make_new_type(new_type, NULL, type_ordinal);
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

static void process_typedef(DieHolder &typedef_holder)
{
  die_cache cache;
  bool ok = look_ref_type(typedef_holder, &cache);

  if(ok)
  {
    process_typed_typedef(typedef_holder, cache.ordinal);
  }
}

// TODO: handle multimensional arrays
static void process_array(DieHolder &array_holder)
{
  Dwarf_Off offset = array_holder.get_ref_from_attr(DW_AT_type);
  DieHolder new_die(array_holder.get_dbg(), offset);
  die_cache cache;
  bool ok = false;

  // found die may not be in cache
  try_visit_type_die(new_die);
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
      qtype new_type;
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

static void add_structure_member(DieHolder *member_holder, struc_t *sptr,
                                 bool *second_pass)
{
  char const *member_name = member_holder->get_name();
  Dwarf_Off const offset = member_holder->get_ref_from_attr(DW_AT_type);
  DieHolder new_die(member_holder->get_dbg(), offset);
  ea_t moffset = sptr->is_union() ? 0 : static_cast<ea_t>(member_holder->get_member_offset());
  die_cache cache;
  bool ok = false;

  try_visit_type_die(new_die);
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

          // override type size (we get an error if we don't do that...)
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

// find if the struct/union being processed is the copy of another one
static tid_t get_other_structure(DieHolder &structure_holder, char const *name,
                          ulong *ordinal)
{
  tid_t struc_id = BADNODE;
  tid_t other_id = get_struc_id(name);
  struc_t *sptr = get_struc(other_id);

  if(sptr != NULL)
  {
    ulong const other_ordinal = static_cast<ulong>(sptr->ordinal);

    if(other_ordinal != 0 && other_ordinal != BADADDR)
    {
      Dwarf_Off const offset = structure_holder.get_offset();
      Dwarf_Off other_offset = 0;
      bool const ok = diecache.get_offset(other_ordinal, &other_offset);

      // not the same offsets => different structures
      if(ok && offset != other_offset)
      {
        StrucCmp struc_cmp(name);

        if(struc_cmp.equal(structure_holder))
        {
          *ordinal = other_ordinal;
        }
        else
        {
          // generate a new name for the struct/union
          struc_id = add_dup_struc(structure_holder, name);
        }
      }
    }
  }

  return struc_id;
}

// maybe add a new structure
// and find the declaration ordinal if existing
static tid_t decl_add_struc(char const *name, bool const is_union,
                     ulong *decl_ordinal)
{
  if(name != NULL)
  {
    ulong ordinal = 0;
    type_t const *type = NULL;
    bool const ok = get_named_type(idati, name, NTF_TYPE | NTF_NOBASE, &type,
                             NULL, NULL, NULL, NULL, &ordinal);
    if(ok && is_type_void(type[0]))
    {
      *decl_ordinal = ordinal;
    }
  }

  return add_struc(BADADDR, name, is_union);
}

// structure/union processing (no incomplete type)
static void process_complete_structure(DieHolder &structure_holder, char const *name,
                                ulong *ordinal, bool *second_pass)
{
  bool const is_union = structure_holder.get_tag() == DW_TAG_union_type;
  ulong decl_ordinal = 0;
  tid_t struc_id = decl_add_struc(name, is_union, &decl_ordinal);

  if(struc_id == BADNODE)
  {
    struc_id = get_other_structure(structure_holder, name, ordinal);
  }

  // handle only newly added struct/unions
  if(*ordinal == 0 && struc_id != BADNODE)
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
    else if(decl_ordinal != 0)
    {
      set_type_alias(idati, decl_ordinal, *ordinal);
    }
  }
}

// TODO: handle bitfields
static void process_structure(DieHolder &structure_holder)
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

static void add_subroutine_parameter(DieHolder *param_holder, qtype &params_type,
                              bool *second_pass)
{
  Dwarf_Off offset = param_holder->get_ref_from_attr(DW_AT_type);
  DieHolder new_die(param_holder->get_dbg(), offset);
  type_t const *type = NULL;
  qtype new_type;
  die_cache cache;
  bool ok = false;

  // found die may not be in cache
  try_visit_type_die(new_die);
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

  params_type.append(new_type);
}

static void add_subroutine_return(DieHolder &subroutine_holder, qtype &func_type,
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
    try_visit_type_die(new_die);
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

  func_type.append(new_type);
}

// TODO: handle ellipsis parameter
static void process_subroutine(DieHolder &subroutine_holder)
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
    func_type.append(params_type);
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

void visit_type_die(DieHolder &die_holder)
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

// find members we did not get when doing first pass
static void second_process_structure(DieHolder &structure_holder,
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
    member_t *mptr = get_member_by_name(sptr, member_name);

    // no member at this offset?
    if(mptr == NULL)
    {
      add_structure_member(member_holder, sptr, &third_pass);
    }
  }

  if(third_pass)
  {
    MSG("structure/union name='%s' ordinal=%lu needs a third pass\n", type_name, ordinal);
  }
}

// find return type/parameters we did not get when doing first pass
static void second_process_subroutine(DieHolder &subroutine_holder,
                                      ulong const ordinal)
{
  type_t const *type = NULL;
  p_list const *fields = NULL;
  char const *type_name = get_numbered_type_name(idati, ordinal);
  bool ok = false;

  ok = get_numbered_type(idati, ordinal, &type, &fields);
  if(type_name == NULL || !ok)
  {
    MSG("cannot get type from ordinal=%lu\n", ordinal);
    ok = false;
  }
  else
  {
    func_type_info_t info;
    int nb_args = build_funcarg_info(idati, type, fields, &info, 0);

    if(nb_args == -1)
    {
      MSG("cannot build function arg info ordinal=%lu\n", ordinal);
      ok = false;
    }
    else
    {
      qtype func_type;
      int idx = 0;
      bool third_pass = false;

      // rebuild the function type, hopefully with no unknown types
      func_type.append(info.basetype);
      func_type.append(info.cc);

      if(is_type_unknown(info.rettype[0]))
      {
        add_subroutine_return(subroutine_holder, func_type, &third_pass);
      }
      else
      {
        func_type.append(info.rettype);
      }

      if(nb_args != 0)
      {
        append_dt(&func_type, nb_args);
      }

      for(DieChildIterator iter(subroutine_holder, DW_TAG_formal_parameter);
          *iter != NULL; ++iter, ++idx)
      {
        qtype param_type;

        if(is_type_unknown(info[idx].type[0]))
        {
          add_subroutine_parameter(*iter, param_type, &third_pass);
        }
        else
        {
          param_type = info[idx].type;
        }

        func_type.append(param_type);
      }

      if(third_pass)
      {
        MSG("function ordinal=%lu needs a third pass\n", ordinal);
      }

      ok = set_numbered_type(idati, ordinal, NTF_REPLACE, type_name, func_type.c_str());
    }
  }

  if(!ok)
  {
    MSG("failed to do function second pass ordinal=%lu\n", ordinal);
  }
}

static void do_second_pass(Dwarf_Debug dbg)
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

// update a simple (i.e. not BT_COMPLEX) type in all members of all struct/unions
static void update_structure_member(Dwarf_Debug dbg, Dwarf_Half const tag,
                             qtype const &old_type, qtype const &new_type)
{
  for(CachedDieIterator struc_iter(dbg, tag);
      *struc_iter != NULL; ++struc_iter)
  {
    DieHolder *struc_holder = *struc_iter;
    ulong struc_ordinal = 0;
    bool ok = struc_holder->get_ordinal(&struc_ordinal);

    if(ok)
    {
      char const *type_name = get_numbered_type_name(idati, struc_ordinal);

      if(type_name != NULL)
      {
        tid_t struc_id = get_struc_id(type_name);
        struc_t *sptr = get_struc(struc_id);

        for(DieChildIterator child_iter(*struc_holder, DW_TAG_member);
            *child_iter != NULL; ++child_iter)
        {
          DieHolder *member_holder = *child_iter;
          char const *member_name = member_holder->get_name();
          member_t *mptr = get_member_by_name(sptr, member_name);

          // really a member with this name?
          if(mptr != NULL)
          {
            qtype member_type;

            ok = get_member_tinfo(mptr, &member_type, NULL);
            if(ok)
            {
              // if the member type is the old modified one
              if(typcmp(old_type.c_str(), member_type.c_str()) == 0)
              {
                set_member_tinfo(idati, sptr, mptr, 0, new_type.c_str(), NULL, 0);
                DEBUG("struct/union member changed name='%s' ordinal=%lu\n", member_name, struc_ordinal);
              }
            }
          }
        }
      }
    }
  }
}

// update pointers to function with (old) unknown return/parameters
static void update_ptr_types(Dwarf_Debug dbg)
{
  for(CacheIterator iter(DIE_TYPE); *iter != NULL; ++iter)
  {
    die_cache const *cache = *iter;
    type_t const *type = NULL;
    bool ok = get_numbered_type(idati, cache->ordinal, &type);

    if(ok && is_type_ptr(type[0]) && cache->base_ordinal != 0)
    {
      type_t const *func_type = NULL;
      ok = get_numbered_type(idati, cache->base_ordinal, &func_type);

      // function pointer?
      if(ok && is_type_func(func_type[0]))
      {
        die_cache func_cache;
        char const *type_name = get_numbered_type_name(idati, cache->ordinal);
        ok = diecache.get_cache_by_ordinal(cache->base_ordinal, &func_cache);

        // pointer to an "unknown" function?
        if(ok && type_name != NULL && func_cache.second_pass)
        {
          type_t const *base_type = get_ptrs_base_type(type);
          type_pair_t type_pair(base_type, func_type);
          type_pair_vec_t vector_pair;
          // backup used when old type is replaced
          qtype const old_type(type);
          qstring const old_name(type_name);
          qtype new_type(type);

          vector_pair.push_back(type_pair);
          replace_subtypes(new_type, vector_pair);

          ok = del_numbered_type(idati, cache->ordinal);
          if(ok)
          {
            // we replace a pointer type, so we only need the type_t, not the fields
            ok = set_numbered_type(idati, cache->ordinal, NTF_REPLACE, old_name.c_str(), new_type.c_str());
            if(ok)
            {
              DEBUG("pointer type changed ordinal=%lu\n", cache->ordinal);

              // propagate the new type in the aggregate types
              update_structure_member(dbg, DW_TAG_structure_type, old_type, new_type);
              update_structure_member(dbg, DW_TAG_union_type, old_type, new_type);
            }
          }
        }
      }
    }

    if(!ok)
    {
      Dwarf_Off offset = 0;

      MSG("failed to update pointer type ordinal=%lu\n", cache->ordinal);
      ok = diecache.get_offset(cache->ordinal, &offset);
      if(ok)
      {
        MSG("-> at offset=0x%" DW_PR_DUx "\n", offset);
      }
    }
  }
}

void retrieve_types(Dwarf_Debug dbg, CUsHolder const &cus_holder)
{
  do_dies_traversal(dbg, cus_holder, try_visit_type_die);
  do_second_pass(dbg);
  update_ptr_types(dbg);
  // TODO: add a 'remove duplicates' pass
}
