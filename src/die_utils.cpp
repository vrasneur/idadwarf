#include "die_utils.hpp"

extern DieCache diecache;

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

// DWARF utility funs

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

DieHolder::DieHolder(Dwarf_Debug dbg, Dwarf_Die die) throw()
{
  init(dbg, die);
}

DieHolder::DieHolder(Dwarf_Debug dbg, Dwarf_Off offset)
{
  Dwarf_Die die = NULL;
  Dwarf_Error err = NULL;

  CHECK_DWERR(dwarf_offdie(dbg, offset, &die, &err), err,
              "cannot retrieve DIE from offset 0x%" DW_PR_DUx, offset);

  init(dbg, die);
}

DieHolder::~DieHolder(void) throw()
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

char const *DieHolder::get_name(void)
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

Dwarf_Attribute DieHolder::get_attr(int attr)
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

Dwarf_Off DieHolder::get_ref_from_attr(int attr)
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

Dwarf_Unsigned DieHolder::get_member_offset(void)
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

Dwarf_Signed DieHolder::get_attr_small_val(int attr)
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

Dwarf_Unsigned DieHolder::get_bytesize(void)
{
  Dwarf_Unsigned bytesize = 0;
  Dwarf_Error err = NULL;

  CHECK_DWERR(dwarf_bytesize(m_die, &bytesize, &err), err,
              "cannot get DIE byte size");

  return bytesize;
}

Dwarf_Off DieHolder::get_offset(void)
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

Dwarf_Off DieHolder::get_CU_offset_range(Dwarf_Off *cu_length)
{
  Dwarf_Off cu_offset = 0;
  Dwarf_Error err = NULL;

  CHECK_DWERR(dwarf_die_CU_offset_range(m_die, &cu_offset, cu_length, &err), err,
              "cannot get DIE CU offset range");

  return cu_offset;
}

Dwarf_Half DieHolder::get_tag(void)
{
  Dwarf_Half tag = 0;
  Dwarf_Error err = NULL;

  CHECK_DWERR(dwarf_tag(m_die, &tag, &err), err,
              "cannot get DIE tag");

  return tag;
}


Dwarf_Die DieHolder::get_child(void)
{
  Dwarf_Die child_die = NULL;
  Dwarf_Error err = NULL;

  // there may be no child
  CHECK_DWERR2(dwarf_child(m_die, &child_die, &err) == DW_DLV_ERROR, err,
               "error when asking for a DIE child");

  return child_die;
}

Dwarf_Die DieHolder::get_sibling(void)
{
  Dwarf_Die sibling_die = NULL;
  Dwarf_Error err = NULL;

  // there may be no sibling
  CHECK_DWERR2(dwarf_siblingof(m_dbg, m_die, &sibling_die, &err) == DW_DLV_ERROR, err,
               "error when asking for a DIE sibling");

  return sibling_die;
}

bool DieHolder::in_cache()
{
  return diecache.in_cache(get_offset());
}

bool DieHolder::get_cache(die_cache *cache)
{
  return diecache.get_cache(get_offset(), cache);
}

bool DieHolder::get_cache_type(die_cache *cache)
{
  return diecache.get_cache_type(get_offset(), cache);
}

void DieHolder::cache_useless(void)
{
  diecache.cache_useless(get_offset());
}

void DieHolder::cache_type(ulong const ordinal, bool second_pass, ulong base_ordinal)
{
  diecache.cache_type(get_offset(), ordinal, second_pass, base_ordinal);
}

bool DieHolder::get_ordinal(ulong *ordinal)
{
  die_cache cache;
  bool const found = get_cache_type(&cache);

  if(found)
  {
    *ordinal = cache.ordinal;
  }

  return found;
}

void DieHolder::init(Dwarf_Debug dbg, Dwarf_Die die)
{
  m_dbg = dbg;
  m_die = die;
  m_offset = 0;
  m_name = NULL;
  m_offset_used = false;
}
