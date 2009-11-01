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

DieHolder::DieHolder(Dwarf_Debug dbg, Dwarf_Die die, bool const dealloc_die) throw()
{
  init(dbg, die, dealloc_die);
}

DieHolder::DieHolder(Dwarf_Debug dbg, Dwarf_Off offset, bool const dealloc_die)
{
  Dwarf_Die die = NULL;
  Dwarf_Error err = NULL;

  CHECK_DWERR(dwarf_offdie(dbg, offset, &die, &err), err,
              "cannot retrieve DIE from offset 0x%" DW_PR_DUx, offset);

  init(dbg, die, dealloc_die);
}

DieHolder::~DieHolder(void) throw()
{
  m_origin_holder.reset();

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

  if(m_dealloc_die)
  {
    dwarf_dealloc(m_dbg, m_die, DW_DLA_DIE);
  }

  m_die = NULL;
}

char const *DieHolder::get_name(void)
{
  char const *name = m_name;

  if(name == NULL)
  {
    Dwarf_Error err = NULL;

    // name may be NULL
    CHECK_DWERR2(dwarf_diename(m_die, &m_name, &err) == DW_DLV_ERROR, err,
                 "cannot get DIE name");

    if(m_name != NULL)
    {
      name = m_name;
    }
    else if(m_origin_holder.get() != NULL)
    {
      name = m_origin_holder->get_name();
    }
  }

  return name;
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

    if(attrib != NULL)
    {
      m_attrs[attr] = attrib;
    }
    else if(m_origin_holder.get() != NULL)
    {
      attrib = m_origin_holder->get_attr(attr);
    }
  }
  else
  {
    attrib = iter->second;
  }

  return attrib;
}

Dwarf_Signed DieHolder::get_nb_attrs(void)
{
  Dwarf_Attribute *attrlist = NULL;
  Dwarf_Signed nb_attrs = 0;
  Dwarf_Error err = NULL;

  CHECK_DWERR2(dwarf_attrlist(m_die, &attrlist, &nb_attrs, &err) == DW_DLV_ERROR, err,
               "error when getting the list of attributes");

  // do not use the attributes
  // TODO: maybe we can put them in the attributes map later...
  if(nb_attrs != 0)
  {
    for(Dwarf_Signed idx = 0; idx < nb_attrs; ++idx)
    {
      dwarf_dealloc(m_dbg, attrlist[idx], DW_DLA_ATTR);
    }

    dwarf_dealloc(m_dbg, attrlist, DW_DLA_LIST);
  }

  return nb_attrs;
}

Dwarf_Addr DieHolder::get_addr_from_attr(int attr)
{
  Dwarf_Addr addr = 0;
  Dwarf_Error err = NULL;
  Dwarf_Attribute attrib = get_attr(attr);

  CHECK_DWERR2(attrib == NULL, NULL, "cannot find DIE attribute %d\n", attr);
  CHECK_DWERR(dwarf_formaddr(attrib, &addr, &err), err,
              "cannot get address");

  return addr;
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

bool DieHolder::get_operand(int const attr, ea_t const rel_addr, Dwarf_Small const atom,
                            Dwarf_Unsigned *operand, bool only_locblock)
{
  Dwarf_Attribute attrib = get_attr(attr);
  Dwarf_Locdesc **llbuf = NULL;
  Dwarf_Locdesc *locdesc = NULL;
  Dwarf_Signed count = 0;
  Dwarf_Error err = NULL;
  DwarfDealloc dealloc(m_dbg);
  bool found = false;
  bool ret = false;

  CHECK_DWERR2(attrib == NULL, NULL,
               "retrieving an operand implies finding the attribute...");

  CHECK_DWERR(dwarf_loclist_n(attrib, &llbuf, &count, &err), err,
              "cannot get location descriptions");

  dealloc.add(llbuf, DW_DLA_LIST);
  for(Dwarf_Signed idx = 0; idx < count; ++idx)
  {
    locdesc = llbuf[idx];
    // handle deallocation too
    dealloc.add(llbuf[idx], DW_DLA_LOCDESC);
    dealloc.add(llbuf[idx]->ld_s, DW_DLA_LOC_BLOCK);

    if(!found)
    {
      // from a location block?
      if(!locdesc->ld_from_loclist)
      {
        // no need to check the address
        found = true;
      }
      // this loc desc is from a location list
      else if(!only_locblock &&
              (locdesc->ld_lopc <= rel_addr &&
               locdesc->ld_hipc > rel_addr))
      {
        found = true;
      }
    }
  }
  
  if(found)
  {
    CHECK_DWERR2(locdesc->ld_cents != 1, NULL,
                 "only 1 location in a location description is supported");

    Dwarf_Loc *loc = &locdesc->ld_s[0];

    if(loc->lr_atom == atom)
    {
      *operand = loc->lr_number;
      ret = true;
    }
  }

  return ret;
}

void DieHolder::get_frame_base_offsets(OffsetAreas &offset_areas)
{
  Dwarf_Attribute attrib = get_attr(DW_AT_frame_base);
  Dwarf_Locdesc **llbuf = NULL;
  Dwarf_Locdesc *locdesc = NULL;
  Dwarf_Signed count = 0;
  Dwarf_Error err = NULL;
  DwarfDealloc dealloc(m_dbg);

  CHECK_DWERR2(attrib == NULL, NULL,
               "retrieving an operand implies finding the attribute...");

  CHECK_DWERR(dwarf_loclist_n(attrib, &llbuf, &count, &err), err,
              "cannot get location descriptions");

  dealloc.add(llbuf, DW_DLA_LIST);
  for(Dwarf_Signed idx = 0; idx < count; ++idx)
  {
    ea_t low_pc = 0;
    ea_t high_pc = 0;

    locdesc = llbuf[idx];
    // handle deallocation too
    dealloc.add(llbuf[idx], DW_DLA_LOCDESC);
    dealloc.add(llbuf[idx]->ld_s, DW_DLA_LOC_BLOCK);

    // only 1 location in a location description is supported
    if(locdesc->ld_cents == 1)
    {
      Dwarf_Loc *loc = &locdesc->ld_s[0];

      // from a location block?
      if(!locdesc->ld_from_loclist)
      {
        low_pc = BADADDR;
        high_pc = BADADDR;
      }
      // this loc desc is from a location list
      else
      {
        low_pc = static_cast<ea_t>(locdesc->ld_lopc);
        high_pc = static_cast<ea_t>(locdesc->ld_hipc);
      }

      // is it the right atom to get the offset from?
      if(loc->lr_atom == offset_areas.get_atom())
      {
        offset_areas.push_back(OffsetArea(low_pc, high_pc,
                                          // operand is unsigned, but should be signed...
                                          static_cast<sval_t>(loc->lr_number)));
      }
    }
  }
}

void DieHolder::retrieve_var(func_t *funptr, ea_t const cu_low_pc,
                             OffsetAreas const &offset_areas, var_visitor_fun visit)
{
  Dwarf_Attribute attrib = get_attr(DW_AT_location);

  if(attrib != NULL)
  {
    Dwarf_Locdesc **llbuf = NULL;
    Dwarf_Locdesc *locdesc = NULL;
    Dwarf_Signed count = 0;
    Dwarf_Error err = NULL;
    DwarfDealloc dealloc(m_dbg);

    CHECK_DWERR(dwarf_loclist_n(attrib, &llbuf, &count, &err), err,
                "cannot get location descriptions");

    dealloc.add(llbuf, DW_DLA_LIST);
    for(Dwarf_Signed idx = 0; idx < count; ++idx)
    {
      locdesc = llbuf[idx];
      // handle deallocation too
      dealloc.add(llbuf[idx], DW_DLA_LOCDESC);
      dealloc.add(llbuf[idx]->ld_s, DW_DLA_LOC_BLOCK);

      visit(*this, locdesc, funptr, cu_low_pc, offset_areas);
    }
  }
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

Dwarf_Bool DieHolder::get_attr_flag(int attr)
{
  Dwarf_Attribute attrib = get_attr(attr);
  Dwarf_Bool flag = (attrib != NULL); 

  if(flag)
  {
    Dwarf_Error err = NULL;

    CHECK_DWERR(dwarf_formflag(attrib, &flag, &err), err,
                "cannot retrieve flag from attr %d", attr);
  }

  return flag;
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

Dwarf_Off DieHolder::get_CU_offset(void)
{
  Dwarf_Off cu_offset = 0;
  Dwarf_Error err = NULL;

  CHECK_DWERR(dwarf_CU_dieoffset_given_die(m_die, &cu_offset, &err), err,
              "cannot get CU DIE offset");

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

void DieHolder::enable_abstract_origin(void)
{
  if(m_origin_holder.get() == NULL)
  {
    Dwarf_Attribute attrib = get_attr(DW_AT_abstract_origin);

    if(attrib != NULL)
    {
      Dwarf_Off const offset = get_ref_from_attr(DW_AT_abstract_origin);

      m_origin_holder.reset(new DieHolder(m_dbg, offset));

      // if it is a useless DIE, disable the abstract origin DIE
      if(m_origin_holder.get() != NULL &&
         m_origin_holder->get_nb_attrs() == 1)
      {
        Dwarf_Die child_die = m_origin_holder->get_child();

        if(child_die == NULL)
        {
          m_origin_holder.reset();
        }
        else
        {
          dwarf_dealloc(m_dbg, child_die, DW_DLA_DIE);
        }
      }
    }
  }
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

void DieHolder::cache_func(ea_t const startEA)
{
  diecache.cache_func(get_offset(), startEA);
}

void DieHolder::cache_var(var_type const type, ea_t const func_startEA)
{
  diecache.cache_var(get_offset(), type, func_startEA);
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

bool DieHolder::get_type_ordinal(ulong *ordinal)
{
  bool found = false;

  if(get_attr(DW_AT_type) != NULL)
  {
    Dwarf_Off const type_offset = get_ref_from_attr(DW_AT_type);

    found = diecache.get_cache_type_ordinal(type_offset, ordinal);
  }

  return found;
}

char *DieHolder::get_type_comment(void)
{
  char *comment = NULL;
  ulong ordinal = 0;

  if(get_type_ordinal(&ordinal))
  {
    type_t const *type = NULL;
    p_list const *fields = NULL;
    bool const found = get_numbered_type(idati, ordinal, &type, &fields);

    if(found)
    {      
      // dynamic type string allocation does not work (returns T_SHORTSTR)
      // so allocate a huge buffer on the stack...
      char buf[MAXSTR];
      int const ret = print_type_to_one_line(buf, sizeof(buf), idati, type, get_name(),
                                             NULL, fields, NULL);
      if(ret >= 0);
      {
        size_t len = strlen(buf);
        comment = static_cast<char *>(qalloc(len + 1));

        if(comment != NULL)
        {
          memcpy(comment, buf, len + 1);
        }
      }
    }
  }

  return comment;
}

void DieHolder::init(Dwarf_Debug dbg, Dwarf_Die die, bool const dealloc_die)
{
  m_dbg = dbg;
  m_die = die;
  m_offset = 0;
  m_name = NULL;
  m_offset_used = false;
  m_dealloc_die = dealloc_die;
}

void CUsHolder::clean(void) throw()
{
  Dwarf_Error err = NULL;
  int ret = 0;

  for(size_t idx = 0; idx < size(); ++idx)
  {
    dwarf_dealloc(m_dbg, (*this)[idx], DW_DLA_DIE);
    (*this)[idx] = NULL;
  }

  ret = dwarf_finish(m_dbg, &err);
  if(ret != DW_DLV_OK)
  {
    MSG("libdwarf cleanup failed: %s\n", dwarf_errmsg(err));
  }

  clear();

  m_dbg = NULL;
  if(m_fd != -1)
  {
    close(m_fd), m_fd = -1;
  }
}

void do_dies_traversal(CUsHolder const &cus_holder,
                       die_visitor_fun visit)
{
  Dwarf_Debug dbg = cus_holder.get_dbg();
  qstack<Dwarf_Die> stack;

  for(size_t idx = 0; idx < cus_holder.size(); ++idx)
  {
    Dwarf_Die cu_die = cus_holder[idx];

    stack.push_back(cu_die);

    while(!stack.empty())
    {
      Dwarf_Die other_die = NULL;
      Dwarf_Die current_die = stack.back();
      DieHolder holder(dbg, current_die, current_die != cu_die);

      stack.pop_back();

      (*visit)(holder);

      try
      {
        other_die = holder.get_sibling();
        if(other_die != NULL)
        {
          stack.push_back(other_die);
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
          stack.push_back(other_die);
        }
      }
      catch(DieException const &exc)
      {
        MSG("cannot retrieve current DIE child (skipping): %s\n", exc.what());
      }
    }
  }
}
