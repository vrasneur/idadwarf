#include "die_cache.hpp"

bool DieCache::get_cache(Dwarf_Off const offset, die_cache *cache) throw()
{
  bool ret = false;
  ssize_t size = m_dies_node.supval(static_cast<sval_t>(offset), cache, sizeof(*cache));

  // found?
  if(size != -1)
  {
    ret = true;
  }

  return ret;
}

bool DieCache::get_cache_type(Dwarf_Off const offset, die_cache *cache) throw()
{
  bool ret = get_cache(offset, cache);

  if(ret && cache->type != DIE_TYPE)
  {
    DEBUG("tried to access type from ordinal=%lu, but it is not a type!\n", cache->ordinal);
    ret = false;
  }

  return ret;
}

bool DieCache::get_cache_type_ordinal(Dwarf_Off const offset, ulong *ordinal)
{
  die_cache cache;
  bool const ok = get_cache_type(offset, &cache);

  if(ok)
  {
    *ordinal = cache.ordinal;
  }

  return ok;
}

bool DieCache::get_offset(sval_t const reverse, die_type const type,
                          Dwarf_Off *offset) throw()
{
  ssize_t const size = m_dies_node.supval(reverse, offset, sizeof(*offset), type);

  return (size != -1);
}

bool DieCache::get_cache_by_ordinal(ulong const ordinal, die_cache *cache) throw()
{
  Dwarf_Off offset = 0;
  bool found = get_type_offset(ordinal, &offset);

  if(found)
  {
    found = get_cache(offset, cache);
  }

  return found;
}

void DieCache::cache_useless(Dwarf_Off const offset) throw()
{
  if(!in_cache(offset))
  {
    die_cache cache = { DIE_USELESS, { 0 } };

    m_dies_node.supset(static_cast<sval_t>(offset), &cache, sizeof(cache));
  }
}

void DieCache::cache_useful(Dwarf_Off const offset, sval_t const reverse,
                            die_cache const *cache) throw()
{
  die_cache existing_cache;
  Dwarf_Off orig_offset = 0;
  bool ok = get_offset(reverse, cache->type, &orig_offset);

  // already a DIE with the same reverse mapping in cache?
  if(ok && orig_offset != offset)
  {
    ok = get_cache(orig_offset, &existing_cache);
    if(ok)
    {
      nodeidx_t const offset_idx = static_cast<nodeidx_t>(offset);

      // set the same cache infos
      // but don't touch the existing reverse mapping!
      m_dies_node.supset(offset_idx, &existing_cache, sizeof(existing_cache));
    }
  }
  else
  {
    // is there already an useless cache, overrride it
    if(get_cache(offset, &existing_cache) &&
       existing_cache.type != DIE_USELESS)
    {
      // should not happen
      DEBUG("do not do cache for ordinal %lu\n", existing_cache.ordinal);
    }
    else
    {
      nodeidx_t const offset_idx = static_cast<nodeidx_t>(offset);

      m_dies_node.supset(offset_idx, cache, sizeof(*cache));
      m_dies_node.altset(reverse, offset_idx, cache->type);
    }
  }
}

void DieCache::cache_type(Dwarf_Off const offset, ulong const ordinal,
                          bool second_pass, ulong base_ordinal) throw()
{
  if(ordinal != 0 && ordinal != BADADDR)
  {
    die_cache cache;

    cache.type = DIE_TYPE;
    cache.ordinal = ordinal;
    cache.second_pass = second_pass;
    cache.base_ordinal = base_ordinal;

    cache_useful(offset, static_cast<sval_t>(ordinal), &cache);
  }
}

void DieCache::cache_func(Dwarf_Off const offset, ea_t const startEA) throw()
{
  if(startEA != BADADDR)
  {
    die_cache const cache = { DIE_FUNC, { startEA } };
  
    cache_useful(offset, static_cast<sval_t>(startEA), &cache);
  }
}

void DieCache::cache_var(Dwarf_Off const offset, var_type const type,
                         ea_t const func_startEA) throw()
{
  die_cache cache;

  cache.type = DIE_VAR;
  cache.vtype = type;
  cache.func_startEA = func_startEA;

  cache_useful(offset, static_cast<sval_t>(func_startEA), &cache);
}
