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

bool DieCache::get_offset(ulong const ordinal, Dwarf_Off *offset) throw()
{
  ssize_t const size = m_dies_node.supval(static_cast<sval_t>(ordinal), offset,
                                          sizeof(*offset), atag);

  return (size != -1);
}

bool DieCache::get_cache_by_ordinal(ulong const ordinal, die_cache *cache) throw()
{
  Dwarf_Off offset = 0;
  bool found = get_offset(ordinal, &offset);

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
    die_cache cache = { DIE_USELESS, 0, 0, false };

    m_dies_node.supset(static_cast<sval_t>(offset), &cache, sizeof(cache));
  }
}

void DieCache::cache_type(Dwarf_Off const offset, ulong const ordinal,
                          bool second_pass, ulong base_ordinal) throw()
{
  if(ordinal != 0 && ordinal != BADADDR)
  {
    die_cache cache;
    Dwarf_Off orig_offset = 0;
    bool ok = get_offset(ordinal, &orig_offset);

    // already a DIE with the same ordinal in cache?
    if(ok && orig_offset != offset)
    {
      ok = get_cache(orig_offset, &cache);
      if(ok)
      {
        nodeidx_t const offset_idx = static_cast<nodeidx_t>(offset);

        // set the same cache infos
        // but don't touch the ordinal -> offset mapping!
        m_dies_node.supset(offset_idx, &cache, sizeof(cache));
      }
    }
    else
    {
      // is there already an useless cache, overrride it
      if(get_cache(offset, &cache) && cache.type != DIE_USELESS)
      {
        DEBUG("do not do cache for ordinal %lu\n", ordinal);
      }
      else
      {
        nodeidx_t const offset_idx = static_cast<nodeidx_t>(offset);

        cache.type = DIE_TYPE;
        cache.ordinal = ordinal;
        cache.base_ordinal = base_ordinal;
        cache.second_pass = second_pass;

        m_dies_node.supset(offset_idx, &cache, sizeof(cache));
        m_dies_node.altset(static_cast<sval_t>(ordinal), offset_idx);
      }
    }
  }
}
