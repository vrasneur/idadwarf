#include "iterators.hpp"

extern DieCache diecache;

DieChildIterator::DieChildIterator(DieHolder &die_holder, Dwarf_Half const tag)
  : m_tag(tag)
{
  Dwarf_Debug dbg = die_holder.get_dbg();
  Dwarf_Die child_die = die_holder.get_child();

  set_current_child(dbg, child_die);
}

bool DieChildIterator::operator==(DieChildIterator const &other) const throw()
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

DieChildIterator &DieChildIterator::operator++(void)
{
  if(m_current_child.get() != NULL)
  {
    Dwarf_Debug dbg = m_current_child->get_dbg();
    Dwarf_Die sibling_die = m_current_child->get_sibling();

    set_current_child(dbg, sibling_die);
  }

  return *this;
}

void DieChildIterator::set_current_child(Dwarf_Debug dbg, Dwarf_Die child_die)
{
  while(child_die != NULL)
  {
    DieHolder::Ptr child_holder(new DieHolder(dbg, child_die));

    if(m_tag == 0 || child_holder->get_tag() == m_tag)
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

CachedDieIterator::CachedDieIterator(Dwarf_Debug dbg, Dwarf_Half tag)
  : m_dbg(dbg), m_tag(tag), m_current_idx(diecache.get_first_offset())
{
  set_current_die();
}

bool CachedDieIterator::operator==(CachedDieIterator const &other) const throw()
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

CachedDieIterator &CachedDieIterator::operator++(void)
{
  if(m_current_die.get() != NULL)
  {
    m_current_idx = diecache.get_next_offset(m_current_idx);

    set_current_die();
  }

  return *this;
}

void CachedDieIterator::set_current_die(void)
{
  m_current_die.reset((m_current_idx == BADNODE) ?
                      NULL : new DieHolder(m_dbg, static_cast<Dwarf_Off>(m_current_idx)));

  // not the right DIE tag?
  if(m_current_die.get() != NULL &&
     m_tag != 0 && m_current_die->get_tag() != m_tag)
  {
    // TODO: recursion -> iteration
    ++(*this);
  }
}

CacheIterator::CacheIterator(die_type type) throw()
  : m_die_type(type), m_current_idx(diecache.get_first_offset())
{
  set_current_cache();
}

CacheIterator &CacheIterator::operator++(void)
{
  if(m_current_idx != BADNODE)
  {
    m_current_idx = diecache.get_next_offset(m_current_idx);

    set_current_cache();
  }

  return *this;
}

void CacheIterator::set_current_cache(void) throw()
{
  if(m_current_idx != BADNODE)
  {
    ssize_t size = diecache.get_cache(static_cast<Dwarf_Off>(m_current_idx),
                                      &m_current_cache);

    // not found? (should not happen)
    if(size == -1)
    {
      m_current_idx = BADNODE;
    }
    // not the right cache type?
    else if(m_current_cache.type != m_die_type)
    {
      // try next die cache
      // TODO: recursion -> iteration
      ++(*this);
    }
  }
}
