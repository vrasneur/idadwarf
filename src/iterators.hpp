#ifndef IDADWARF_ITERATORS_HPP
#define IDADWARF_ITERATORS_HPP

// standard headers
#include <iterator>
#include <memory>

// local headers
#include "die_cache.hpp"
#include "die_utils.hpp"
#include "gcc_defs.hpp"

using namespace std;

class DieChildIterator : public iterator<input_iterator_tag, DieHolder *>
{
public:
  DieChildIterator(DieHolder &die_holder, Dwarf_Half const tag=0);

  DieChildIterator(DieChildIterator &other) throw()
    : m_tag(other.m_tag), m_current_child(other.m_current_child)
  {

  }

  virtual ~DieChildIterator(void) throw()
  {
    m_current_child.reset();
  }

  bool operator==(DieChildIterator const &other) const throw();

  value_type operator*(void) const throw()
  {
    return m_current_child.get();
  }

  DieChildIterator &operator++(void);

  DieChildIterator operator++(GCC_UNUSED int dummy)
  {
    DieChildIterator iter(*this);

    ++iter;
    return iter;
  }

private:
  Dwarf_Half const m_tag;
  DieHolder::Ptr m_current_child;

  void set_current_child(Dwarf_Debug dbg, Dwarf_Die child_die);
};

class CachedDieIterator : public iterator<input_iterator_tag, DieHolder *>
{
public:
  // if tag is zero, get all the DIEs in cache
  // else, get all the DIEs with the specified tag
  CachedDieIterator(Dwarf_Debug dbg, Dwarf_Half tag=0);

  CachedDieIterator(CachedDieIterator &other) throw()
    : m_dbg(other.m_dbg), m_tag(other.m_tag),
      m_current_idx(other.m_current_idx), m_current_die(other.m_current_die)
  {

  }

  virtual ~CachedDieIterator(void) throw()
  {
    m_current_die.reset();
  }

  bool operator==(CachedDieIterator const &other) const throw();

  value_type operator*(void) const throw()
  {
    return m_current_die.get();
  }

  CachedDieIterator &operator++(void);

  CachedDieIterator operator++(GCC_UNUSED int dummy)
  {
    CachedDieIterator iter(*this);

    ++iter;
    return iter;
  }

private:
  Dwarf_Debug m_dbg;
  Dwarf_Half const m_tag;
  nodeidx_t m_current_idx;
  DieHolder::Ptr m_current_die;

  void set_current_die(void);
};

class CacheIterator : public iterator<input_iterator_tag, die_cache const *>
{
public:
  CacheIterator(die_type type) throw();

  virtual ~CacheIterator(void) throw()
  {

  }

  value_type operator*(void) const throw()
  {
    return (m_current_idx == BADNODE ? NULL : &m_current_cache);
  }

  CacheIterator &operator++(void);

  CacheIterator operator++(GCC_UNUSED int dummy)
  {
    CacheIterator iter(*this);

    ++iter;
    return iter;
  }

private:
  die_type const m_die_type;
  nodeidx_t m_current_idx;
  die_cache m_current_cache;

  void set_current_cache(void) throw();
};

#endif // IDADWARF_ITERATORS_HPP
