#include "registers.hpp"

void RegNames::add_registers(void) throw()
{
#define ITEM(nb, reg_op, reg_name)                                      \
  do                                                                    \
  {                                                                     \
    m_names[static_cast<metapc_reg>(nb)] = #reg_name;                   \
    m_atom_names[reg_op] =                                              \
      make_pair(static_cast<metapc_reg>(nb), #reg_name);                \
  }                                                                     \
  while(0);
# include "items/metapc.itm"
#undef ITEM
}

char const *RegNames::get_name(metapc_reg const nb)
{
  char const *name = NULL;
  MapNames::const_iterator iter = m_names.find(nb);

  if(iter != m_names.end())
  {
    name = iter->second;
  }

  return name;
}

metapc_reg RegNames::get_nb_from_atom(Dwarf_Small const atom)
{
  metapc_reg nb = R_error;
  MapAtomNames::const_iterator iter = m_atom_names.find(atom);

  if(iter != m_atom_names.end())
  {
    nb = iter->second.first;
  }

  return nb;
}

char const *RegNames::get_name_from_atom(Dwarf_Small const atom)
{
  char const *name = NULL;
  MapAtomNames::const_iterator iter = m_atom_names.find(atom);

  if(iter != m_atom_names.end())
  {
    name = iter->second.second;
  }

  return name;
}
