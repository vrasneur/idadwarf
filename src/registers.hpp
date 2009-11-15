#ifndef IDADWARF_REGISTERS_HPP
#define IDADWARF_REGISTERS_HPP

#include <map>
#include <utility>

// additional libs headers
#include <dwarf.h>
#include <libdwarf.h>

using namespace std;

enum metapc_reg
{
  R_error = -1,
#define ITEM(nb, reg_op, reg_name) R_ ## reg_name = nb,
# include "items/metapc.itm"
#undef ITEM
};

class RegNames
{
public:
  RegNames(void) throw()
  {
    add_registers();
  }

  virtual ~RegNames(void) throw()
  {

  }

  char const *get_name(metapc_reg const nb);

  metapc_reg get_nb_from_atom(Dwarf_Small const atom);

  char const *get_name_from_atom(Dwarf_Small const atom);

private:
  typedef map<metapc_reg, char const *> MapNames;
  MapNames m_names;
  typedef map<Dwarf_Small, pair<metapc_reg, char const *> > MapAtomNames;
  MapAtomNames m_atom_names;

  void add_registers(void) throw();
};

#endif // IDADWARF_REGISTERS_HPP
