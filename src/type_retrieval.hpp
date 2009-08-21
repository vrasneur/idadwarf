#ifndef IDADWARF_TYPE_RETRIEVAL_HPP
#define IDADWARF_TYPE_RETRIEVAL_HPP

#include "die_utils.hpp"

void try_visit_type_die(DieHolder &die);

void retrieve_types(Dwarf_Debug dbg, CUsHolder const &cus_holder);

#endif // IDADWARF_TYPE_RETRIEVAL_HPP
