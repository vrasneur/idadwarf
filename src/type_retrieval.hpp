#ifndef IDADWARF_TYPE_RETRIEVAL_HPP
#define IDADWARF_TYPE_RETRIEVAL_HPP

#include "die_utils.hpp"

void try_visit_type_die(DieHolder &die);

void do_second_pass(Dwarf_Debug dbg);

void update_ptr_types(Dwarf_Debug dbg);

#endif // IDADWARF_TYPE_RETRIEVAL_HPP
