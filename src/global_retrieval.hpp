#ifndef IDADWARF_GLOBAL_RETRIEVAL_HPP
#define IDADWARF_GLOBAL_RETRIEVAL_HPP

#include "die_utils.hpp"

void visit_global_die(DieHolder &die_holder);

TRY_VISIT_DIE(visit_global_die);

void retrieve_globals(CUsHolder const &cus_holder);

#endif // IDADWARF_GLOBAL_RETRIEVAL_HPP
