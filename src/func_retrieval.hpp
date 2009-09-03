#ifndef IDADWARF_FUNC_RETRIEVAL_HPP
#define IDADWARF_FUNC_RETRIEVAL_HPP

#include "die_utils.hpp"

void visit_func_die(DieHolder &die_holder);

TRY_VISIT_DIE(visit_func_die);

void retrieve_funcs(CUsHolder const &cus_holder);

#endif // IDADWARF_FUNC_RETRIEVAL_HPP
