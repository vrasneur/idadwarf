#ifndef IDADWARF_FRAME_RETRIEVAL_HPP
#define IDADWARF_FRAME_RETRIEVAL_HPP

#include "die_utils.hpp"

void visit_frame_die(DieHolder &die_holder);

TRY_VISIT_DIE(visit_frame_die);

void retrieve_frames(Dwarf_Debug dbg, CUsHolder const &cus_holder);

#endif // IDADWARF_FRAME_RETRIEVAL_HPP
