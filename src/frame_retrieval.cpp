#include "frame_retrieval.hpp"

// IDA headers
#include "frame.hpp"
#include "struct.hpp"
#include "area.hpp"

// local headers
#include "iterators.hpp"

// TODO: diecache!

// TODO: stack var with fpo-based functions
static void visit_frame_var(DieHolder &var_holder, Dwarf_Locdesc const *locdesc,
                            func_t *funptr, ea_t const cu_low_pc,
                            OffsetAreas const &offset_areas)
{
  char const *var_name = var_holder.get_name();
  char const *reg_name = NULL;

  // only 1 location in a location description is supported
  if(locdesc->ld_cents == 1)
  {
    Dwarf_Loc *loc = &locdesc->ld_s[0];

    // variable stored in a register?
    switch(loc->lr_atom)
    {
    case DW_OP_reg0:
      reg_name = "eax";
      break;
    case DW_OP_reg1:
      reg_name = "ecx";
      break;
    case DW_OP_reg2:
      reg_name = "edx";
      break;
    case DW_OP_reg3:
      reg_name = "ebx";
      break;
    case DW_OP_reg4:
      reg_name = "esp";
      break;
    case DW_OP_reg5:
      reg_name = "ebp";
      break;
    case DW_OP_reg6:
      reg_name = "esi";
      break;
    case DW_OP_reg7:
      reg_name = "edi";
      break;
    case DW_OP_reg8:
      reg_name = "eip";
      break;
    default:
      // perfectly correct behavior
      break;
    }

    if(reg_name != NULL)
    {
      if(locdesc->ld_from_loclist)
      {
        DEBUG("applied reg_name='%s'for var_name='%s'\n", reg_name, var_name);
        add_regvar(funptr, locdesc->ld_lopc + cu_low_pc, locdesc->ld_hipc + cu_low_pc,
                   reg_name, var_name, NULL);
      }
    }
    // stored in the stack frame?
    else
    {
      struc_t *fptr = get_frame(funptr);
      if(fptr != NULL)
      {
        // a stack frame variable has the current name?
        if(get_member_by_name(fptr, var_name) == NULL)
        {
          sval_t offset = 0;
          bool found = false;

          // ebp based location?
          if(loc->lr_atom == DW_OP_breg5)
          {
              offset = loc->lr_number;
              found = true;
          }
          // frame-base based location?
          else if(loc->lr_atom == DW_OP_fbreg && offset_areas.size() != 0)
          {
            // frame-base offset is from the subprogram
            if(!locdesc->ld_from_loclist)
            {
              offset = offset_areas[0].offset + loc->lr_number;
              DEBUG("found a stack frame var in a location block name='%s' offset=%ld\n", var_name, offset);
              found = true;
            }
            else
            {
              // frame-base offset is from the location list of the variable
              area_t area(locdesc->ld_lopc, locdesc->ld_hipc);
            
              for(size_t idx = 0; idx < offset_areas.size(); ++idx)
              {
                OffsetArea const &offset_area = offset_areas[idx];

                if(offset_area.contains(area))
                {
                  offset = offset_area.offset + loc->lr_number;
                  DEBUG("found a stack frame var in a location list name='%s' offset=%ld\n", var_name, offset);
                  found = true;
                  break;
                }
              }
            }
          }

          if(found)
          {
            // TODO: apply variable type too
            add_stkvar2(funptr, var_name, offset, 0, NULL, 0);
          }
        }
      }
    }
  }      
}

static void process_subprogram(DieHolder &subprogram_holder)
{
  Dwarf_Attribute attrib = subprogram_holder.get_attr(DW_AT_low_pc);

  // ignore potentially inlined functions for now
  if(attrib != NULL)
  {
    ea_t const low_pc = static_cast<ea_t>(subprogram_holder.get_addr_from_attr(
                                            DW_AT_low_pc));

    func_t *funptr = get_func(low_pc);

    if(funptr != NULL)
    {
#if 0
// TODO: esp-based heuristic
//    sval_t min_spd = get_spd(funptr, get_min_spd_ea(funptr));
//    char const *name = subprogram_holder.get_name();
//    MSG("name: '%s' min_spd=%d\n'", name, min_spd);
#endif
      DieHolder cu_holder(subprogram_holder.get_dbg(),
                          subprogram_holder.get_CU_offset());
      ea_t const cu_low_pc = static_cast<ea_t>(cu_holder.get_addr_from_attr(DW_AT_low_pc));
      OffsetAreas offset_areas;

      subprogram_holder.get_frame_pointer_offsets(offset_areas);

      for(DieChildIterator iter(subprogram_holder, DW_TAG_formal_parameter);
          *iter != NULL; ++iter)
      {
        DieHolder *param_holder = *iter;

        param_holder->retrieve_var(funptr, cu_low_pc, offset_areas,
                                   visit_frame_var);
      }

      // TODO: for lexical blocks too...

      for(DieChildIterator iter(subprogram_holder, DW_TAG_variable);
          *iter != NULL; ++iter)
      {
        DieHolder *var_holder = *iter;

        var_holder->retrieve_var(funptr, cu_low_pc, offset_areas,
                                 visit_frame_var);
      }
    }
  }
}

void visit_frame_die(DieHolder &die_holder)
{
  if(!die_holder.in_cache())
  {
    Dwarf_Half const tag = die_holder.get_tag();

    switch(tag)
    {
    case DW_TAG_subprogram:
      process_subprogram(die_holder);
      break;
    case DW_TAG_inlined_subroutine:
      // TODO
      break;
    default:
      break;
    }
  }
}

void retrieve_frames(Dwarf_Debug dbg, CUsHolder const &cus_holder)
{
  do_dies_traversal(dbg, cus_holder, try_visit_frame_die);
}
