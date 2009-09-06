#include "func_retrieval.hpp"

// IDA headers
#include <frame.hpp>
#include <struct.hpp>
#include <area.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <xref.hpp>
#include <lines.hpp>

// local headers
#include "iterators.hpp"
#include "ida_utils.hpp"
#include "type_utils.hpp"

extern DieCache diecache;

static var_type get_var_type(Dwarf_Small const atom)
{
  var_type type = VAR_USELESS;

  switch(atom)
  {
  case DW_OP_reg0:
  case DW_OP_reg1:
  case DW_OP_reg2:
  case DW_OP_reg3:
  case DW_OP_reg4:
  case DW_OP_reg5:
  case DW_OP_reg6:
  case DW_OP_reg7:
  case DW_OP_reg8:
    type = VAR_REGISTER;
    break;
  case DW_OP_breg5:
  case DW_OP_fbreg:
    type = VAR_STACK;
    break;
  case DW_OP_addr:
    type = VAR_FUNC_STATIC;
    break;
  default:
    break;
  }

  return type;
}

static bool process_register_var(DieHolder &var_holder, Dwarf_Locdesc const *locdesc,
                                 func_t *funptr, ea_t const cu_low_pc)
{
  char const *var_name = var_holder.get_name();
  char const *reg_name = NULL;
  Dwarf_Loc const *loc = &locdesc->ld_s[0];
  bool ok = false;

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
    MSG("unknown register atom=%u\n", loc->lr_atom);
    break;
  }

  if(reg_name != NULL)
  {
    if(locdesc->ld_from_loclist)
    {
      int const ret = add_regvar(funptr, locdesc->ld_lopc + cu_low_pc, locdesc->ld_hipc + cu_low_pc,
                                 reg_name, var_name, NULL);
      ok = (ret == REGVAR_ERROR_OK);
      DEBUG("applied reg_name='%s'for var_name='%s'\n", reg_name, var_name);
    }
  }

  return ok;
}

static bool process_stack_var(DieHolder &var_holder, Dwarf_Locdesc const *locdesc,
                              func_t *funptr, OffsetAreas const &offset_areas)
{
  char const *var_name = var_holder.get_name();
  Dwarf_Loc const *loc = &locdesc->ld_s[0];
  struc_t *fptr = get_frame(funptr);
  bool ok = false;

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
        // we got the variable offset in the stack
        // get its type now
        bool type_found = false;

        if(var_holder.get_attr(DW_AT_type) != NULL)
        {
          die_cache cache;
          Dwarf_Off const type_offset = var_holder.get_ref_from_attr(DW_AT_type);

          if(!diecache.get_cache_type(type_offset, &cache))
          {
            MSG("cannot retrieve type offset=0x%" DW_PR_DUx, type_offset);
            msg(" for frame variable name='%s' offset=0x%" DW_PR_DUx "\n", 
                var_name, var_holder.get_offset());
          }
          else
          {
            typeinfo_t mt;
            type_t const *type = NULL;
            flags_t flags = fill_typeinfo(&mt, cache.ordinal, &type);

            if(type != NULL)
            {
              // override type size for structs (we get an error if we don't do that...)
              size_t const size = (flags == struflag() ? get_struc_size(mt.tid) :
                                   get_type_size0(idati, type));

              if(size == BADSIZE)
              {
                MSG("cannot get size of stack frame var name='%s'\n", var_name);
              }
              else
              {
                if(flags != 0)
                {
                  ok = add_stkvar2(funptr, var_name, offset, flags, &mt, size);
                }
                else
                {
                  // not a struct/union nor an enum
                  ok = add_stkvar2(funptr, var_name, offset, flags, NULL, size);

                  if(ok)
                  {
                    member_t *mptr = get_member_by_name(fptr, var_name);
                    if(mptr != NULL)
                    {
                      ok = set_member_tinfo(idati, fptr, mptr, 0, type, NULL, 0);
                    }
                  }
                }

                type_found = true;
              }
            }
          }
        }

        // no type info found at all? only set the name
        if(!type_found)
        {
          ok = add_stkvar2(funptr, var_name, offset, 0, NULL, 0);
        }
      }
    }
  }

  return ok;
}                       

static bool process_func_static_var(DieHolder &var_holder, Dwarf_Locdesc const *locdesc)
{
  Dwarf_Loc const *loc = &locdesc->ld_s[0];
  ea_t const addr = static_cast<ea_t>(loc->lr_number);
  bool const ok = apply_die_type(var_holder, addr);

  if(!ok)
  {
    MSG("failed to add function static variable name='%s' offset=0x%" DW_PR_DUx "\n",
        var_holder.get_name(), var_holder.get_offset());
  }
  else
  {
    add_long_cmt(addr, true, "function static variable");
  }

  return ok;
}

// TODO: stack var with fpo-based functions
static void visit_func_var(DieHolder &var_holder, Dwarf_Locdesc const *locdesc,
                           func_t *funptr, ea_t const cu_low_pc,
                           OffsetAreas const &offset_areas)
{
  char const *var_name = var_holder.get_name();
  var_type type = VAR_USELESS;
  bool ok = false;

  // only 1 location in a location description is supported
  if(var_name != NULL && locdesc->ld_cents == 1)
  {
    Dwarf_Loc const *loc = &locdesc->ld_s[0];
    type = get_var_type(loc->lr_atom);

    switch(type)
    {
    case VAR_REGISTER:
      // variable stored in a register?
      ok = process_register_var(var_holder, locdesc, funptr, cu_low_pc);
      break;
    case VAR_STACK:
      // stored in the stack frame?
      ok = process_stack_var(var_holder, locdesc, funptr, offset_areas);
      break;
    case VAR_FUNC_STATIC:
      // static variable local to a function?
      ok = process_func_static_var(var_holder, locdesc);
      break;
    default:
      break;
    }
  }

  if(ok)
  {
    var_holder.cache_var(type, funptr->startEA);
  }
  else
  {
    var_holder.cache_useless();
  }
}

static void process_func_vars(DieHolder &locals_holder, func_t *funptr,
                               ea_t const cu_low_pc, OffsetAreas const &offset_areas)
{
  for(DieChildIterator iter(locals_holder, DW_TAG_formal_parameter);
      *iter != NULL; ++iter)
  {
    DieHolder *param_holder = *iter;

    param_holder->enable_abstract_origin();
    param_holder->retrieve_var(funptr, cu_low_pc, offset_areas,
                               visit_func_var);
  }

  for(DieChildIterator iter(locals_holder, DW_TAG_variable);
      *iter != NULL; ++iter)
  {
    DieHolder *var_holder = *iter;

    var_holder->enable_abstract_origin();
    var_holder->retrieve_var(funptr, cu_low_pc, offset_areas,
                             visit_func_var);
  }

  for(DieChildIterator iter(locals_holder, DW_TAG_inlined_subroutine);
      *iter != NULL; ++iter)
  {
    DieHolder *subroutine_holder = *iter;

    process_func_vars(*subroutine_holder, funptr, cu_low_pc, offset_areas);
  }

  for(DieChildIterator iter(locals_holder, DW_TAG_lexical_block);
      *iter != NULL; ++iter)
  {
    DieHolder *block_holder = *iter;

    process_func_vars(*block_holder, funptr, cu_low_pc, offset_areas);
  }
}

static bool add_subprogram_return(DieHolder &subprogram_holder, func_t *funptr)
{
  bool ok = false;

  if(subprogram_holder.get_attr(DW_AT_type) != NULL)
  {
    die_cache cache;
    Dwarf_Off const type_offset = subprogram_holder.get_ref_from_attr(DW_AT_type);

    if(!diecache.get_cache_type(type_offset, &cache))
    {
      MSG("cannot retrieve return type offset=0x%" DW_PR_DUx, type_offset);
      msg(" for function name='%s' offset=0x%" DW_PR_DUx "\n", 
          subprogram_holder.get_name(), subprogram_holder.get_offset());
    }
    else
    {
      type_t const *type = NULL;
      ok = get_numbered_type(idati, cache.ordinal, &type);
                
      if(ok)
      {
        // old function type/fields
        qtype func_type;
        qtype func_fields;
        // correct return type
        qtype return_type;
        // function type with correct return type
        qtype new_type;
        int ret = 0;

        make_new_type(return_type, type, cache.ordinal);
        ret = guess_func_tinfo(funptr, &func_type, &func_fields);
        ok = (ret != GUESS_FUNC_FAILED);

        if(ok)
        {
          ok = replace_func_return(new_type, return_type, func_type.c_str());
          if(!ok)
          {
            MSG("failed to set the return type for function name='%s'\n", subprogram_holder.get_name());
          }
          else
          {
            ok = apply_tinfo(idati, funptr->startEA, new_type.c_str(), func_fields.c_str(), 0);
          }
        }
      }
    }
  }

  return ok;
}

static void process_subprogram(DieHolder &subprogram_holder)
{
  Dwarf_Attribute attrib = subprogram_holder.get_attr(DW_AT_low_pc);
  bool ok = false;

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

      process_func_vars(subprogram_holder, funptr, cu_low_pc, offset_areas);

      // is it the function entry chunk?
      if(funptr->startEA == low_pc)
      {
        // we are really in the right function, set its return type
        ok = add_subprogram_return(subprogram_holder, funptr);
        if(ok)
        {
          DEBUG("added function name='%s' offset=%lu\n",
                subprogram_holder.get_name(), funptr->startEA);
          subprogram_holder.cache_func(funptr->startEA);
        }
      }
    }
  }

  if(!ok)
  {
    subprogram_holder.cache_useless();
  }
}

void process_label(DieHolder &label_holder)
{
  label_holder.enable_abstract_origin();

  char const *name = label_holder.get_name();
  Dwarf_Attribute attrib = label_holder.get_attr(DW_AT_low_pc);

  if(name != NULL && attrib != NULL)
  {
    ea_t const low_pc = static_cast<ea_t>(label_holder.get_addr_from_attr(DW_AT_low_pc));

    set_name(low_pc, name, SN_CHECK | SN_LOCAL);
    DEBUG("added a label name='%s' at offset=0x%lx\n", name, low_pc);
  }

  label_holder.cache_useless();
}

void visit_func_die(DieHolder &die_holder)
{
  if(!die_holder.in_cache())
  {
    Dwarf_Half const tag = die_holder.get_tag();

    switch(tag)
    {
    case DW_TAG_subprogram:
      process_subprogram(die_holder);
      break;
    case DW_TAG_label:
      process_label(die_holder);
      break;
    default:
      break;
    }
  }
}

void add_callee_types(void)
{
  for(CacheIterator iter(DIE_FUNC); *iter != NULL; ++iter)
  {
    die_cache const *cache = *iter;
    func_t *funptr = get_func(cache->startEA);

    if(funptr != NULL)
    {
      qtype func_type;
      qtype func_fields;
      int const ret = guess_func_tinfo(funptr, &func_type, &func_fields);

      if(ret != GUESS_FUNC_FAILED)
      {
        xrefblk_t xref;

        for(bool ok = xref.first_to(cache->startEA, XREF_ALL);
            ok; ok = xref.next_to())
        {
          if(xref.type == fl_CN || xref.type == fl_CF)
          {
            // appears to only work when "push"ing arguments to the stack
            // not when "mov"ing them at [esp+offset]
            apply_callee_type(xref.from, func_type.c_str(), func_fields.c_str());
            DEBUG("applied callee type at 0x%lx\n", xref.from);
          }
        }
      }
    }
  }
}

void retrieve_funcs(CUsHolder const &cus_holder)
{
  do_dies_traversal(cus_holder, try_visit_func_die);
  add_callee_types();
}
