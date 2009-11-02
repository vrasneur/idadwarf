#include "func_retrieval.hpp"

// IDA headers
#include <frame.hpp>
#include <struct.hpp>
#include <area.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <xref.hpp>
#include <lines.hpp>
#include <ua.hpp>
#include <segment.hpp>

// local headers
#include "iterators.hpp"
#include "ida_utils.hpp"
#include "type_utils.hpp"
#include "registers.hpp"

RegNames regnames;

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
  case DW_OP_breg4: // esp based
  case DW_OP_breg5: // ebp based
  case DW_OP_fbreg: // frame base (depends...)
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

// transform operand [var+offset] into [var+struct.member] if var is a pointer to a struct/union
static void set_register_var_strpath(ea_t const current_addr, char const *reg_name,
                                     struc_t *sptr)
{
  for(int nb_op = 0; nb_op < UA_MAXOP; ++nb_op)
  {
    op_t const &op = cmd.Operands[nb_op];
    // no more operands for this instruction?
    if(op.type == o_void)
    {
      break;
    }

    uval_t reg_offset = BADADDR;
    switch(op.type)
    {
    case o_displ:
      reg_offset = op.addr;
      break;
    case o_phrase:
      reg_offset = 0;
      break;
    default:
      break;
    }

    if(reg_offset != BADADDR)
    {
      member_t *mptr = NULL;
      // same register?
      char const *name = regnames.get_name(static_cast<metapc_reg>(op.reg));
      if(name == NULL || strcmp(name, reg_name) != 0)
      {
        continue;
      }

      mptr = get_best_fit_member(sptr, reg_offset);
      if(mptr != NULL)
      {
        tid_t path[2] = { sptr->id, mptr->id };

        op_stroff(current_addr, nb_op, path, 2, 0);
        DEBUG("applied struct member reg_name='%s' at 0x%lx\n",
              reg_name, current_addr);
      }
    }
  }
}

// apply enum value to an operand
static void set_register_var_enum(ea_t const current_addr, char const *reg_name,
                                  enum_t enum_id)
{
#define NN_cmp 27
#define NN_mov 122
#define NN_test 210

  if(cmd.itype == NN_cmp || cmd.itype == NN_mov || cmd.itype == NN_test)
  {
    bool found = false;

    for(int nb_op = 0; nb_op < UA_MAXOP; ++nb_op)
    {
      op_t const &op = cmd.Operands[nb_op];
      // no more operands for this instruction?
      if(op.type == o_void)
      {
        break;
      }

      if(op.type == o_reg)
      {
        // same register?
        char const *name = regnames.get_name(static_cast<metapc_reg>(op.reg));
        if(name != NULL && strcmp(name, reg_name) == 0)
        {
          found = true;
          break;
        }
      }
    }

    if(found)
    {
      for(int nb_op = 0; nb_op < UA_MAXOP; ++nb_op)
      {
        op_t const &op = cmd.Operands[nb_op];
        // no more operands for this instruction?
        if(op.type == o_void)
        {
          break;
        }

        if(op.type == o_imm)
        {
          op_enum(current_addr, nb_op, enum_id, 0);
          DEBUG("applied enum reg_name='%s' at 0x%lx\n",
                reg_name, current_addr);

        }
      }
    }
  }

#undef NN_test
#undef NN_mov
#undef NN_cmp
}

static void set_register_var_operand_type(DieHolder &var_holder, char const *reg_name,
                                          ea_t const startEA, ea_t const endEA)
{
  Dwarf_Off const offset = var_holder.get_ref_from_attr(DW_AT_type);
  ulong ordinal = 0;
  bool ok = diecache.get_cache_type_ordinal(offset, &ordinal);
  struc_t *sptr = NULL;
  enum_t enum_id = BADNODE;

  if(ok)
  {
    type_t const *type = NULL;

    ordinal = resolve_typedef_ordinal(ordinal) ?: ordinal;
    ok = get_numbered_type(idati, ordinal, &type);
    if(ok)
    {
      // handle enums
      if(is_type_enum(*type))
      {
        char const *name = get_numbered_type_name(idati, ordinal);

        enum_id = get_enum(name);
      }
      // handle pointers to structures/unions
      else if(is_type_ptr(*type))
      {
        ok = remove_type_pointer(idati, &type, NULL);
        if(ok && is_type_typedef(*type))
        {
          char const *name = resolve_typedef_name(type);

          if(name != NULL)
          {
            tid_t const struc_id = get_struc_id(name);

            if(struc_id != BADNODE)
            {
              sptr = get_struc(struc_id);
            }
          }
        }
      }
    }
  }

  if(sptr != NULL || enum_id != BADNODE)
  {
    ea_t current_addr = startEA;

    while(current_addr < endEA)
    {
      ua_ana0(current_addr);
      if(cmd.size == 0)
      {
        break;
      }

      if(sptr != NULL)
      {
        set_register_var_strpath(current_addr, reg_name, sptr);
      }
      else if(enum_id != BADNODE)
      {
        set_register_var_enum(current_addr, reg_name, enum_id);
      }

      current_addr += cmd.size;
    }
  }
}

static bool process_register_var(DieHolder &var_holder, Dwarf_Locdesc const *locdesc,
                                 func_t *funptr, ea_t const cu_low_pc)
{
  char const *var_name = var_holder.get_name();
  Dwarf_Loc const *loc = &locdesc->ld_s[0];
  char const *reg_name = regnames.get_name_from_atom(loc->lr_atom);
  bool ok = false;

  if(reg_name != NULL)
  {
    if(locdesc->ld_from_loclist)
    {
      char *comment = var_holder.get_type_comment();
      ea_t const startEA = locdesc->ld_lopc + cu_low_pc;
      ea_t const endEA = locdesc->ld_hipc + cu_low_pc;
      int const ret = add_regvar(funptr, startEA, endEA,
                                 reg_name, var_name, comment);

      if(comment != NULL)
      {
        qfree(comment), comment = NULL;
      }

      set_register_var_operand_type(var_holder, reg_name, startEA, endEA);

      ok = (ret == REGVAR_ERROR_OK);
      DEBUG("applied register name='%s'for variable name='%s'\n", reg_name, var_name);
    }
  }

  return ok;
}

static void set_stack_var_complex_type(struc_t *fptr, char const *var_name)
{
  member_t *mptr = get_member_by_name(fptr, var_name);

  if(mptr != NULL)
  {
    qtype guessed_type;
    qtype guessed_fields;

    // guess_func_tinfo fails if we don't use the guessed types
    // instead of the normal ones
    bool const ok = get_or_guess_member_tinfo(mptr, &guessed_type, &guessed_fields);
    if(ok)
    {
      set_member_tinfo(idati, fptr, mptr, 0, guessed_type.c_str(), guessed_fields.c_str(), 0);
    }
  }
}

static void set_stack_var_type_cmt(struc_t *fptr, char const *var_name)
{
  member_t *mptr = get_member_by_name(fptr, var_name);

  if(mptr != NULL)
  {
    qtype type;
    qtype fields;
    
    bool const ok = get_or_guess_member_tinfo(mptr, &type, &fields);

    if(ok)
    {
      // dynamic type string allocation does not work (returns T_SHORTSTR)
      // so allocate a huge buffer on the stack...
      char buf[MAXSTR];
      int const ret = print_type_to_one_line(buf, sizeof(buf), idati, type.c_str(), var_name,
                                       NULL, fields.c_str(), NULL);

      if(ret < 0)
      {
        MSG("cannot get the formatted type for stack variable name='%s' ret=%d\n",
            var_name, ret);
      }
      else
      {
        set_struc_cmt(mptr->id, buf, true);
      }
    }
  }
}

static bool set_stack_var(DieHolder &var_holder, func_t *funptr, sval_t const offset)
{
  char const *var_name = var_holder.get_name();
  struc_t *fptr = get_frame(funptr);
  bool type_found = false;
  ulong ordinal = 0;
  bool ok = false;

  if(!var_holder.get_type_ordinal(&ordinal))
  {
    MSG("cannot retrieve type offset for frame variable "
        "name='%s' offset=0x%" DW_PR_DUx "\n", 
        var_name, var_holder.get_offset());
  }
  else
  {
    typeinfo_t mt;
    type_t const *type = NULL;
    flags_t flags = fill_typeinfo(&mt, ordinal, &type);

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
          ok = add_stkvar2(funptr, var_name, offset, 0, &mt, size);
          if(ok)
          {
            set_stack_var_complex_type(fptr, var_name);
          }
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

        set_stack_var_type_cmt(fptr, var_name);
        DEBUG("found type for stack var name='%s' offset=0x%" DW_PR_DUx "\n",
              var_name, var_holder.get_offset());
        type_found = true;
      }
    }
  }

  // no type info found at all? only set the name
  if(!type_found)
  {
    ok = add_stkvar2(funptr, var_name, offset, 0, NULL, 0);
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
      ea_t const rel_addr = offset_areas.get_rel_addr();
      sval_t offset = 0;
      bool found = false;

      // ebp based location?
      if(loc->lr_atom == DW_OP_breg5)
      {
        offset = loc->lr_number;
        found = true;
      }
      // esp based location?
      else if(loc->lr_atom == DW_OP_breg4 && rel_addr != BADADDR)
      {
        offset = loc->lr_number + offset_areas.get_base();
        found = true;
      }
      // frame-base based location?
      else if(loc->lr_atom == DW_OP_fbreg && offset_areas.size() != 0)
      {
        area_t area(BADADDR, BADADDR);

        // frame-base offset can be retrieved with the location list of the variable?
        if(locdesc->ld_from_loclist)
        {
          area.startEA = locdesc->ld_lopc;
          area.endEA = locdesc->ld_hipc;
        }

        for(size_t idx = 0; idx < offset_areas.size(); ++idx)
        {
          OffsetArea const &offset_area = offset_areas[idx];

          if(!locdesc->ld_from_loclist)
          {
            // frame-base offset can be retrieved from the entire subprogram
            if(offset_area.use_fp ||
               (rel_addr != BADADDR && offset_area.startEA >= rel_addr))
            {
              area.startEA = offset_area.startEA;
              area.endEA = offset_area.endEA;
            }
          }

          // esp based, but area location is before the "base stack address"
          // we cannot do anything
          if(!offset_area.use_fp &&
             (rel_addr == BADADDR || area.startEA < rel_addr))
          {
            continue;
          }

          if(offset_area.contains(area))
          {
            offset = (offset_area.offset + loc->lr_number +
                      (offset_area.use_fp ? 0 : offset_areas.get_base()));
            DEBUG("found a stack frame var in a location list name='%s' offset=%ld\n", var_name, offset);
            found = true;
            break;
          }
        }
      }

      if(found)
      {
        // we got the variable offset in the stack
        // get its type and add it to the stack frame
        ok = set_stack_var(var_holder, funptr, offset);
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
    DEBUG("added a function static variable name='%s' offset=0x%" DW_PR_DUx "\n",
          var_holder.get_name(), var_holder.get_offset());
  }

  return ok;
}

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
  // correct return type
  qtype return_type;

  if(subprogram_holder.get_attr(DW_AT_type) == NULL)
  {
    // function has no return type (that is... returns void)
    return_type.append(BTF_VOID);
    ok = true;
  }
  else
  {
    ulong ordinal = 0;

    if(!subprogram_holder.get_type_ordinal(&ordinal))
    {
      MSG("cannot retrieve return type"
          " for function name='%s' offset=0x%" DW_PR_DUx "\n", 
          subprogram_holder.get_name(), subprogram_holder.get_offset());
    }
    else
    {
      type_t const *type = NULL;
      ok = get_numbered_type(idati, ordinal, &type);

      if(ok)
      {
        make_new_type(return_type, type, ordinal);
      }
    }
  }

  // correct return type has been filled?
  if(ok)
  {
    // old function type/fields
    qtype func_type;
    qtype func_fields;
    // function type with correct return type
    qtype new_type;
    int const ret = guess_func_tinfo(funptr, &func_type, &func_fields);

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

    if(funptr != NULL && funptr->startEA == low_pc)
    {
      DieHolder cu_holder(subprogram_holder.get_dbg(),
                          subprogram_holder.get_CU_offset());
      ea_t const cu_low_pc = static_cast<ea_t>(cu_holder.get_addr_from_attr(DW_AT_low_pc));
      OffsetAreas offset_areas;
      Dwarf_Bool const is_external = subprogram_holder.get_attr_flag(DW_AT_external);

      if(is_external)
      {
        funptr->flags &= ~FUNC_STATIC;
      }
      else
      {
        funptr->flags |= FUNC_STATIC;
      }

      // FPO-based function?
      if((funptr->flags & FUNC_FRAME) == 0)
      {
        ea_t const ea = get_min_spd_ea(funptr);

        if(ea != BADADDR)
        {
          // Heuristic: get the esp delta IDA uses as a base for all the stack vars
          sval_t const min_spd = get_spd(funptr, ea);

          offset_areas.set_stack_base(min_spd, ea - cu_low_pc);
        }
      }

      subprogram_holder.get_frame_base_offsets(offset_areas);

      process_func_vars(subprogram_holder, funptr, cu_low_pc, offset_areas);

      // set the function return type
      ok = add_subprogram_return(subprogram_holder, funptr);
      if(ok)
      {
        DEBUG("added function name='%s' offset=%lu\n",
              subprogram_holder.get_name(), funptr->startEA);
        subprogram_holder.cache_func(funptr->startEA);
      }
    }
  }

  if(!ok)
  {
    subprogram_holder.cache_useless();
  }
}

static void process_label(DieHolder &label_holder)
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

static void my_apply_callee_type(func_t *funptr, ea_t const call_addr)
{
  qtype func_type;
  qtype func_fields;
  qvector<uval_t> stack_offsets;
  func_type_info_t finfo;
  int const ret = guess_func_tinfo(funptr, &func_type, &func_fields);

  // get the stack offsets of the arguments
  if(ret != GUESS_FUNC_FAILED)
  {
    int const nb_args = build_funcarg_info(idati, func_type.c_str(),
                                           func_fields.c_str(), &finfo, 0);

    if(nb_args >= 1 &&
       get_cc(finfo.cc) == CM_CC_CDECL)
    {
      for(int idx = 0; idx < nb_args; ++idx)
      {
        // first argloc starts at 0, that's exactly what we need
        if(is_stack_argloc(finfo[idx].argloc))
        {
          stack_offsets.push_back(finfo[idx].argloc);
        }
      }
    }
  }

// only define the necessary instructions
// allins.hpp is too big...
#define NN_call 16
#define NN_mov 122

  // at least one arg to comment?
  if(stack_offsets.size() != 0)
  {
    ea_t addr = call_addr;
    size_t args_found = 0;

    DEBUG("finding args for call address=0x%lx\n", call_addr);

    do
    {
      ea_t const prev_addr = decode_prev_insn(addr);
      
      if(prev_addr == BADADDR || cmd.itype == NN_call)
      {
        break;
      }

      if(cmd.itype == NN_mov)
      {
        op_t const &first_op = cmd.Operands[0];
        uval_t stack_offset = BADADDR;

        switch(first_op.type)
        {
        case o_displ:
          stack_offset = first_op.addr;
          break;
        case o_phrase:
          stack_offset = 0;
          break;
        default:
          break;
        }

        if(stack_offset != BADADDR && first_op.reg == R_esp)
        {
          for(size_t idx = 0; idx < stack_offsets.size(); ++idx)
          {
            if(stack_offsets[idx] == stack_offset)
            {
              DEBUG("found arg count=%ld at address=0x%lx\n",
                    static_cast<unsigned long>(idx), prev_addr);
              set_cmt(prev_addr, finfo[idx].name.c_str(), false);
              args_found++;
              break;
            }
          }
        }
      }

      addr = prev_addr;
    }
    while(args_found != stack_offsets.size() || addr < funptr->startEA);

    DEBUG("found %ld args (total %ld)\n",
          static_cast<unsigned long>(args_found),
          static_cast<unsigned long>(stack_offsets.size()));
  }

#undef NN_mov
#undef NN_call
}

static void add_callee_types(void)
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
            apply_callee_type(xref.from, func_type.c_str(), func_fields.c_str());
            // do the same thing when "mov"ing them at [esp+offset]
            my_apply_callee_type(funptr, xref.from);
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
