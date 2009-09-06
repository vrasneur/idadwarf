#include "ida_utils.hpp"

// IDA headers
#include <struct.hpp>
#include <enum.hpp>

// misc IDA utility funs

type_t const *get_ptrs_base_type(type_t const *type)
{
  type_t const *base_type = type;

  if(base_type != NULL)
  {
    while(is_type_ptr(base_type[0]))
    {
      base_type = skip_ptr_type_header(base_type);
    }
  }

  return base_type;
}

void append_ordinal_name(qtype &type, ulong const ordinal)
{
  type.append('#');
  append_de(&type, ordinal);
}

void append_complex_type(qtype &new_type, qtype const *complex_type)
{
  char const *complex_name = NULL;

  complex_name = reinterpret_cast<char const *>(complex_type->c_str());
  append_name(&new_type, complex_name);
}

void append_complex_type(qtype &new_type, ulong const ordinal)
{
  qtype complex_type;
  char const *complex_name = NULL;

  append_ordinal_name(complex_type, ordinal);
  complex_name = reinterpret_cast<char const *>(complex_type.c_str());
  append_name(&new_type, complex_name);
}

void make_new_type(qtype &new_type, type_t const *type, ulong const ordinal)
{
  // without any type, make an 'ordinal' typedef
  if(type == NULL)
  {
    new_type.append(BTF_TYPEDEF);
    append_complex_type(new_type, ordinal);
  }
  else
  {
    type_t const type_header = type[0];
    char const *type_name = get_numbered_type_name(idati, ordinal);

    // an anonymous typedef or not a complex type?
    // simply copy the type
    if(!is_type_complex(type_header) ||
       (is_type_typedef(type_header) && type_name[0] == '\0'))
    {
      new_type = type;
    }
    else
    {
      new_type.append(type_header);
      if(!is_type_typedef(type_header))
      {
        append_dt(&new_type, 0);
      }

      append_complex_type(new_type, ordinal);
    }
  }
}

// simple == no fields or C++ class infos
// returns true => the same type with the same name already exists
bool find_simple_type(char const *name, qtype const &ida_type, ulong *ordinal,
                     bool *found)
{
  bool ret = false;

  // reset the found status
  *found = false;

  // don't look for an anonymous type in the database
  if(name != NULL)
  {
    type_t const *type = NULL;
    ulong existing_ordinal = 0;
    int ok = get_named_type(idati, name, NTF_TYPE | NTF_NOBASE, &type,
                               NULL, NULL, NULL, NULL, &existing_ordinal);

    // found an existing type with same name?
    if(ok != 0)
    {
      *found = true;

      // TODO: check if the found type is really simple
      // same name, same type_t?
      if(typcmp(type, ida_type.c_str()) == 0)
      {
        *ordinal = existing_ordinal;
        ret = true;
      }

    }
  }

  return ret;
}

// set the name and type for a (not struct/union or enum) DIE type
// if *ordinal is not 0, do a type replace
bool set_simple_die_type(char const *name, qtype const &ida_type, ulong *ordinal)
{
  ulong alloced_ordinal = 0;
  bool found = false;
  bool saved = find_simple_type(name, ida_type, &alloced_ordinal, &found);
  bool const replace = (*ordinal != 0);

  if(!saved)
  {
    qstring new_name(name);

    alloced_ordinal = *ordinal ?: alloc_type_ordinal(idati);

    while(!saved)
    {
      // if the name already exists in the db,
      // the old type name will get deleted (if we replace the type)
      // avoid that!
      if(!found)
      {
        saved = set_numbered_type(idati, alloced_ordinal,
                                  replace ? NTF_REPLACE : 0,
                                  new_name.c_str(), ida_type.c_str());
      }

      if(!saved)
      {
        // try an approx name to avoid collision
        new_name.append('_');
        // look if a type with same name exists for the new generated name
        saved = find_simple_type(new_name.c_str(), ida_type,
                                 &alloced_ordinal, &found);
      }
    }
  }

  if(saved)
  {
    *ordinal = alloced_ordinal;
  }

  return saved;
}

flags_t fill_typeinfo(typeinfo_t *mt, ulong const ordinal, type_t const **type)
{
  char const *type_name = get_numbered_type_name(idati, ordinal);
  bool const ok = get_numbered_type(idati, ordinal, type);
  flags_t flags = 0;
  
  if(type_name == NULL || !ok)
  {
    MSG("cannot get member type from ordinal=%lu\n", ordinal);
  }
  else
  {
    if(is_type_enum(**type))
    {
      enum_t const enum_id = getn_enum(ordinal);
      uval_t const serial = get_enum_idx(ordinal);

      mt->ec.tid = enum_id;
      mt->ec.serial = serial;
      flags = enumflag();
    }
    else if(is_type_struni(**type))
    {
      tid_t const mstruc_id = get_struc_id(type_name);

      mt->tid = mstruc_id;
      flags = struflag();
    }
  }

  return flags;
}

bool replace_func_return(qtype &new_type, qtype const &return_type, type_t const *func_type)
{
  type_t const *tmp_ptr = NULL;
  bool ret = false;

  new_type.append(*func_type); // append BT_FUNC
  func_type++;
  new_type.append(*func_type); // append calling convention and memory model
  func_type++;
  // TODO: not sure about that step
  tmp_ptr = skip_spoiled_info(func_type);
  // type not ending prematurely?
  if(tmp_ptr != NULL)
  {
    // need to append spoiled info?
    if(tmp_ptr != func_type)
    {
      new_type.append(func_type, static_cast<size_t>(tmp_ptr - func_type));
      func_type = tmp_ptr;
    }
    // append new return type
    new_type.append(return_type);
    // skip old return type
    tmp_ptr = skip_type(idati, func_type);
    if(tmp_ptr != NULL && *func_type != '\0')
    {
      // skip action has succeeded, append the old arguments
      new_type.append(func_type);
      ret = true;
    }
  }

  return ret;
}

bool apply_type_ordinal(ea_t const addr, ulong const ordinal)
{
  type_t const *type = NULL;
  bool ok = get_numbered_type(idati, ordinal, &type);

  if(ok)
  {
    // WORKAROUND: apply_tinfo crashes when applying
    // some complex types (even if fields are provided).
    // make a wrapper type for now.
    qtype new_type;

    make_new_type(new_type, type, ordinal);

    ok = apply_tinfo(idati, addr, new_type.c_str(), NULL, 0);
  }

  return ok;
}
