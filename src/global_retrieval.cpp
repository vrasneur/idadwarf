#include "global_retrieval.hpp"

// IDA headers
#include <lines.hpp>

// local headers
#include "type_utils.hpp"

void process_global_var(DieHolder &var_holder)
{
  if(var_holder.get_attr(DW_AT_location) != NULL)
  {
    Dwarf_Unsigned addr = 0;
    bool ok = var_holder.get_var_addr(&addr);

    if(ok)
    {
      ok = apply_die_type(var_holder, addr);
      if(ok)
      {
        Dwarf_Bool const is_global = var_holder.get_attr_flag(DW_AT_external);

        add_long_cmt(addr, true, "%s variable", is_global ? "global" : "static");
        DEBUG("added a %s variable name='%s' offset=0x%" DW_PR_DUx "\n",
              is_global ? "global" : "static", var_holder.get_name(), var_holder.get_offset());
        var_holder.cache_var(VAR_GLOBAL);
      }
    }

    if(!ok)
    {
      MSG("failed to add global/static variable name='%s' offset=0x%" DW_PR_DUx "\n",
          var_holder.get_name(), var_holder.get_offset());
      var_holder.cache_useless();
    }
  }
}

void visit_global_die(DieHolder &die_holder)
{
  if(!die_holder.in_cache())
  {
    Dwarf_Half const tag = die_holder.get_tag();

    switch(tag)
    {
    // all local/register variables have been processed
    // when retrieving functions
    case DW_TAG_variable:
      process_global_var(die_holder);
      break;
    default:
      break;
    }
  }
}

void retrieve_globals(CUsHolder const &cus_holder)
{
  do_dies_traversal(cus_holder, try_visit_global_die);
}
