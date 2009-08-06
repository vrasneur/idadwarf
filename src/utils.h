#ifndef IDADWARF_UTILS_H
#define IDADWARF_UTILS_H

#include <cstdlib>
#include <cerrno>

// number conversion

static inline int my_strtol(char const *str, long *nb, char **endptr)
{
   int ret = 0;
   long lnb = 0;

   if(str == NULL || *str == '\0' || nb == NULL)
   {
      ret = EINVAL;
   }
   else
   {
      errno = 0;
      lnb = strtol(str, endptr, 0);
      if(errno != 0)
      {
         ret = errno;
      }
      else if(endptr != NULL && (str == *endptr || *endptr == NULL))
      {
         ret = EINVAL;
      }
      else
      {
         *nb = lnb;
      }
   }

   return ret;
}

static inline int my_strict_strtol(char const *str, long *nb)
{
   char *endptr = NULL;

   int ret = my_strtol(str, nb, &endptr);
   // the string must be a full long integer, no garbage allowed after.
   if(ret == 0 && endptr != NULL && *endptr != '\0')
   {
      ret = EINVAL;
   }

   return ret;
}

#endif // IDADWARF_UTILS_H
