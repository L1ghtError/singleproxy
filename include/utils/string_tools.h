#ifndef _STRING_TOOLS_H_
#define _STRING_TOOLS_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "status.h"
#include "ctype.h"
static inline int
str_i_cmp (const char *s1, const char *s2)
{
   while (*s1 && *s2) {
      int diff = tolower ((unsigned char) *s1) - tolower ((unsigned char) *s2);
      if (diff != 0) {
         return diff;
      }
      ++s1;
      ++s2;
   }
   return (unsigned char) *s1 - (unsigned char) *s2;
}

static inline char *
str_i_str (const char *haystack, const char *needle)
{
   if (!*needle) {
      return (char *) haystack;
   }

   for (; *haystack; haystack++) {
      const char *h = haystack;
      const char *n = needle;

      while (*n && (tolower (*h) == tolower (*n))) {
         h++;
         n++;
      }

      if (!*n) {
         return (char *) haystack;
      }
   }

   return NULL;
}

#endif // _STRING_TOOLS_H_