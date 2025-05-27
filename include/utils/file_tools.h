
#ifndef _FILE_TOOLS_H_
#define _FILE_TOOLS_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "status.h"

static inline size_t
get_filesize (FILE *file)
{
   if (file == NULL) {
      return -1;
   }

   fseek (file, 0, SEEK_END);
   int size = ftell (file);
   fseek (file, 0, SEEK_SET);
   return size;
}


static inline dns_rc_t
get_content (FILE *file, size_t filesize, char *content)
{
   if (file == NULL || content == NULL) {
      return kInvalidInput;
   }

   size_t read_size = fread (content, 1, filesize, file);
   if (read_size != filesize) {
      return kAborted;
   }
   return kOk;
}


#endif // _FILE_TOOLS_H_