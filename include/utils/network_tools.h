#ifndef _NETWORK_TOOLS_H_
#define _NETWORK_TOOLS_H_

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include "stddef.h"

static inline void *
get_in_addr (const struct sockaddr_storage *sa)
{
   if (sa != NULL) {
      if (sa->ss_family == AF_INET) {
         return &((struct sockaddr_in *) sa)->sin_addr;
      } else {
         return &((struct sockaddr_in6 *) sa)->sin6_addr;
      }
   }
   return NULL;
}

static inline void
get_sockaddr_ip (const struct sockaddr_storage *sa, char *s, int buflen)
{
   inet_ntop (sa->ss_family, get_in_addr (sa), s, buflen);
}

static inline int
get_address_ip_binary (const uint8_t *string_addr, uint8_t *binary, int *length)
{
   if (inet_pton (AF_INET, (const char *) string_addr, binary) == 1) {
      *length = 4;
      return 0;
   }

   if (inet_pton (AF_INET6, (const char *) string_addr, binary) == 1) {
      *length = 16;
      return 0;
   }

   return -1;
}

#endif // _NETWORK_TOOLS_H_