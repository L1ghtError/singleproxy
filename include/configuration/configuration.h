#ifndef _CONFIGURATION_H_
#define _CONFIGURATION_H_

#include <stdint.h>
#include <stddef.h>

#include "utils/status.h"

enum dns_filter_type { DNS_FT_IPV4 = 0, DNS_FT_IPV6 = 1, DNS_FT_ALL = 2 };
typedef enum dns_filter_type dns_filter_type_t;

enum dns_match_type { DNS_MT_CONTAINS = 0, DNS_MT_EXACT = 1 };
typedef enum dns_match_type dns_match_type_t;

enum dns_action_type { DNS_AT_NOTFOUND = 0, DNS_AT_REFUSE = 1, DNS_AT_REDIRECT = 2, DNS_AT_HANDLE = 2 };
typedef enum dns_action_type dns_action_type_t;

struct dns_filter_conf {
   dns_filter_type_t filter_type;
   dns_match_type_t match_type;
   dns_action_type_t action_type;
   uint8_t *host;
   uint8_t *redirect_addr;
};
typedef struct dns_filter_conf dns_filter_conf_t;
struct dns_server_conf {
   uint8_t *addr;
   uint16_t port;
};
typedef struct dns_server_conf dns_server_conf_t;

struct dns_conf {
   dns_filter_conf_t *filters;

   dns_server_conf_t self;
   dns_server_conf_t upstream;

   int filter_size;
};
typedef struct dns_conf dns_conf_t;

dns_conf_t *
new_dns_conf_from_json (const char *conf_filepath, dns_rc_t *rc);

void
destroy_dns_conf (dns_conf_t *dns_conf);

#endif // _CONFIGURATION_H_
