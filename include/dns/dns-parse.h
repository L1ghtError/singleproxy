#ifndef _DNS_PARSE_
#define _DNS_PARSE_

#include "dns/dns-protocol.h"
#include "utils/status.h"

struct dns_h {
   dns_header_t header;
   dns_qrr_t *qrs;
   dns_arr_t *ancs;
};
typedef struct dns_h dns_h_t;

dns_h_t *
new_dns_h (const uint8_t *req, dns_rc_t *rc);

uint8_t *
new_dns_buffer (const dns_h_t *dns, dns_rc_t *rc, int *out_bufsize);

void
destroy_dns_h (dns_h_t *dnsh);

#endif //  _DNS_PARSE_