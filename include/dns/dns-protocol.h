#ifndef _DNS_PROTOCOL_
#define _DNS_PROTOCOL_
#include <stdint.h>

#define POINTER_MASK 0xC0 /* flag that indicated that name is pointer */
#define RR_NAME_MAX 255   /* max length for rr name */
#define QNAME_MAX_SEG_LEN 63
#define DNS_UDP_MAX_PACKLEN 512
#define DEFAULT_TTL 300 // 5 minutes

#define RCODE_NOERROR 0  /* no error */
#define RCODE_FORMERR 1  /* format error */
#define RCODE_SERVFAIL 2 /* server failure */
#define RCODE_NXDOMAIN 3 /* non existent domain */
#define RCODE_NOTIMP 4   /* not implemented */
#define RCODE_REFUSED 5  /* query refused */

#define QUERY 0 /* opcode */

#define C_IN 1     /* the arpa internet */
#define C_CHAOS 3  /* for chaos net (MIT) */
#define C_HESIOD 4 /* hesiod */
#define C_ANY 255  /* wildcard match */


#define T_A 1
#define T_NS 2
#define T_MD 3
#define T_MF 4
#define T_CNAME 5
#define T_SOA 6
#define T_MB 7
#define T_MG 8
#define T_MR 9
#define T_PTR 12
#define T_MINFO 14
#define T_MX 15
#define T_TXT 16
#define T_RP 17
#define T_AFSDB 18
#define T_RT 21
#define T_SIG 24
#define T_PX 26
#define T_AAAA 28
#define T_NXT 30
#define T_SRV 33
#define T_NAPTR 35
#define T_KX 36
#define T_DNAME 39
#define T_OPT 41
#define T_DS 43
#define T_RRSIG 46
#define T_NSEC 47
#define T_DNSKEY 48
#define T_NSEC3 50
#define T_TKEY 249
#define T_TSIG 250
#define T_AXFR 252
#define T_MAILB 253
#define T_ANY 255
#define T_CAA 257


#pragma pack(push, 1)
struct dns_header {
   uint16_t id;
   uint8_t hb3, hb4;
   uint16_t qdcount, ancount, nscount, arcount;
};
typedef struct dns_header dns_header_t;
#pragma pack(pop)
#define HB3_QR 0x80 /* Query */
#define HB3_OPCODE 0x78
#define HB3_AA 0x04 /* Authoritative Answer */
#define HB3_TC 0x02 /* TrunCated */
#define HB3_RD 0x01 /* Recursion Desired */

#define HB4_RA 0x80 /* Recursion Available */
#define HB4_AD 0x20 /* Authenticated Data */
#define HB4_CD 0x10 /* Checking Disabled */
#define HB4_RCODE 0x0f

#define OPCODE(x) (((x)->hb3 & HB3_OPCODE) >> 3)
#define SET_OPCODE(x, code) (x)->hb3 = ((x)->hb3 & ~HB3_OPCODE) | code

#define RCODE(x) ((x)->hb4 & HB4_RCODE)
#define SET_RCODE(x, code) (x)->hb4 = ((x)->hb4 & ~HB4_RCODE) | code

#define GETSHORT(s, cp)                                       \
   {                                                          \
      unsigned char *t_cp = (unsigned char *) (cp);           \
      (s) = ((uint16_t) t_cp[0] << 8) | ((uint16_t) t_cp[1]); \
      (cp) += 2;                                              \
   }

#define GETLONG(l, cp)                                                                                               \
   {                                                                                                                 \
      unsigned char *t_cp = (unsigned char *) (cp);                                                                  \
      (l) =                                                                                                          \
         ((uint32_t) t_cp[0] << 24) | ((uint32_t) t_cp[1] << 16) | ((uint32_t) t_cp[2] << 8) | ((uint32_t) t_cp[3]); \
      (cp) += 4;                                                                                                     \
   }

#define PUTSHORT(s, cp)                             \
   {                                                \
      uint16_t t_s = (uint16_t) (s);                \
      unsigned char *t_cp = (unsigned char *) (cp); \
      *t_cp++ = t_s >> 8;                           \
      *t_cp = t_s;                                  \
      (cp) += 2;                                    \
   }

#define PUTLONG(l, cp)                              \
   {                                                \
      uint32_t t_l = (uint32_t) (l);                \
      unsigned char *t_cp = (unsigned char *) (cp); \
      *t_cp++ = t_l >> 24;                          \
      *t_cp++ = t_l >> 16;                          \
      *t_cp++ = t_l >> 8;                           \
      *t_cp = t_l;                                  \
      (cp) += 4;                                    \
   }

#pragma pack(push, 1)
struct dns_qrr {
   uint8_t name[RR_NAME_MAX];
   uint16_t type;
   uint16_t class;
};
#pragma pack(pop)
typedef struct dns_qrr dns_qrr_t;

#pragma pack(push, 1)
struct dns_arr {
   uint8_t name[RR_NAME_MAX];
   uint16_t type;
   uint16_t class;
   uint32_t ttl;
   uint16_t rdlength;
   uint8_t *rdata;
};
#pragma pack(pop)
typedef struct dns_arr dns_arr_t;

#endif // _DNS_PROTOCOL_
