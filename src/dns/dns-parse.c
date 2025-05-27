#include "stdlib.h"
#include "string.h"
#include <netinet/in.h>
#include <stdio.h>

#include "dns/dns-parse.h"
#include "dns/dns-protocol.h"
#include "utils/network_tools.h"
int
process_qname (uint8_t *dst, const uint8_t *src, int length)
{
   int segment_length = *src;
   if (segment_length == 0 || dst == NULL || src == NULL) {
      return -1;
   }
   uint8_t *d = dst;
   const uint8_t *c = NULL;
   for (c = src + 1; *c != 0 || (c - src) >= length; ++c) {
      if (segment_length > 0) {
         if ((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') || (*c == '-')) {
            *d = *c;
            ++d;
         } else {
            return -1;
         }
         --segment_length;
      } else if (segment_length == 0) {
         segment_length = *c;
         *d = '.';
         ++d;
      }
   }
   if (d - dst < length) {
      *d = 0;
   }
   int orig_size = (c + 1) - src;
   return orig_size;
}

int
convert_to_qname (uint8_t *dst, const char *src, int max_length)
{
   if (dst == NULL || src == NULL) {
      return -1;
   }

   int src_len = strlen (src);
   if (src_len + 2 > max_length) { // +2 for the label lengths and the final 0 byte
      return -1;
   }

   uint8_t *d = dst;
   const char *start = src;
   const char *dot = strchr (start, '.');

   while (dot != NULL) {
      int segment_length = dot - start;
      if (segment_length > QNAME_MAX_SEG_LEN) {
         return -1;
      }

      *d++ = (uint8_t) segment_length;
      memcpy (d, start, segment_length);
      d += segment_length;

      start = dot + 1;
      dot = strchr (start, '.');
   }

   // Handle the last segment (after the last dot)
   int segment_length = strlen (start);
   if (segment_length > QNAME_MAX_SEG_LEN) {
      return -1;
   }

   *d++ = (uint8_t) segment_length;
   memcpy (d, start, segment_length);
   d += segment_length;

   *d++ = 0;

   return d - dst;
}

int
convert_to_dns_name (uint8_t *dst, const uint8_t *src, int length)
{
   if (dst == NULL || src == NULL || length == 0) {
      return kInvalidInput;
   }
   if (*src == POINTER_MASK) {
      *dst++ = *src++;
      *dst++ = *src++;
      return 2;
   } else {
      return convert_to_qname (dst, src, length);
   }
   return kOk;
}

int
process_dns_name (uint8_t *dst, const uint8_t *src, const uint8_t *dns_packet, int length)
{
   if (dst == NULL || src == NULL || dns_packet == NULL || length == 0) {
      return kInvalidInput;
   }
   if (*src == POINTER_MASK) {
      *dst++ = *src++;
      *dst++ = *src++;
      return 2;
   } else {
      return process_qname (dst, src, length);
   }
   return kOk;
}

dns_rc_t
process_dns_rdata (dns_arr_t *dst, const uint8_t *rdata_src, uint16_t length)
{
   if (dst == NULL || rdata_src == NULL || length == 0) {
      return kInvalidInput;
   }
   dst->rdlength = length;
   dst->rdata = (uint8_t *) malloc (length * sizeof (*dst->rdata)); // + 1 ?
   memcpy (dst->rdata, rdata_src, length);


   return kOk;
}

dns_h_t *
new_dns_h (const uint8_t *req, dns_rc_t *rc)
{
   dns_rc_t *lrc = rc;
   if (rc == NULL) {
      dns_rc_t trc;
      lrc = &trc;
   }
   *lrc = kOk;

   dns_h_t *dns = (dns_h_t *) calloc (1, sizeof (*dns));
   if (req == NULL) {
      return dns;
   }
   const dns_header_t *hdr_ptr = (const dns_header_t *) req;


   dns->header.id = ntohs (hdr_ptr->id);
   dns->header.hb3 = hdr_ptr->hb3;
   dns->header.hb4 = hdr_ptr->hb4;
   dns->header.qdcount = ntohs (hdr_ptr->qdcount);
   dns->header.ancount = ntohs (hdr_ptr->ancount);
   dns->header.nscount = ntohs (hdr_ptr->nscount);
   dns->header.arcount = ntohs (hdr_ptr->arcount);
   const uint8_t *cur_rr = req + sizeof (*hdr_ptr);
   do {
      if (dns->header.qdcount > 0) {
         dns->qrs = (dns_qrr_t *) malloc (dns->header.qdcount * sizeof (*dns->qrs));
         for (int i = 0; i < dns->header.qdcount; i++) {
            // Read and offset position of cur_rr to type field
            size_t len = 0;
            if ((len = process_qname ((char *) dns->qrs[i].name, (char *) cur_rr, RR_NAME_MAX)) < 0) {
               *lrc = kDataMalformed;
            }
            cur_rr += len;
            GETSHORT (dns->qrs[i].type, cur_rr);
            GETSHORT (dns->qrs[i].class, cur_rr);
         }
      }

      if (dns->header.ancount > 0) {
         dns->ancs = (dns_arr_t *) malloc (dns->header.ancount * sizeof (*dns->ancs));
         for (int i = 0; i < dns->header.ancount; i++) {
            // Read and offset position of cur_rr to type field
            size_t qlen = 0;
            if ((qlen = process_dns_name ((char *) dns->ancs[i].name, (char *) cur_rr, req, RR_NAME_MAX)) < 0) {
               *lrc = kDataMalformed;
            }
            cur_rr += qlen;
            GETSHORT (dns->ancs[i].type, cur_rr);
            GETSHORT (dns->ancs[i].class, cur_rr);
            GETLONG (dns->ancs[i].ttl, cur_rr);
            GETSHORT (dns->ancs[i].rdlength, cur_rr);
            const uint16_t rdl = dns->ancs[i].rdlength;
            if (process_dns_rdata (&dns->ancs[i], cur_rr, rdl) != kOk) {
               *lrc = kDataMalformed;
            }
            cur_rr += rdl;
         }
      }
      return dns;
   } while (0);
   destroy_dns_h (dns);
   return NULL;
};

uint8_t *
new_dns_buffer (const dns_h_t *dns, dns_rc_t *rc, int *out_bufsize)
{
   dns_rc_t *lrc = rc;
   if (rc == NULL) {
      dns_rc_t trc;
      lrc = &trc;
   }
   *lrc = kOk;

   uint8_t tmp[DNS_UDP_MAX_PACKLEN] = {0};
   uint8_t *cur_rr = tmp;

   if (dns == NULL) {
      return NULL;
   }

   PUTSHORT (dns->header.id, cur_rr);
   *cur_rr++ = dns->header.hb3;
   *cur_rr++ = dns->header.hb4;
   PUTSHORT (dns->header.qdcount, cur_rr);
   PUTSHORT (dns->header.ancount, cur_rr);
   PUTSHORT (dns->header.nscount, cur_rr);
   PUTSHORT (dns->header.arcount, cur_rr);
   for (int i = 0; i < dns->header.qdcount; ++i) {
      // Read and offset position of cur_rr to type field
      int len = convert_to_qname (cur_rr, dns->qrs[i].name, RR_NAME_MAX);
      cur_rr += len;
      PUTSHORT (dns->qrs[i].type, cur_rr);
      PUTSHORT (dns->qrs[i].class, cur_rr);
   }
   for (int i = 0; i < dns->header.ancount; ++i) {
      // Read and offset position of cur_rr to type field
      int len = convert_to_dns_name (cur_rr, dns->ancs[i].name, RR_NAME_MAX);
      cur_rr += len;
      PUTSHORT (dns->ancs[i].type, cur_rr);
      PUTSHORT (dns->ancs[i].class, cur_rr);
      PUTLONG (dns->ancs[i].ttl, cur_rr);
      PUTSHORT (dns->ancs[i].rdlength, cur_rr);
      const uint16_t rdl = dns->ancs[i].rdlength;
      memcpy (cur_rr, dns->ancs[i].rdata, rdl);

      cur_rr += rdl;
   }
   *out_bufsize = cur_rr - tmp;
   uint8_t *buf = (uint8_t *) malloc (*out_bufsize * sizeof (*buf));
   memcpy (buf, tmp, *out_bufsize);
   return buf;
};

void
destroy_dns_h (dns_h_t *dns)
{
   if (dns == NULL) {
      return;
   }
   if (dns->qrs != NULL) {
      free (dns->qrs);
   }
   for (int i = 0; i < dns->header.ancount; i++) {
      if (&dns->ancs[i] != NULL) {
         if (dns->ancs[i].rdlength > 0 && dns->ancs[i].rdata != NULL) {
            free (dns->ancs[i].rdata);
         }
      }
   }
   if (dns->ancs != NULL) {
      free (dns->ancs);
   }
   free (dns);
}