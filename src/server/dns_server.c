#include "server/dns_server.h"
#include "dns/dns-parse.h"
#include "utils/string_tools.h"
#include "utils/network_tools.h"

#include "sys/select.h"

#include "stdlib.h"
#include "string.h"
#include <errno.h>

dns_rc_t
init_dns_addrinfo (struct addrinfo *ainfo, const char *host, uint16_t port, struct sockaddr_storage *storage)
{
   memset (storage, 0, sizeof (*storage)); // Ensure zero-initialization
   memset (ainfo, 0, sizeof (*ainfo));     // Ensure zero-initialization

   // Clear the storage and handle AF_INET (IPv4)
   struct sockaddr_in *sa = (struct sockaddr_in *) storage;
   sa->sin_port = htons (port);
   ainfo->ai_family = AF_INET;
   ainfo->ai_socktype = SOCK_DGRAM;
   ainfo->ai_protocol = IPPROTO_UDP;
   ainfo->ai_addr = (struct sockaddr *) sa;
   sa->sin_family = ainfo->ai_family;
   sa->sin_addr.s_addr = INADDR_ANY;
   ainfo->ai_addrlen = sizeof (*sa);

   // Try to parse as IPv4
   if (inet_pton (AF_INET, host, &sa->sin_addr) == 1) {
      return kOk; // Successfully parsed IPv4
   }

   // Clear the storage and handle AF_INET6 (IPv6)
   struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) storage;
   sa6->sin6_port = htons (port);
   ainfo->ai_family = AF_INET6;
   ainfo->ai_protocol = IPPROTO_UDP;
   ainfo->ai_addr = (struct sockaddr *) sa6;
   ainfo->ai_addrlen = sizeof (*sa6);

   // Try to parse as IPv6
   sa6->sin6_family = AF_INET6;
   if (inet_pton (AF_INET6, host, &sa6->sin6_addr) == 1) {
      return kOk; // Successfully parsed IPv6
   }

   return kDataMalformed; // Neither IPv4 nor IPv6 address could be parsed
}


DNS_SOCK
bind_dns_socket (const struct addrinfo *ainfo, struct sockaddr_storage *storage)
{
   DNS_SOCK sockfd = -1;
   if ((sockfd = socket (ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol)) == -1) {
      close (sockfd);
      return -1;
   }
   int so_reuseaddr = 1;
   if (setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof (int)) == -1) {
      close (sockfd);
      return -1;
   }
   struct sockaddr_in *sa = (struct sockaddr_in *) ainfo->ai_addr;
   if (bind (sockfd, ainfo->ai_addr, ainfo->ai_addrlen) < 0) {
      perror ("bind");
      close (sockfd);
      return -1;
   }
   return sockfd;
}

dns_server_t *
init_dns_server (const dns_conf_t *conf, dns_rc_t *rc)
{
   dns_rc_t *lrc = rc;
   if (rc == NULL) {
      dns_rc_t trc;
      lrc = &trc;
   }
   *lrc = kOk;

   if (conf == NULL) {
      *lrc = kInvalidInput;
      return NULL;
   }

   validate_dns_conf (conf, lrc);
   if (*lrc != kOk) {
      return NULL;
   }
   size_t addrlen = strlen (conf->self.addr);
   dns_server_t *server = (dns_server_t *) calloc (1, sizeof (*server));
   strncpy (server->s_host, conf->self.addr, addrlen);
   server->s_port = conf->self.port;

   addrlen = strlen (conf->upstream.addr);
   strncpy (server->u_host, conf->upstream.addr, addrlen);
   server->u_port = conf->upstream.port;
   server->conf = conf;

   *lrc = init_dns_addrinfo (&server->s_hints, server->s_host, server->s_port, &server->s_storage);
   if (*lrc != kOk) {
      destroy_dns_server (server);
      return NULL;
   }
   server->self_sockfd = bind_dns_socket (&server->s_hints, &server->s_storage);
   if (server->self_sockfd == -1) {
      *lrc = kAborted;
      destroy_dns_server (server);
      return NULL;
   }

   *lrc = init_dns_addrinfo (&server->u_hints, server->u_host, server->u_port, &server->u_storage);
   if (*lrc != kOk) {
      destroy_dns_server (server);
      return NULL;
   }
   if ((server->upstream_sockfd =
           socket (server->u_hints.ai_family, server->u_hints.ai_socktype, server->u_hints.ai_protocol)) == -1) {
      *lrc = kAborted;
      destroy_dns_server (server);
      return NULL;
   }
   server->read_timeout.tv_sec = DEFAULT_READ_TIMEOUT_SEC;
   server->read_timeout.tv_usec = DEFAULT_READ_TIMEOUT_USEC;

   server->quit = 0;
   return server;
}

const dns_filter_conf_t *
find_filter (const dns_filter_conf_t *filters, int fsize, const dns_h_t *dht, uint16_t *out_q)
{
   if (filters == NULL || fsize == 0 || dht == NULL) {
      return NULL;
   }

   for (int i = 0; i < dht->header.qdcount; i++) {
      for (int j = 0; j < fsize; j++) {
         if ((filters[j].match_type == DNS_MT_EXACT && (str_i_cmp (dht->qrs[i].name, filters[j].host) == 0)) ||
             ((filters[j].match_type == DNS_MT_CONTAINS) && (str_i_str (dht->qrs[i].name, filters[j].host) != NULL))) {
            if (out_q != NULL) {
               *out_q = i;
            }
            return &filters[j];
         }
      }
   }
   return NULL;
}

dns_h_t *
new_dns_h_refuse (const dns_h_t *dht)
{
   if (dht == NULL) {
      return NULL;
   }
   dns_h_t *dht_resp = new_dns_h (NULL, NULL);
   if (dht_resp == NULL) {
      return dht_resp;
   }
   dht_resp->header = dht->header;

   if (dht_resp->header.qdcount > 0) {
      dht_resp->qrs = (dns_qrr_t *) malloc (dht_resp->header.qdcount * sizeof (*dht_resp->qrs));
      for (int i = 0; i < dht_resp->header.qdcount; i++) {
         size_t len = strlen (dht->qrs[i].name);
         strncpy (dht_resp->qrs[i].name, dht->qrs[i].name, len);
         dht_resp->qrs[i].type = dht->qrs[i].type;
         dht_resp->qrs[i].class = dht->qrs[i].class;
      }
   }
   SET_RCODE (&dht_resp->header, RCODE_REFUSED);
   return dht_resp;
}

dns_h_t *
new_dns_h_notfound (const dns_h_t *dht)
{
   if (dht == NULL) {
      return NULL;
   }
   dns_h_t *dht_resp = new_dns_h (NULL, NULL);
   if (dht_resp == NULL) {
      return dht_resp;
   }
   dht_resp->header = dht->header;

   if (dht_resp->header.qdcount > 0) {
      dht_resp->qrs = (dns_qrr_t *) malloc (dht_resp->header.qdcount * sizeof (*dht_resp->qrs));
      for (int i = 0; i < dht_resp->header.qdcount; i++) {
         size_t len = strlen (dht->qrs[i].name);
         strncpy (dht_resp->qrs[i].name, dht->qrs[i].name, len);
         dht_resp->qrs[i].type = dht->qrs[i].type;
         dht_resp->qrs[i].class = dht->qrs[i].class;
      }
   }
   SET_RCODE (&dht_resp->header, RCODE_NXDOMAIN);
   return dht_resp;
}

dns_h_t *
new_dns_h_redirect (const dns_h_t *dht, uint16_t qindex, const uint8_t *redirect_addr)
{
   if (dht == NULL || redirect_addr == NULL) {
      return NULL;
   }
   dns_h_t *dht_resp = new_dns_h (NULL, NULL);
   if (dht_resp == NULL) {
      return dht_resp;
   }
   dht_resp->header = dht->header;
   size_t *qlengths = 0;
   if (dht_resp->header.qdcount < 0 || dht_resp->header.qdcount < qindex) {
      return NULL;
   }

   dht_resp->qrs = (dns_qrr_t *) malloc (dht_resp->header.qdcount * sizeof (*dht_resp->qrs));
   qlengths = (size_t *) calloc (dht_resp->header.qdcount, sizeof (*qlengths));

   for (int i = 0; i < dht_resp->header.qdcount; i++) {
      size_t len = strlen (dht->qrs[i].name);
      strncpy (dht_resp->qrs[i].name, dht->qrs[i].name, len);
      dht_resp->qrs[i].type = dht->qrs[i].type;
      dht_resp->qrs[i].class = dht->qrs[i].class;

      qlengths[i] += (sizeof (*dht_resp->qrs) - sizeof (dht_resp->qrs->name) + len);
   }
   dht_resp->header.ancount = 1;
   dht_resp->ancs = (dns_arr_t *) malloc (sizeof (*dht_resp->ancs));
   dht_resp->ancs->name[0] = POINTER_MASK;
   uint8_t ptr_offset = sizeof (dht->header);
   for (int i = 0; i < (dht_resp->header.qdcount - 1); ++i) {
      ptr_offset += qlengths[i];
   }
   free (qlengths);
   dht_resp->ancs->name[1] = ptr_offset;
   uint8_t bin_addr[16] = {0};
   int addr_size = 0;
   if (get_address_ip_binary (redirect_addr, bin_addr, &addr_size) == -1) {
      return NULL;
   }
   if ((dht_resp->qrs[qindex].type == T_A && addr_size == 4) ||
       (dht_resp->qrs[qindex].type == T_AAAA && addr_size == 16)) {
      dht_resp->ancs->type = dht_resp->qrs[qindex].type;
   } else {
      return NULL;
   }
   dht_resp->ancs->class = C_IN;
   dht_resp->ancs->ttl = DEFAULT_TTL;
   dht_resp->ancs->rdlength = addr_size;
   dht_resp->ancs->rdata = (uint8_t *) malloc (addr_size * sizeof (*dht_resp->ancs->rdata));
   memcpy (dht_resp->ancs->rdata, bin_addr, addr_size);
   return dht_resp;
}


dns_h_t *
decide_dns_response (const dns_server_t *server, const dns_h_t *dht)
{
   if (server == NULL || dht == NULL) {
      return NULL;
   }
   uint16_t q_index = 0;
   const dns_filter_conf_t *filter = find_filter (server->conf->filters, server->conf->filter_size, dht, &q_index);
   if (filter == NULL) {
      return NULL;
   }
   dns_action_type_t action = DNS_AT_HANDLE;

   if (filter->filter_type == DNS_FT_ALL) {
      action = filter->action_type;
   } else if (filter->filter_type == DNS_FT_IPV4 && dht->qrs->type == T_A) {
      action = filter->action_type;
   } else if (filter->filter_type == DNS_FT_IPV6 && dht->qrs->type == T_AAAA) {
      action = filter->action_type;
   }
   if (action == DNS_AT_NOTFOUND) {
      return new_dns_h_notfound (dht);
   } else if (action == DNS_AT_REFUSE) {
      return new_dns_h_refuse (dht);
   } else if (action == DNS_AT_REDIRECT) {
      return new_dns_h_redirect (dht, q_index, filter->redirect_addr);
   }

   return NULL;
}


#define BUFFER_SIZE 1024
dns_rc_t
run_dns_server (const dns_server_t *server)
{
   char buffer[BUFFER_SIZE] = {0};
   struct sockaddr_in client_addr = {0};

   socklen_t c_len = sizeof (client_addr);
   socklen_t u_len = server->u_hints.ai_addrlen;
   ssize_t n;
   fd_set read_fds;

   // select expects non-const timeout pointer
   READ_TIMEOUT read_timeout = server->read_timeout;

   while (server->quit == 0) {
      FD_ZERO (&read_fds);
      FD_SET (server->self_sockfd, &read_fds);
      n = select (server->self_sockfd + 1, &read_fds, NULL, NULL, &read_timeout);
      if (n < 0) {
         printf ("Error, socket select failed!\n");
         break;
      } else if (n == 0) {
         continue;
      }
      // invert FD_ISSET to prevents code from nesting several if-statements
      if (!FD_ISSET (server->self_sockfd, &read_fds)) {
         printf ("Error, socket expects to a have data!\n");
         break;
      }
      // Receive a message from a client
      n = recvfrom (server->self_sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &client_addr, &c_len);
      dns_h_t *dha = new_dns_h (buffer, NULL);
      if (dha == NULL) {
         printf ("Error, cannot alloc memory for response!\n");
         break;
      }

      dns_h_t *resp = decide_dns_response (server, dha);
      // FILTERED ROUTE
      if (resp != NULL) {
         int buf_len = 0;
         uint8_t *gen_buf = new_dns_buffer (resp, NULL, &buf_len);

         sendto (server->self_sockfd, gen_buf, buf_len, 0, (struct sockaddr *) &client_addr, c_len);
         memset (buffer, 0, BUFFER_SIZE);

         destroy_dns_h (resp);
         free (gen_buf);
      } else {
         // UNFILTERED ROUTE
         sendto (server->upstream_sockfd, buffer, n, 0, server->u_hints.ai_addr, server->u_hints.ai_addrlen);
         memset (buffer, 0, BUFFER_SIZE);

         n = recvfrom (server->upstream_sockfd, buffer, BUFFER_SIZE, 0, server->u_hints.ai_addr, &u_len);

         sendto (server->self_sockfd, buffer, n, 0, (struct sockaddr *) &client_addr, c_len);
         memset (buffer, 0, BUFFER_SIZE);
      }
      destroy_dns_h (dha);
   }
   return kOk;
}

const uint8_t *
validate_dns_conf (const dns_conf_t *conf, dns_rc_t *rc)
{
   dns_rc_t *lrc = rc;
   if (rc == NULL) {
      dns_rc_t trc;
      lrc = &trc;
   }
   *lrc = kOk;

   if (conf == NULL) {
      *lrc = kInvalidInput;
      static const uint8_t *err = "provided config is NULL";
      return err;
   }


   if (conf->self.addr == NULL) {
      *lrc = kDataMalformed;
      static const uint8_t *err = "server address is not provided";
      return err;
   }

   struct sockaddr_in sa;
   struct sockaddr_in6 sa6;
   if (inet_pton (AF_INET, conf->self.addr, &(sa.sin_addr)) != 1) {
      if (inet_pton (AF_INET6, conf->self.addr, &(sa6.sin6_addr)) != 1) {
         *lrc = kDataMalformed;
         static const uint8_t *err = "provided server address is invalid, it should be valid ipv4 or ipv6 address";
         return err;
      }
   }
   if (conf->self.port == 0) {
      *lrc = kDataMalformed;
      static const uint8_t *err = "provided server port address is 0, it should be greater than 0";
      return err;
   }


   if (conf->upstream.addr == NULL) {
      *lrc = kDataMalformed;
      static const uint8_t *err = "upstream address is not provided";
      return err;
   }

   if (inet_pton (AF_INET, conf->upstream.addr, &(sa.sin_addr)) != 1) {
      if (inet_pton (AF_INET6, conf->upstream.addr, &(sa6.sin6_addr)) != 1) {
         *lrc = kDataMalformed;
         static const uint8_t *err = "provided upstream address is invalid, it should be valid ipv4 or ipv6 address";
         return err;
      }
   }
   if (conf->upstream.port == 0) {
      *lrc = kDataMalformed;
      static const uint8_t *err = "provided upstream port address is 0, it should be greater than 0";
      return err;
   }
   for (int i = 0; i < conf->filter_size; ++i) {
      if (conf->filters[i].host == NULL) {
         *lrc = kDataMalformed;
         static const uint8_t *err = "one of the filters \"host\" is not provided";
         return err;
      }

      if (conf->filters[i].action_type == DNS_AT_REDIRECT) {
         if (conf->filters[i].redirect_addr == NULL) {
            *lrc = kDataMalformed;
            static const uint8_t *err = "selected action is \"redirect\" but \"redirect_addr\" is not provided";
            return err;
         }

         if (inet_pton (AF_INET, conf->filters[i].redirect_addr, &(sa.sin_addr)) != 1) {
            if (inet_pton (AF_INET6, conf->filters[i].redirect_addr, &(sa6.sin6_addr)) != 1) {
               *lrc = kDataMalformed;
               static const uint8_t *err =
                  "provided \"redirect_addr\" is invalid, it should be valid ipv4 or ipv6 address";
               return err;
            }
         }
      }
   }
   return NULL;
}

void
destroy_dns_server (dns_server_t *server)
{
   free (server);
   close (server->self_sockfd);
   close (server->upstream_sockfd);
}