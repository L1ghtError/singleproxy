#include "configuration/configuration.h"
#include "utils/file_tools.h"
#include "utils/string_tools.h"
#include <cJSON.h>

dns_conf_t *
new_dns_conf_from_json (const char *conf_filepath, dns_rc_t *rc)
{
   dns_rc_t *lrc = rc;
   if (rc == NULL) {
      dns_rc_t trc;
      lrc = &trc;
   }
   *lrc = kOk;

   if (conf_filepath == NULL) {
      *lrc = kInvalidInput;
      return NULL;
   }

   FILE *file = NULL;
   if ((file = fopen (conf_filepath, "r")) == NULL) {
      *lrc = kNotFound;
      return NULL;
   }

   size_t filesize = get_filesize (file);
   uint8_t *filecontent = (uint8_t *) malloc (filesize * sizeof (*filecontent));
   *lrc = get_content (file, filesize, filecontent);
   if (*lrc != kOk) {
      return NULL;
   }

   cJSON *json_conf = cJSON_ParseWithLength (filecontent, filesize);

   if (json_conf == NULL) {
      *lrc = kInvalidInput;
      return NULL;
   }
   dns_conf_t *dns_conf = (dns_conf_t *) malloc (sizeof (*dns_conf));
   do {
      const cJSON *address = cJSON_GetObjectItem (json_conf, "address");
      if (address != NULL) {
         if (cJSON_IsString (address) && (address->valuestring != NULL)) {
            size_t l = strlen (address->valuestring) + 1;
            dns_conf->self.addr = (uint8_t *) malloc (l * sizeof (dns_conf->self.addr));
            strncpy (dns_conf->self.addr, address->valuestring, l);
         } else {
            *lrc = kInvalidInput;
            break;
         }
      }

      const cJSON *port = cJSON_GetObjectItem (json_conf, "port");
      if (port != NULL) {
         if (cJSON_IsNumber (port)) {
            dns_conf->self.port = (uint16_t) port->valueint;
         } else {
            *lrc = kInvalidInput;
            break;
         }
      }

      const cJSON *forwarder = cJSON_GetObjectItem (json_conf, "forwarder");
      if (forwarder != NULL) {
         if (cJSON_IsObject (forwarder)) {
            const cJSON *address = cJSON_GetObjectItem (forwarder, "address");
            if (!(cJSON_IsNull (address))) {
               if (cJSON_IsString (address) && (address->valuestring != NULL)) {
                  size_t l = strlen (address->valuestring) + 1;
                  dns_conf->upstream.addr = (uint8_t *) malloc (l * sizeof (dns_conf->upstream.addr));
                  strncpy (dns_conf->upstream.addr, address->valuestring, l);
               } else {
                  *lrc = kInvalidInput;
                  break;
               }
            }

            const cJSON *port = cJSON_GetObjectItem (forwarder, "port");
            if (port != NULL) {
               if (cJSON_IsNumber (port)) {
                  dns_conf->upstream.port = (uint16_t) port->valueint;
               } else {
                  *lrc = kInvalidInput;
                  break;
               }
            }
         } else {
            *lrc = kInvalidInput;
            break;
         }
      }

      const cJSON *filters = cJSON_GetObjectItem (json_conf, "filters");
      if (filters != NULL) {
         if (cJSON_IsArray (filters)) {
            int s = cJSON_GetArraySize (filters);
            dns_conf->filter_size = s;
            dns_conf->filters = (dns_filter_conf_t *) calloc (s, sizeof (*dns_conf->filters));

            int i = 0;
            const cJSON *filter = NULL;
            cJSON_ArrayForEach (filter, filters)
            {
               const cJSON *host = cJSON_GetObjectItem (filter, "host");
               if (host != NULL) {
                  if (cJSON_IsString (host) && (host->valuestring != NULL)) {
                     size_t l = strlen (host->valuestring) + 1;
                     dns_conf->filters[i].host = (uint8_t *) malloc (l * sizeof (dns_conf->filters[i].host));
                     strncpy (dns_conf->filters[i].host, host->valuestring, l);
                  } else {
                     *lrc = kInvalidInput;
                     break;
                  }
               }

               const cJSON *redirect = cJSON_GetObjectItem (filter, "redirect_addr");
               if (redirect != NULL) {
                  if (cJSON_IsString (redirect) && (redirect->valuestring != NULL)) {
                     size_t l = strlen (redirect->valuestring) + 1;

                     dns_conf->filters[i].redirect_addr =
                        (uint8_t *) malloc (l * sizeof (dns_conf->filters[i].redirect_addr));

                     strncpy (dns_conf->filters[i].redirect_addr, redirect->valuestring, l);
                  } else {
                     *lrc = kInvalidInput;
                     break;
                  }
               }

               const cJSON *filter_type = cJSON_GetObjectItem (filter, "type");
               if (filter_type != NULL) {
                  if (cJSON_IsString (filter_type) && (filter_type->valuestring != NULL)) {
                     if (str_i_cmp (filter_type->valuestring, "ALL") == 0)
                        dns_conf->filters[i].filter_type = DNS_FT_ALL;
                     else if (str_i_cmp (filter_type->valuestring, "A") == 0)
                        dns_conf->filters[i].filter_type = DNS_FT_IPV4;
                     else if (str_i_cmp (filter_type->valuestring, "AAAA") == 0)
                        dns_conf->filters[i].filter_type = DNS_FT_IPV6;
                     else {
                        *lrc = kInvalidInput;
                        break;
                     }
                  } else {
                     *lrc = kInvalidInput;
                     break;
                  }
               }

               const cJSON *match_type = cJSON_GetObjectItem (filter, "matching");
               if (match_type != NULL) {
                  if (cJSON_IsString (match_type) && (match_type->valuestring != NULL)) {
                     if (str_i_cmp (match_type->valuestring, "contains") == 0)
                        dns_conf->filters[i].match_type = DNS_MT_CONTAINS;
                     else if (str_i_cmp (match_type->valuestring, "exact") == 0)
                        dns_conf->filters[i].match_type = DNS_MT_EXACT;
                     else {
                        *lrc = kInvalidInput;
                        break;
                     }
                  } else {
                     *lrc = kInvalidInput;
                     break;
                  }
               }

               const cJSON *action_type = cJSON_GetObjectItem (filter, "action");
               if (action_type != NULL) {
                  if (cJSON_IsString (action_type) && (action_type->valuestring != NULL)) {
                     if (str_i_cmp (action_type->valuestring, "discard") == 0)
                        dns_conf->filters[i].action_type = DNS_AT_NOTFOUND;
                     else if (str_i_cmp (action_type->valuestring, "refuse") == 0)
                        dns_conf->filters[i].action_type = DNS_AT_REFUSE;
                     else if (str_i_cmp (action_type->valuestring, "redirect") == 0)
                        dns_conf->filters[i].action_type = DNS_AT_REDIRECT;
                     else {
                        *lrc = kInvalidInput;
                        break;
                     }
                  } else {
                     *lrc = kInvalidInput;
                     break;
                  }
               }
               ++i;
            }

         } else {
            *lrc = kInvalidInput;
            break;
         }
      }
   } while (0);
   free (filecontent);
   cJSON_Delete (json_conf);
   if (*lrc != kOk) {
      destroy_dns_conf (dns_conf);
      return NULL;
   }

   return dns_conf;
}

void
destroy_dns_conf (dns_conf_t *dns_conf)
{
   if (dns_conf == NULL) {
      return;
   }
   if (dns_conf->self.addr != NULL) {
      free (dns_conf->self.addr);
   }
   if (dns_conf->upstream.addr != NULL) {
      free (dns_conf->upstream.addr);
   }
   for (int i = 0; i < dns_conf->filter_size; ++i) {
      if (dns_conf->filters[i].host != NULL) {
         free (dns_conf->filters[i].host);
      }
      if (dns_conf->filters[i].redirect_addr != NULL) {
         free (dns_conf->filters[i].redirect_addr);
      }
   }
   if (dns_conf->filter_size > 0) {
      free (dns_conf->filters);
   }
   free (dns_conf);
}
