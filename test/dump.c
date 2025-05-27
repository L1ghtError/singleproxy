#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

void
resolve_hostname (const char *hostname)
{
   struct addrinfo hints, *res;
   struct sockaddr_in *addr;
   char ip[INET_ADDRSTRLEN];

   // Prepare the hints structure
   memset (&hints, 0, sizeof (hints));
   hints.ai_family = AF_INET;       // IPv4
   hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

   // Resolve the DNS name
   if (getaddrinfo (hostname, NULL, &hints, &res) != 0) {
      perror ("getaddrinfo");
      return;
   }

   // Extract the IP address and print it
   addr = (struct sockaddr_in *) res->ai_addr;
   inet_ntop (AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);
   printf ("IP address for %s: %s\n", hostname, ip);

   freeaddrinfo (res);
}

int
main ()
{
   const char *hostnames[] = {"www.example.com", "www.google.com", "www.openai.com","www.youtube.com"};
   size_t num_hostnames = sizeof (hostnames) / sizeof (hostnames[0]);

   for (size_t i = 0; i < num_hostnames; i++) {
      resolve_hostname (hostnames[i]);
   }

   return 0;
}
