#ifndef CLIENT_H_ // include guard
#define CLIENT_H_

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct addrinfo addrinfo_t;

typedef struct website {
    char *address;
    char *port;
    char *page;
    int ssl;
} website_t;

typedef struct response {
    double time;
    char *code;
    unsigned long size;
} response_t;

website_t* parse_url(char *url);
response_t *make_request(addrinfo_t *res, website_t *website, SSL_CTX *ctx);

#endif // include guard