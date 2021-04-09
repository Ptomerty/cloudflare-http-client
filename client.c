#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "client.h"

#include <openssl/ssl.h>
#include <openssl/err.h>


// here goes...

/** 
    Simple HTTP Client, with support for chunked Transfer Encoding and TLS!

    Dependencies: OpenSSL

    Author: Spencer Hua (Ptomerty)
*/

website_t *parse_url(char *url) {
    /** 
        Parse URL argument
    */
    website_t *website = calloc(1, sizeof(website_t));
    website->address = calloc(48, sizeof(char));
    website->page = calloc(128, sizeof(char));

    char *strip_url = calloc(strlen(url) + 1, sizeof(char));
    char *check_split = strstr(url, "://");
    if (check_split == NULL) {
        fprintf(stderr, "No protocol protocol specified. Did you forget http(s)?\n");
        exit(EXIT_FAILURE);
    } else if (strncmp(url, "https", 5) == 0) {
        // TLS found
        website->port = "443";
        website->ssl = 1;
        strncpy(strip_url, url + 8, strlen(url) - 7);
    } else if (strncmp(url, "http", 4) == 0) {
        // HTTP found
        website->port = "80";
        website->ssl = 0;
        strncpy(strip_url, url + 7, strlen(url) - 6);
    } else {
        fprintf(stderr, "Unknown protocol provided!\n");
        exit(EXIT_FAILURE);
    }

    // char *addr = calloc(strlen(strip_url) + 1, sizeof(char));
    website->page = strstr(strip_url, "/");
    if (website->page == NULL) {
        website->page = "/";
        website->address = strip_url;
    } else {
        strncpy(website->address, strip_url, website->page - strip_url);
    }

    return website;
}
response_t *make_request(addrinfo_t *res, website_t *website, SSL_CTX *ctx) {
    response_t *response = calloc(1, sizeof(response_t));
    response->code = calloc(64, sizeof(char));
    // start timing!

    clock_t start, end;
    start = clock();

    char *request = calloc(256, sizeof(char)); // request buffer
    snprintf(request, 256, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nAccept-Encoding: identity\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0) Gecko/20100101 Firefox/6.0\r\n\r\n", website->page, website->address);
    // printf("strlen: %d, request: %s\n",256, request);

    int sockfd;
    addrinfo_t *res_item;
    for (res_item = res; res_item != NULL; res_item = res_item->ai_next) {
        sockfd = socket(res_item->ai_family, res_item->ai_socktype, res_item->ai_protocol);
        if (sockfd == -1) {
            continue; // unsuccessful socket
        }
        if (connect(sockfd, res_item->ai_addr, res_item->ai_addrlen) == 0) {
            break; // succesfully connected
        } else {
            close(sockfd); // didn't connect
        }
    }
    if (res_item == NULL) {
        fprintf(stderr, "Could not connect to server.\n");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = NULL;
    if (ctx != NULL) {
        ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, website->address);
        SSL_set_connect_state(ssl);
        SSL_set_fd(ssl, sockfd);
        if (SSL_connect(ssl) == -1) {
            ERR_print_errors_fp(stderr);
        }
        
        if (SSL_write(ssl, request, 256) < 0) {
            fprintf(stderr, "Could not write to socket!\n");
            exit(EXIT_FAILURE);
        }
    } else {
        if (write(sockfd, request, 256) < 0) {
            fprintf(stderr, "Could not write to socket!\n");
            exit(EXIT_FAILURE);
        }
    }
    
    

    puts("---------- RESPONSE START ----------");

    char *buf = calloc(9001, sizeof(char));
    char *chunk_size_str = calloc(16, sizeof(char));
    char *split = NULL, *iter = NULL;
    int chunked = 0, headers_done = 0, transfer_done = 0;
    int bytes_read = 0;
    unsigned long chunk_size = 0, content_length = 0, header_len = 0; // includes trailing \r\n
    while (1) {
        if (!headers_done) {
            int total_bytes_read = 0;
            while (split == NULL) {
                if (ssl) {
                    bytes_read = SSL_read(ssl, buf + total_bytes_read, 9000);
                } else {
                    bytes_read = read(sockfd, buf + total_bytes_read, 9000);
                }                
                response->size += bytes_read;
                total_bytes_read += bytes_read;
                split = strstr(buf, "\r\n\r\n");
            }
            buf[total_bytes_read] = 0;
            headers_done = 1;
            header_len = split - buf + 4;

            // parse headers
            char *end_of_http = strstr(buf, " ");
            char *eol = strstr(buf, "\r\n");
            memcpy(response->code, end_of_http + 1, eol - end_of_http - 1);
            response->code[eol - end_of_http] = 0; // null terminate
            if (strstr(buf, "Transfer-Encoding: chunked") != NULL) {
                chunked = 1; // we've got chunked transfers!
            } else if (strstr(buf, "Content-Length:") != NULL) {
                char *head_l = strstr(buf, "Content-Length:") + 15;
                char *end_l = strstr(head_l, "\r\n");
                char *len_str = calloc(8, sizeof(char));
                memcpy(len_str, head_l, end_l - head_l);
                content_length = strtoul(len_str, NULL, 10);
                free(len_str);
                if (content_length == 0) {
                    // end early
                    end = clock();
                    break;
                }
            }
            if (header_len == total_bytes_read) {
                // header finished and no extra data was send, get next chunk
                continue;
            } else {
                // parse the data left in the buffer
                iter = buf + header_len; // points DIRECTLY to beginning of buffer
                if (!chunked) {
                    // identity: just print
                    content_length -= (total_bytes_read - header_len);
                    // printf("%s", iter);
                } else {
                    // parse chunk length
                    split = strstr(iter, "\r\n");
                    if (split == NULL) {
                        fprintf(stderr, "ERROR: Couldn't find length of initial chunk for chunked encoding!\n");
                        exit(EXIT_FAILURE);
                    }
                    memset(chunk_size_str, 0, 16); // ensure we're not writing over garbage data
                    strncpy(chunk_size_str, iter, split - iter);
                    chunk_size = strtoul(chunk_size_str, NULL, 16);
                    iter = split + 2; // move iter to beginning of text

                    // if there's data left after chunk size, print it out
                    chunk_size -= strlen(iter); // get rid of rest of iter
                }
                // either way, print out the rest of the buffer
                printf("%s", iter);
            }
        } else {
            // handling data
            if (ssl) {
                bytes_read = SSL_read(ssl, buf, 9000);
            } else {
                bytes_read = read(sockfd, buf, 9000);
            }
            
            buf[bytes_read] = 0;
            response->size += bytes_read;
            if (!chunked) {
                // identity encoding? can just print the buffer
                content_length -= bytes_read;
                if (content_length == 0) {
                    transfer_done = 1;
                }
                printf("%s", buf);
            } else {
                iter = buf;
                if (bytes_read < chunk_size + 2) {
                    // chunk is fine to print, chunk + footer is big enough
                    write(1, iter, bytes_read);
                    chunk_size -= bytes_read;
                } else {
                    // need to handle chunk sizes, our current chunk is ending
                    while (bytes_read >= chunk_size + 2) {
                        // flush remaining chunk in buffer
                        if (chunk_size != 0) {
                            write(1, iter, chunk_size);
                            bytes_read -= (chunk_size + 2);
                            // flush endline
                            iter += (chunk_size + 2);
                            chunk_size = 0;
                            if (bytes_read == 0) {
                                // buffer has ended
                                break;
                            }
                        }

                        // else find next break in data
                        split = strstr(iter, "\r\n");
                        if (split == NULL) {
                            // handling edge case where uncompliant server doesn't follow spec
                            memset(chunk_size_str, 0, 16);
                            memcpy(chunk_size_str, iter, strlen(iter) + 1);
                            chunk_size_str[strlen(iter)] = 0;                            
                            bytes_read -= strlen(iter);
                        } else {
                            memset(chunk_size_str, 0, 16);
                            strncpy(chunk_size_str, iter, split - iter);
                            bytes_read -= (split - iter + 2);
                        }

                        // got chunk size string!
                        chunk_size = strtoul(chunk_size_str, NULL, 16);
                        if (chunk_size == 0) {
                            // next chunk ends
                            transfer_done = 1;
                            break;
                        } else {
                            // flush endline after chunk length
                            iter = split + 2;
                        }     
                    }
                    // chunk sizes handled
                    if ((bytes_read > 0) && (chunk_size > 0)) {
                        // only chunk data remains in buffer, we're safe to print it out
                        write(1, iter, bytes_read);
                        chunk_size -= bytes_read;
                    }
                }
            }
        }
        if (transfer_done) {
            end = clock();
            break;
        }
    }

    response->time = ((double) (end - start)) / CLOCKS_PER_SEC;
    puts("\n---------- RESPONSE END ----------");
    close(sockfd);

    // free calloc'd memory
    free(request);
    free(chunk_size_str);
    free(buf);
    return response;

}

/*
    Comparator function for qsort() call
*/
int compare_d( const void* a, const void* b) {
    return (*(double*)a > *(double*)b) ? 1 : (*(double*)a < *(double*)b) ? -1 : 0 ;
}

int main(int argc, char *argv[]) {
    // check provided arguments
    if (argc < 2) {
        fprintf(stderr, "Not enough arguments provided. Usage: client [-h|--help] [--url <url --profile <int>]\n");
        exit(EXIT_FAILURE);
    }
    if (argc > 5) {
        fprintf(stderr, "Too many arguments provided. Usage: client [-h|--help] [--url <url --profile <int>]\n");
        exit(EXIT_FAILURE);
    }

    // disable buffering to prevent weird line-buffered printf errors
    setbuf(stdout, NULL);

    // set up options
    const static struct option long_options[] = { 
        { "url", required_argument, NULL, 1 },
        { "profile", required_argument, NULL, 2 },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 } 
    };


    const char *help_str = "Usage: client [-h|--help] [--url <url --profile <int>]\n\n"
                "Description: Basic HTTP Client for the Cloudflare Systems Engineering Challenge\n\n"
                "Optional Arguments:\n\n"
                "-h, --help\t\tPrint this help message.\n"
                "--url <url>\t\tSend request to a full path URL. Include http(s) in your URL.\n"
                "--profile <p=1>\t\tMake p requests to the specified URL. Defaults to 1 if not specified.";
    char *url = NULL;
    int opt;
    unsigned long profile = 1;
    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (opt) {
            case 1:
                url = optarg;
                break;
            case 2:
                profile = strtoul(optarg, NULL, 10);
                if (profile == 0) {
                    fprintf(stderr, "Cannot run 0 times!\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
                printf("%s\n",help_str);
                exit(EXIT_SUCCESS);
                break;
            default:
                fprintf(stderr, "Panic while getting options!\n");
                exit(EXIT_FAILURE);
        }
    }
    if (url == NULL) {
        fprintf(stderr, "URL was not specified!\n\n%s\n", help_str);
        exit(EXIT_FAILURE);
    }

    // initialize SSL context
    SSL_CTX *ctx;
    SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    const SSL_METHOD *method = TLS_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // parse URL into website_t
    website_t *website = parse_url(url);

    /**
        Set up connection pre-requisites
    */
    // https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
    // https://beej.us/guide/bgnet/html/
    addrinfo_t hints;
    addrinfo_t *res;
    memset(&hints, 0, sizeof(addrinfo_t)); // clear hint struct
    hints.ai_family = AF_INET; // ipv4 for now
    hints.ai_socktype = SOCK_STREAM; // tcp
    hints.ai_flags = AI_CANONNAME; // no extra flags
    hints.ai_protocol = 0; // any protocol

    if ((getaddrinfo(website->address, website->port, &hints, &res)) != 0) {
        fprintf(stderr, "Invalid address provided!\n");
        exit(EXIT_FAILURE);
    }

    /**
        Send GET requests according to profile
    */
    response_t *response_arr[profile];
    double times[profile];
    double total_time = 0;
    unsigned long resp_s = ULONG_MAX, resp_l = 0, successes = 0;
    for (int i = 0; i < profile; i++) {
        if (website->ssl) {
            response_arr[i] = make_request(res, website, ctx);
        } else {
            response_arr[i] = make_request(res, website, NULL);
        }
        
        times[i] = response_arr[i]->time;

        // print out response info
        printf("Response code: %s\n", response_arr[i]->code);
        printf("Time taken: %f seconds\n", response_arr[i]->time);
        printf("Response size: %lu bytes\n", response_arr[i]->size);

        // start tracking profile info
        total_time += response_arr[i]->time;
        if (response_arr[i]->size < resp_s) {
            resp_s = response_arr[i]->size;
        }
        if (response_arr[i]->size > resp_l) {
            resp_l = response_arr[i]->size;
        }
        if ((strncmp(response_arr[i]->code, "200", 3)) == 0) {
            successes += 1;
        }
    }

    // get time info
    qsort(times, profile, sizeof(double), compare_d);
    double median_time;
    if (profile & 0x1) {
        // profile is odd
        median_time = times[profile / 2];
    } else {
        double a = times[profile / 2];
        double b = times[profile / 2 - 1];
        median_time = (a + b) / 2;
    }


    printf("\n---------- PROFILE STATISTICS ----------\n");
    printf("Number of requests: %lu\n", profile);
    printf("Fastest time: %f seconds\n", times[0]);
    printf("Slowest time: %f seconds\n", times[profile - 1]);
    printf("Mean time: %f seconds\n", total_time / profile);
    printf("Median time: %f seconds\n", median_time);
    printf("Percentage of requests that succeeded: %.2f%%\n", (double)successes * 100 / profile);
    printf("Error codes returned (if applicable): ");
    for (int i = 0; i < profile; i++) {
        if ((strncmp(response_arr[i]->code, "200", 3)) != 0) {
            printf("%s", response_arr[i]->code);
            if (i != profile - 1) {
                printf(", ");
            }
        }
    }
    printf("\nSmallest response: %lu bytes\n", resp_s);
    printf("Largest response: %lu bytes\n", resp_l);

    exit(EXIT_SUCCESS);        
}