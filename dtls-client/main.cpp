/*
 *  Hello world example of a DTLS client
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/** \file main.cpp
 *  \brief An example TLS Client application
 *  This application sends an HTTPS request to os.mbed.com and searches for a string in
 *  the result.
 *
 *  This example is implemented as a logic class (HelloHTTPS) wrapping a UDP socket.
 *  The logic class handles all events, leaving the main loop to just check if the process
 *  has finished.
 */

/* Change to a number between 1 and 4 to debug the TLS connection */
//#define MBEDTLS_DEBUG_C // This comes from the tls config, but we didn't include it yet, so include it here
#define DEBUG_LEVEL 0

#include "mbed.h"
#include "mbed_stats.h"
#include "NetworkStack.h"

#include "EthernetInterface.h"
#include "UDPSocket.h"

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

struct my_timer_t {
    osTimerId_t int_timer_id;
    osTimerId_t fin_timer_id;
    osTimerAttr_t int_timer_attr;
    osTimerAttr_t fin_timer_attr;
    mbed_rtos_storage_timer_t int_timer_mem;
    mbed_rtos_storage_timer_t fin_timer_mem;
    uint32_t int_ms;
    uint32_t fin_ms;
    int cancelled;
};

//static const char *SERVER_ADDR = "10.1.25.22";
static const char *SERVER_ADDR = "192.168.42.132";
static const nsapi_addr_t NS_SERVER_ADDR = {NSAPI_IPv4, {192, 168, 42, 132}};
static const int SERVER_PORT = 4433;
static const int RECV_BUFFER_SIZE = 600;
static const int READ_TIMEOUT_MS = 1000;
static const int MAX_RETRY = 5;

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    static const unsigned char my_psk[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    static char psk_identity[] = "foo";
#endif

#if MBED_HEAP_STATS_ENABLED
static mbed_stats_heap_t heap_stats;
#endif

/* PSK or ECDHE_ECDSA */

/* TLS_PSK_WITH_AES_128_CCM_8
 * TLS_PSK_WITH_AES_128_CBC_SHA256
 * TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
 * TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 * (TLS_DHE_PSK_WITH_AES_128_CCM)
 * (TLS_PSK_DHE_WITH_AES_128_CCM_8)
 * */

/* Test related data */
const char *HTTPS_OK_STR = "200 OK";
const char *HTTPS_HELLO_STR = "Hello world!";

/* personalization string for the drbg */
const char *DRBG_PERS = "Mbed TLS DTLS client";

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/* List of trusted root CA certificates
 * currently only GlobalSign, the CA for os.mbed.com
 *
 * To add more than one root, just concatenate them.
 */
static const char SSL_CA_PEM[] = "-----BEGIN CERTIFICATE-----\n"
    "MIICUjCCAdegAwIBAgIJAMFD4n5iQ8zoMAoGCCqGSM49BAMCMD4xCzAJBgNVBAYT\r\n"
    "Ak5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBF\r\n"
    "QyBDQTAeFw0xMzA5MjQxNTQ5NDhaFw0yMzA5MjIxNTQ5NDhaMD4xCzAJBgNVBAYT\r\n"
    "Ak5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBF\r\n"
    "QyBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABMPaKzRBN1gvh1b+/Im6KUNLTuBu\r\n"
    "ww5XUzM5WNRStJGVOQsj318XJGJI/BqVKc4sLYfCiFKAr9ZqqyHduNMcbli4yuiy\r\n"
    "aY7zQa0pw7RfdadHb9UZKVVpmlM7ILRmFmAzHqOBoDCBnTAdBgNVHQ4EFgQUnW0g\r\n"
    "JEkBPyvLeLUZvH4kydv7NnwwbgYDVR0jBGcwZYAUnW0gJEkBPyvLeLUZvH4kydv7\r\n"
    "NnyhQqRAMD4xCzAJBgNVBAYTAk5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UE\r\n"
    "AxMTUG9sYXJzc2wgVGVzdCBFQyBDQYIJAMFD4n5iQ8zoMAwGA1UdEwQFMAMBAf8w\r\n"
    "CgYIKoZIzj0EAwIDaQAwZgIxAMO0YnNWKJUAfXgSJtJxexn4ipg+kv4znuR50v56\r\n"
    "t4d0PCu412mUC6Nnd7izvtE2MgIxAP1nnJQjZ8BWukszFQDG48wxCCyci9qpdSMv\r\n"
    "uCjn8pwUOkABXK8Mss90fzCfCEOtIA==\r\n"
    "-----END CERTIFICATE-----\r\n";
#endif

struct dtls_client_t {
    struct my_timer_t timer;
    UDPSocket *udpsocket;
    SocketAddress *sockaddr;

    char buffer[RECV_BUFFER_SIZE]; /**< The response buffer */
    size_t bpos;                   /**< The current offset in the response buffer */
    volatile bool got200;          /**< Status flag for HTTPS 200 */
    volatile bool gothello;        /**< Status flag for finding the test string */
    volatile bool disconnected;
    volatile bool request_sent;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt cacert;
#endif
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
};

#if defined(MBEDTLS_DEBUG_C)
#if DEBUG_LEVEL > 0
/**
 * Certificate verification callback for mbed TLS
 * Here we only use it to display information on each cert in the chain
 */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    const uint32_t buf_size = 1024;
    char *buf = new char[buf_size];
    (void) data;

    mbedtls_printf("\nVerifying certificate at depth %d:\n", depth);
    mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
    mbedtls_printf("%s", buf);

    if (*flags == 0)
        mbedtls_printf("No verification issue for this certificate\n");
    else
    {
        mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
        mbedtls_printf("%s\n", buf);
    }

    delete[] buf;
    return 0;
}
#endif
#endif
#endif

/**
 * Helper for pretty-printing mbed TLS error codes
 */
static void print_mbedtls_error(const char *name, int err) {
#if defined(MBEDTLS_DEBUG_C)
    static char buf[128];
    mbedtls_strerror(err, buf, sizeof (buf));
    mbedtls_printf("%s() failed: -0x%04x (%d): %s\n", name, -err, err, buf);
#endif
}

/**
 * Receive callback for mbed TLS
 */
static int ssl_recv(void *ctx, unsigned char *buf, size_t len) {
    dtls_client_t *c = (dtls_client_t *) ctx;
    int recv = -1;
    //recv = c->udpsocket->recvfrom(c->sockaddr, buf, len); // XXX this one? or other?
    recv = c->udpsocket->recvfrom(NULL, buf, len);

    if (NSAPI_ERROR_WOULD_BLOCK == recv) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }else if (recv < 0) {
        mbedtls_printf("Socket recv error %d\n", recv);
        return -1;
    } else {
        return recv;
    }
}

/**
 * Send callback for mbed TLS
 */
static int ssl_send(void *ctx, const unsigned char *buf, size_t len) {
    dtls_client_t *c = (dtls_client_t *) ctx;
    int size = -1;
    size = c->udpsocket->sendto(*c->sockaddr, buf, len);

    if (NSAPI_ERROR_WOULD_BLOCK == size) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    } else if (size < 0) {
        mbedtls_printf("Socket send error %d\n", size);
        return -1;
    } else {
        return size;
    }
}

#if 0
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
static void unhexify(char *dst, char *src)
{
    /*
     * Unhexify the pre-shared key if any is given
     */
    if( strlen( src ) )
    {
        unsigned char c;
        size_t j;

        if( strlen( src ) % 2 != 0 )
        {
            mbedtls_printf("pre-shared key not valid hex\n");
            goto exit;
        }

        c->psk_len = strlen( src ) / 2;

        for( j = 0; j < strlen( src ); j += 2 )
        {
            c = src[j];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                mbedtls_printf("pre-shared key not valid hex\n");
                goto exit;
            }
            dst[ j / 2 ] = c << 4;

            c = src[j + 1];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                mbedtls_printf("pre-shared key not valid hex\n");
                goto exit;
            }
            dst[ j / 2 ] |= c;
        }
    }

    return;
exit:
    for(;;);
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
#endif

static void int_done(void *)
{
}

static void fin_done(void *)
{
}

static void do_nothing(void *)
{
}

static void my_delay_init(struct my_timer_t *timer)
{
    memset(&timer->int_timer_attr, 0, sizeof(timer->int_timer_attr));
    memset(&timer->fin_timer_attr, 0, sizeof(timer->fin_timer_attr));

    memset(&timer->int_timer_mem, 0, sizeof(timer->int_timer_mem));
    memset(&timer->fin_timer_mem, 0, sizeof(timer->fin_timer_mem));

    timer->int_timer_attr.cb_mem = &timer->int_timer_mem;
    timer->int_timer_attr.cb_size = sizeof(timer->int_timer_mem);
    timer->fin_timer_attr.cb_mem = &timer->fin_timer_mem;
    timer->fin_timer_attr.cb_size = sizeof(timer->fin_timer_mem);

    timer->int_timer_id = osTimerNew(do_nothing, osTimerOnce, NULL, &timer->int_timer_attr);
    timer->fin_timer_id = osTimerNew(do_nothing, osTimerOnce, NULL, &timer->fin_timer_attr);

    if (timer->int_timer_id == NULL || timer->fin_timer_id == NULL) {
        /* Error */
        mbedtls_printf("couldn't create timers\n");
        for (;;);
    }

    timer->cancelled = 0;
}

static void my_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
    my_timer_t *timer = (my_timer_t *) data;
    timer->int_ms = int_ms;
    timer->fin_ms = fin_ms;

    if (fin_ms == 0) {
        timer->cancelled = 1;
        osTimerStop(timer->int_timer_id);
        osTimerStop(timer->fin_timer_id);
    } else {
        /* Start the timers now? I suppose so. */
        /* XXX Note that these timers work with "ticks" which may not be
         * milliseconds. The Mbed OS class doesn't do any conversion... could
         * be bug or we could be okay, I guess. Mbed OS may be configured to
         * always use 1 tick == 1 ms. */
        osTimerStart(timer->int_timer_id, timer->int_ms);
        osTimerStart(timer->fin_timer_id, timer->fin_ms);
        timer->cancelled = 0;
    }

    /* XXX Note sure what the documentation for mbedtls_ssl_set_timer_t is on
     * about: refers to calling mbedtls_ssl_handshake from an event that is
     * fired when the final delay is passed-- but I don't see other timer
     * implementations doing this. Apocrypha? */
}

static int my_get_delay(void *data)
{
    my_timer_t *timer = (my_timer_t *) data;
    int ret;

    if (timer->cancelled) {
        /* Cancelled (fin_ms == 0) */
        ret = -1;
    } else if (osTimerIsRunning(timer->fin_timer_id) == 0) {
        /* Final delay has passed. */
        /* XXX What should happen if final delay passed but not intermediate?
         * */
        ret = 2;
    } else if (osTimerIsRunning(timer->int_timer_id) == 0) {
        /* Only the intermediate delay has passed. */
        ret = 1;
    } else {
        /* None of the delays have passed. */
        ret = 0;
    }

    return ret;
}

#if defined(MBEDTLS_DEBUG_C)
/**
 * Debug callback for mbed TLS
 * Just prints on the USB serial port
 */
static void my_debug(void *ctx, int level, const char *file, int line,
                     const char *str)
{
    const char *p, *basename;
    (void) ctx;

    /* Extract basename from file */
    for(p = basename = file; *p != '\0'; p++) {
        if(*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
}
#endif

/**
 * Initialize the UDP socket. Sets up event handlers and flags.
 *
 * @param[in] domain The domain name to fetch from
 * @param[in] port The port of the HTTPS server
 */
static void init(struct dtls_client_t *c, NetworkInterface *net_iface)
{
    memset(c, 0, sizeof(*c));
    c->gothello = false;
    c->got200 = false;
    c->bpos = 0;
    c->request_sent = 0;
    c->disconnected = false; /* XXX Not always? */
    c->udpsocket = new UDPSocket();
    c->udpsocket->set_blocking(false);
    c->buffer[RECV_BUFFER_SIZE - 1] = 0;

    c->sockaddr = new SocketAddress(NS_SERVER_ADDR, SERVER_PORT);
    nsapi_error_t err = c->udpsocket->open(net_iface);
    if (err) {
        printf("UDP socket open failed: %d\n", err);
        for(;;);
    }
    c->udpsocket->set_blocking(false); // XXX again?

    my_delay_init(&c->timer);

    mbedtls_ssl_init(&c->ssl);
    mbedtls_ssl_config_init(&c->conf);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg(&c->conf, my_debug, NULL);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_entropy_init(&c->entropy);
    mbedtls_ctr_drbg_init(&c->ctr_drbg);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_init(&c->cacert);
#endif
}

/**
 * HelloHTTPS Desctructor
 */
static void deinit(struct dtls_client_t *c) {
    mbedtls_entropy_free(&c->entropy);
    mbedtls_ctr_drbg_free(&c->ctr_drbg);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_free(&c->cacert);
#endif
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->conf);
    delete c->udpsocket;
}

/**
 * Start the test.
 *
 * Starts by clearing test flags, then resolves the address with DNS.
 *
 * @param[in] path The path of the file to fetch from the HTTPS server
 * @return SOCKET_ERROR_NONE on success, or an error code on failure
 */
static void startTest(struct dtls_client_t *c) {
    int retry_left = MAX_RETRY;

    /*
     * Initialize TLS-related stuf.
     */
    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(&c->ctr_drbg, mbedtls_entropy_func, &c->entropy,
                      (const unsigned char *) DRBG_PERS,
                      sizeof (DRBG_PERS))) != 0) {
        print_mbedtls_error("mbedtls_ctr_drbg_seed", ret);
        return;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if ((ret = mbedtls_x509_crt_parse(&c->cacert, (const unsigned char *) SSL_CA_PEM,
                       sizeof (SSL_CA_PEM))) != 0) {
        print_mbedtls_error("mbedtls_x509_crt_parse", ret);
        return;
    }
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if( ( ret = mbedtls_ssl_conf_psk( &c->conf, my_psk, sizeof(my_psk), (const unsigned char *) psk_identity, sizeof(psk_identity) - 1) ) != 0 )
    {
        print_mbedtls_error("mbedtls_ssl_conf_psk", ret);
        return;
    }
#endif

    if ((ret = mbedtls_ssl_config_defaults(&c->conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
        return;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_conf_ca_chain(&c->conf, &c->cacert, NULL);
#endif
    mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &c->ctr_drbg);

    /* It is possible to disable authentication by passing
     * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
     */
    mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if defined(MBEDTLS_DEBUG_C)
#if DEBUG_LEVEL > 0
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_conf_verify(&c->conf, my_verify, NULL);
#endif
#endif
#endif
    mbedtls_ssl_conf_min_version( &c->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3 );
    mbedtls_ssl_conf_max_version( &c->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3 );
    //opt.mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_512;
    //if( ( ret = mbedtls_ssl_conf_max_frag_len( &conf, opt.mfl_code ) ) != 0 )

    if ((ret = mbedtls_ssl_setup(&c->ssl, &c->conf)) != 0) {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        return;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_set_hostname(&c->ssl, "localhost");
#endif

    mbedtls_ssl_set_bio(&c->ssl, static_cast<void *>(c),
                               ssl_send, ssl_recv, NULL );
    mbedtls_ssl_set_timer_cb( &c->ssl, &c->timer, my_set_delay, my_get_delay );

   /* Start the handshake, the rest will be done in onReceive() */
    mbedtls_printf("Starting the TLS handshake...\n");
    do {
        ret = mbedtls_ssl_handshake(&c->ssl);
    } while (/*ret != 0 && */(ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_handshake", ret);
        return;
    }

    /* Fill the request buffer */
    c->bpos = snprintf(c->buffer, sizeof(c->buffer) - 1,
                     "GET %s HTTP/1.1\nHost: %s\n\n", "/", SERVER_ADDR);

send_request:
    size_t offset = 0;
    do {
        ret = mbedtls_ssl_write(&c->ssl,
                                (const unsigned char *) c->buffer + offset,
                                c->bpos - offset);
        if (ret > 0)
          offset += ret;
    } while (offset < c->bpos && (ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_write", ret);
        return;
    }

    /* It also means the handshake is done, time to print info */
    printf("TLS connection to %s established\n", SERVER_ADDR);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    const uint32_t buf_size = 1024;
    char *buf = new char[buf_size];
    mbedtls_x509_crt_info(buf, buf_size, "    ",
                    mbedtls_ssl_get_peer_cert(&c->ssl));
    mbedtls_printf("Server certificate:\n%s", buf);

    uint32_t flags = mbedtls_ssl_get_verify_result(&c->ssl);
    if( flags != 0 )
    {
        mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", flags);
        printf("Certificate verification failed:\n%s\n", buf);
    }
    else
        printf("Certificate verification passed\n\n");
#endif


#if 0
    /* Read data out of the socket */
    offset = 0;
    do {
        ret = mbedtls_ssl_read(&c->ssl, (unsigned char *) c->buffer + offset,
                               sizeof(c->buffer) - offset - 1);
        if (ret > 0)
          offset += ret;

        /* Check each of the flags */
        c->buffer[offset] = 0;
        c->got200 = c->got200 || strstr(c->buffer, HTTPS_OK_STR) != NULL;
        c->gothello = c->gothello || strstr(c->buffer, HTTPS_HELLO_STR) != NULL;
    } while ( (!c->got200 || !c->gothello) &&
            (ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_read", ret);
        delete[] buf;
        return;
    }
    c->bpos = static_cast<size_t>(offset);

    c->buffer[c->bpos] = 0;
#else

    /* Read data out of the socket */
    offset = 0;
    memset( c->buffer, 0, sizeof( c->buffer ) );

    do {
        ret = mbedtls_ssl_read( &c->ssl, (unsigned char *) c->buffer + offset, sizeof(c->buffer) - offset - 1 );

        if (ret > 0)
            offset += ret;

        /* XXX Check each of the flags */
        c->buffer[offset] = 0;
    } while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret < 0 )
    {
        switch( ret )
        {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                mbedtls_printf( " timeout\n" );
                if( retry_left-- > 0 )
                    goto send_request;
                goto exit;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                mbedtls_printf( " connection was closed gracefully\n" );
                ret = 0;
                break;

            default:
                print_mbedtls_error("mbedtls_ssl_read", ret);
                goto exit;
        }
    }

    c->bpos = static_cast<size_t>(offset);
    c->buffer[c->bpos] = '\0';
    mbedtls_printf(" %d bytes read\n\n", c->bpos);
    ret = 0;
#endif

    /* Print status messages */
    mbedtls_printf("HTTPS: Received %d chars from server\n", c->bpos);
    //mbedtls_printf("HTTPS: Received 200 OK status ... %s\n", c->got200 ? "[OK]" : "[FAIL]");
    //mbedtls_printf("HTTPS: Received '%s' status ... %s\n", HTTPS_HELLO_STR, c->gothello ? "[OK]" : "[FAIL]");
    mbedtls_printf("HTTPS: Received message:\n\n");
    mbedtls_printf("%s", c->buffer);

exit:
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    delete[] buf;
#endif
    return;
}

/**
 * The main loop of the HTTPS Hello World test
 */
int main(int argc, char *argv[]) {

#if MBED_HEAP_STATS_ENABLED
    mbed_stats_heap_get(&heap_stats);
    printf("Current heap: %lu\n", heap_stats.current_size);
    printf("Max heap size: %lu\n", heap_stats.max_size);
#endif


    /* The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out. */

    /* Inititalise with DHCP, connect, and start up the stack */
    EthernetInterface eth_iface;
    eth_iface.connect();
    mbedtls_printf("Using Ethernet LWIP\n");
    const char *ip_addr = eth_iface.get_ip_address();
    if (ip_addr) {
        mbedtls_printf("Client IP Address is %s\n", ip_addr);
    } else {
        mbedtls_printf("No Client IP Address\n");
    }

    //mbedtls_ssl_session saved_session;
    dtls_client_t *client = (dtls_client_t *) malloc(sizeof(*client));
    init(client, &eth_iface);

#if MBED_HEAP_STATS_ENABLED
    mbed_stats_heap_get(&heap_stats);
    printf("Current heap after init: %lu\n", heap_stats.current_size);
    printf("Max heap size after init: %lu\n", heap_stats.max_size);
#endif

    startTest(client);

#if MBED_HEAP_STATS_ENABLED
    mbed_stats_heap_get(&heap_stats);
    printf("Current heap after test: %lu\n", heap_stats.current_size);
    printf("Max heap size after test: %lu\n", heap_stats.max_size);
#endif

    deinit(client);
    free(client);
#if MBED_HEAP_STATS_ENABLED
    mbed_stats_heap_get(&heap_stats);
    printf("Current heap final: %lu\n", heap_stats.current_size);
    printf("Max heap size final: %lu\n", heap_stats.max_size);
#endif

    for(;;);
}
