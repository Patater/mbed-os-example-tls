/*
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

#include "mbedtls_base.h"

#undef MBEDTLS_CCM_C

#undef MBEDTLS_SSL_CIPHERSUITES
//#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_PSK_DHE_WITH_AES_128_CCM_8
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
// TLS_PSK_ECDHE_WITH_AES_128_CCM_8 <3

/* We probably need more than this to be robust, or support outgoing
 * fragmentation properly. */
#undef MBEDTLS_SSL_MAX_CONTENT_LEN
#define MBEDTLS_SSL_MAX_CONTENT_LEN 512

//#define MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED

/* Add back in ECDH */
#define MBEDTLS_ECDH_C
#  define MBEDTLS_ECP_C
#    define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#    define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#    define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#    define MBEDTLS_ECP_NIST_OPTIM
