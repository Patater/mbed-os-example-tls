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

#if !defined(MBEDTLS_ENTROPY_HARDWARE_ALT) && \
    !defined(MBEDTLS_ENTROPY_NV_SEED) && !defined(MBEDTLS_TEST_NULL_ENTROPY)
#error "This hardware does not have an entropy source."
#endif /* !MBEDTLS_ENTROPY_HARDWARE_ALT && !MBEDTLS_ENTROPY_NV_SEED &&
        * !MBEDTLS_TEST_NULL_ENTROPY */

#if !defined(MBEDTLS_SHA1_C)
#define MBEDTLS_SHA1_C
#endif

/*
 *  This value is sufficient for handling 2048 bit RSA keys.
 *
 *  Set this value higher to enable handling larger keys, but be aware that this
 *  will increase the stack usage.
 */
#define MBEDTLS_MPI_MAX_SIZE        256

#define MBEDTLS_MPI_WINDOW_SIZE     1

#if defined(TARGET_STM32F439xI) && defined(MBEDTLS_CONFIG_HW_SUPPORT)
#undef MBEDTLS_AES_ALT
#endif /* TARGET_STM32F439xI && MBEDTLS_CONFIG_HW_SUPPORT */

/* Minimize to semi-minimal base */
#define MBEDTLS_CIPHER_MODE_CBC // XXX TODO checkconfig needs to say this is needed for CCM-- but we use ECB for CCM? bug?
#undef MBEDTLS_ECP_DP_SECP256R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#undef MBEDTLS_ECP_DP_CURVE25519_ENABLED
#undef MBEDTLS_ECP_NIST_OPTIM
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#undef MBEDTLS_PK_RSA_ALT_SUPPORT
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION
#undef MBEDTLS_ECDH_C
#undef MBEDTLS_ECDSA_C
#undef MBEDTLS_ECP_C
#undef MBEDTLS_GCM_C
#undef MBEDTLS_PEM_PARSE_C
#undef MBEDTLS_PK_C
#undef MBEDTLS_PK_PARSE_C
#undef MBEDTLS_PK_WRITE_C
#undef MBEDTLS_RSA_C
#undef MBEDTLS_SHA512_C
#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_X509_CRL_PARSE_C


/* XXX maybe broken... */
#define MBEDTLS_SSL_MAX_CONTENT_LEN 512

// XXX TODO save some space
#undef MBEDTLS_SSL_SRV_C

#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8
//#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

#undef MBEDTLS_ERROR_C
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_ERROR_STRERROR_DUMMY
#undef MBEDTLS_VERSION_FEATURES
#undef MBEDTLS_DEBUG_C

/* Turn off hw-acceleration */
#undef MBEDTLS_AES_ALT
#undef MBEDTLS_SHA1_ALT
#undef MBEDTLS_SHA256_ALT
#undef MBEDTLS_MD7_ALT
