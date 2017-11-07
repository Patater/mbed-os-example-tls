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

/* Add back in CBC, and remove CCM */
#define MBEDTLS_CIPHER_MODE_CBC
#undef MBEDTLS_CCM_C

#undef MBEDTLS_SSL_CIPHERSUITES
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256
