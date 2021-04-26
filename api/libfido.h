/*
 *
 * Copyright 2019 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef LIBFIDO_H_
#define LIBFIDO_H_

#include "autoconf.h"
#include "libc/types.h"

/* Our Key handle size */
#define FIDO_KEY_HANDLE_SIZE                         64
/* Our challenge parameter size */
#define FIDO_CHALLENGE_PARAMETER_SIZE                32
/* Our application parameter size */
#define FIDO_APPLICATION_PARAMETER_SIZE              32
/* Our private key size */
#define FIDO_PRIV_KEY_SIZE                           32


typedef enum {
    U2F_FIDO_REGISTER     = 0,
    U2F_FIDO_AUTHENTICATE = 1,
} u2f_fido_action;

/*
 * wait for user presence event (typically a button) and return TRUE if
 * button pushed. Otherwhise return FALSE.
 */
typedef bool (*userpresence_request_cb_t)(uint16_t timeout_ms, uint8_t *application_parameter, u2f_fido_action action);

mbed_error_t u2f_fido_initialize(userpresence_request_cb_t userpresence_cb);

mbed_error_t u2f_fido_handle_cmd(uint32_t metadata,
                                 const uint8_t * msg, uint16_t len_in,
                                 uint8_t *resp, uint16_t *len_out);

/* Backend callbacks: statically linked, prototypes set here */
int callback_fido_register(const uint8_t *app_data, uint16_t app_data_len, uint8_t *key_handle, uint16_t *key_handle_len, uint8_t *ecdsa_priv_key, uint16_t *ecdsa_priv_key_len);
int callback_fido_authenticate(const uint8_t *app_data, uint16_t app_data_len, const uint8_t *key_handle, uint16_t key_handle_len, uint8_t *ecdsa_priv_key, uint16_t *ecdsa_priv_key_len, uint8_t check_only);
#if 0
typedef int (*cb_fido_register_t)(const uint8_t *app_data, uint16_t app_data_len, uint8_t *key_handle, uint16_t *key_handle_len, uint8_t *ecdsa_priv_key, uint16_t *ecdsa_priv_key_len);
typedef int (*cb_fido_authenticate_t)(const uint8_t *app_data, uint16_t app_data_len, const uint8_t *key_handle, uint16_t key_handle_len, uint8_t *ecdsa_priv_key, uint16_t *ecdsa_priv_key_len, uint8_t check_only);
#endif

#endif/*!LIBFIDO_H_*/
