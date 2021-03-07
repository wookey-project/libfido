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

/*
 * wait for user presence event (typically a button) and return TRUE if
 * button pushed. Otherwhise return FALSE.
 */
typedef bool (*userpresence_request_cb_t)(uint16_t timeout_ms);

mbed_error_t u2f_fido_initialize(userpresence_request_cb_t userpresence_cb);

mbed_error_t u2f_fido_handle_cmd(uint32_t metadata,
                                 const uint8_t * msg, uint16_t len_in,
                                 uint8_t *resp, uint16_t *len_out);


#endif/*!LIBFIDO_H_*/
