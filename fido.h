/*
 *
 * copyright 2019 the wookey project team <wookey@ssi.gouv.fr>
 *   - ryad     benadjila
 *   - arnauld  michelizza
 *   - mathieu  renard
 *   - philippe thierry
 *   - philippe trebuchet
 *
 * this package is free software; you can redistribute it and/or modify
 * it under the terms of the gnu general public license as published
 * the free software foundation; either version 3 of the license, or (at
 * ur option) any later version.
 *
 * this package is distributed in the hope that it will be useful, but without any
 * warranty; without even the implied warranty of merchantability or fitness for a
 * particular purpose. see the gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license along
 * with this package; if not, write to the free software foundation, inc., 51
 * franklin st, fifth floor, boston, ma 02110-1301 usa
 *
 */
#ifndef __U2F_FIDO_H__
#define __U2F_FIDO_H__

#include "autoconf.h"
#include "libc/types.h"
#include "api/libfido.h"

#if CONFIG_USR_LIB_FIDO_DEBUG > 0
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif


#define U2F_REGISTER                            0x01
#define U2F_AUTHENTICATE                        0x02
#define U2F_VERSION                             0x03
#define U2F_VENDOR_SPECIFIC_MIN                 0x40
#define U2F_VENDOR_SPECIFIC_MAX                 0xbf

#define CHECK_ONLY                              0x07
#define ENFORCE_USER_PRESENCE_AND_SIGN          0x03
#define DONT_ENFORCE_USER_PRESENCE_AND_SIGN     0x08

#define NO_ERROR                                0x00
#define REQUIRE_TEST_USER_PRESENCE              0x01
#define INVALID_KEY_HANDLE                      0x02
#define WRONG_LENGTH                            0x03

/* Our Key handle size */
#define KEY_HANDLE_SIZE				64
/* Our challenge parameter size */
#define CHALLENGE_PARAMETER_SIZE		32
/* Our application parameter size */
#define APPLICATION_PARAMETER_SIZE		32
/* Our public key X and Y sizes */
#define PUB_KEY_X_SIZE				32
#define PUB_KEY_Y_SIZE				32
#define PUB_KEY_Z_SIZE				32
/* Our private key size */
#define PRIV_KEY_SIZE				32
/* Our ECDSA signature r and s sizes */
#define SIG_R_SIZE				32
#define SIG_S_SIZE				32

#endif /* __U2F_FIDO_H__ */
