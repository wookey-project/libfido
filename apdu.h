#ifndef APDU_H_
#define APDU_H_
#include "autoconf.h"
#include "libc/types.h"

mbed_error_t apdu_handle_request(uint8_t *data, uint16_t *data_len);

#endif/*!APDU_H_*/
