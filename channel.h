#ifndef CHANNEL_H_
#define CHANNEL_H_
#include "autoconf.h"
#include "libc/types.h"
#include "u2f.h"

mbed_error_t channel_create(uint32_t *newcid);

bool channel_exists(uint32_t cid);

#endif/*!CHANNEL_H_*/
