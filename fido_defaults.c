#include "api/libfido.h"


/* XXX: For now we use a simple global counter in SRAM for tests
 * These are weak functions that should be overload by effective CTR handling backend
 * for storage
 */
static volatile uint32_t fido_global_counter = 0;
 __attribute__((weak)) uint32_t fido_get_auth_counter(void) {
    return fido_global_counter;
}

__attribute__((weak)) void fido_inc_auth_counter(const uint8_t *appid __attribute__((unused)), uint16_t appid_len __attribute__((unused))) {
    fido_global_counter++;
}
