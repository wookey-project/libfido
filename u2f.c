#include "u2f.h"
#include "fido.h"

mbed_error_t u2f_handle_request(u2f_cmd_t *u2f_cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    if (u2f_cmd == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    switch (u2f_cmd->cmd) {
        case U2FHID_INIT:
        {
            log_printf("[U2F] received U2F INIT\n");
            break;
        }
        case U2FHID_PING:
        {
            log_printf("[U2F] received U2F PING\n");
            break;
        }
        case U2FHID_MSG:
        {
            log_printf("[U2F] received U2F MSG\n");
            break;
        }
        case U2FHID_ERROR:
        {
            log_printf("[U2F] received U2F ERROR\n");
            break;
        }
        case U2FHID_WINK:
        {
            log_printf("[U2F] received U2F WINK\n");
            break;
        }
        case U2FHID_LOCK:
        {
            log_printf("[U2F] received U2F LOCK\n");
            break;
        }
        default:
            log_printf("[U2F] Unkown cmd %d\n", u2f_cmd->cmd);
            break;
    }
err:
    return errcode;
}
