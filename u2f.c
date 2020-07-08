#include "u2f.h"
#include "fido.h"
#include "channel.h"
#include "libc/string.h"
#include "libusbhid.h"


typedef union {
    u2f_resp_init_t init;
} u2f_resp_list_t;

typedef struct __packed {
   u2f_resp_msg_t  resp_header;
   u2f_resp_list_t resp_body;
} u2f_resp_t;

typedef union {
    u2f_resp_t resp;
    uint8_t    data[64]; /* all responses are padded to 64 bytes */
} u2f_padded_resp_t;

static u2f_padded_resp_t u2f_resp;

static mbed_error_t u2f_handle_rq_init(const u2f_cmd_t* cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint32_t curcid;
    uint32_t newcid;
    /* CTAPHID level sanitation */
    /* endianess... */
    uint16_t bcnt = (cmd->bcnth << 8) | cmd->bcntl;
    if (bcnt != 8) {
        log_printf("[CTAPHID] CTAPHID_INIT pkt len must be 8, found %d\n", bcnt);
        log_printf("[CTAPHID] bcnth: %x, bcntl: %x\n", cmd->bcnth, cmd->bcntl);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (cmd->cid == 0) {
        log_printf("[CTAPHID] CTAPHID_INIT CID must be nonzero\n");
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    curcid = cmd->cid;
    if (curcid == U2FHID_BROADCAST_CID) {
        /* new channel request */
        channel_create(&newcid);
        log_printf("[CTAPHID][INIT] New CID: %f\n", newcid);
    } else {
        newcid = curcid;
    }
    /* zeroify response, includding potential padding */
    memset(&(u2f_resp.data[0]), 0x0, 64*sizeof(uint8_t));
    u2f_resp.resp.resp_header.cid = curcid;
    /* TODO init mode mark should be set using a macro*/
    u2f_resp.resp.resp_header.cmd = U2FHID_INIT | 0x80;
    /* bcnt field endianess encoding/decoding should be made through macros */
    u2f_resp.resp.resp_header.bcnth = 0;
    u2f_resp.resp.resp_header.bcntl = (sizeof(u2f_resp_init_t) - 6); /*6 is offsetof(bcnt) */
    for (uint8_t i = 0; i < 8; ++i) {
      u2f_resp.resp.resp_body.init.nonce[i] = cmd->data[i];
    }

    u2f_resp.resp.resp_body.init.chanid = newcid;
    u2f_resp.resp.resp_body.init.proto_version = USBHID_PROTO_VERSION;
    u2f_resp.resp.resp_body.init.major_n = 0;
    u2f_resp.resp.resp_body.init.minor_n = 0;
    u2f_resp.resp.resp_body.init.build_n = 0;
    u2f_resp.resp.resp_body.init.capa_f = U2FHID_CAPA_WINK;

    log_printf("[CTAPHID][INIT] Sending back response\n");
    usbhid_send_report(fido_get_usbhid_handler(), &(u2f_resp.data[0]), 0);
err:
    return errcode;
}

mbed_error_t u2f_handle_request(const u2f_cmd_t *u2f_cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint8_t cmd;
    if (u2f_cmd == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if ((u2f_cmd->cmd & 0x80) == 0) {
        log_printf("[U2F] CMD bit 7 must always be set\n");
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    /* cleaning bit 7 (always set, see above) */
    cmd = u2f_cmd->cmd & 0x7f;
    switch (cmd) {
        case U2FHID_INIT:
        {
            log_printf("[U2F] received U2F INIT\n");
            errcode = u2f_handle_rq_init(u2f_cmd);
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
            log_printf("[U2F] Unkown cmd %d\n", cmd);
            break;
    }
err:
    return errcode;
}
