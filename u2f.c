#include "u2f.h"
#include "fido.h"
#include "channel.h"
#include "libc/string.h"
#include "libusbhid.h"


typedef union {
    ctaphid_resp_header_t     init;
    ctaphid_resp_seq_header_t seq;
} ctaphid_resp_headers_t;

/* a response can be seen as a header with a trailing data
 * or a uint8_t data flow of upto 64 bytes len */
typedef union {
    ctaphid_resp_headers_t  header;
    uint8_t    data[64]; /* all responses are padded to 64 bytes */
} ctaphid_resp_t;


/*
 * A CTAPHID response may be bigger than the CTAPHID Out endpoint MPSize.
 * If it does, this function is responsible for fragmenting the response
 * into successive blocks to which a ctaphid_resp_msg_t header is added,
 * and then pushed to the endpoint. The first frame sent is always a CTAPHID INIT
 * frame (with CID, cmd, bcnt). Others successive ones are CTAPHID CONT
 * (cid and sequence identifier, no cmd, no bcnt - i.e. bcnt is flow global)
 */
static mbed_error_t ctaphid_send_response(uint8_t *resp, uint16_t resp_len, uint32_t cid, uint8_t cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint8_t sequence = 0;
    /* sanitize first */
    if (resp == NULL) {
        log_printf("[CTAPHID] invalid response buf %x\n", resp);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (resp_len == 0) {
        log_printf("[CTAPHID] invalid response len %x\n", resp_len);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (resp_len > 256) {
        log_printf("[CTAPHID] invalid response len %x\n", resp_len);
        /* data[] field is defined as upto 256 bytes length. This test is also
         * a protection against integer overflow in the idx++ loop below */
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

    /* we know that the effective response buffer is upto ctaphid_resp_header_t + 256 bytes
     * (defined in the FIDO U2F standard). Finally, we can only push upto 64 bytes at a time.
     */
    /* total response content to handle */
    uint32_t pushed_bytes = 0;

    ctaphid_resp_t full_resp = { 0 };
    uint32_t offset = 0;
    uint32_t max_resp_len = 0;
    do {
        /* cleaning potential previous frames */
        memset(&full_resp.data[0], 0x0, 64);
        if (pushed_bytes == 0) {
            log_printf("[CTAPHID] first response chunk\n");
            /* first pass */
            full_resp.header.init.cid = cid;
            full_resp.header.init.cmd = cmd;
            full_resp.header.init.bcnth = (resp_len & 0xff00) >> 8;
            full_resp.header.init.bcntl = (resp_len & 0xff);
            offset = sizeof(ctaphid_resp_header_t);
            max_resp_len = CTAPHID_FRAME_MAXLEN - offset;
        } else {
            log_printf("[CTAPHID] sequence response chunk\n");
            full_resp.header.seq.cid = cid;
            full_resp.header.seq.seq = sequence;
            sequence++;
            offset = sizeof(ctaphid_resp_seq_header_t);
            max_resp_len = CTAPHID_FRAME_MAXLEN - offset;
        }
        /*now handle effective response content */
        uint32_t idx = pushed_bytes;
        while (idx < resp_len && idx <= max_resp_len) {
            full_resp.data[offset] = resp[idx];
            offset++;
            idx++;
        }
        /* here, full_resp is ready to be sent. Its size can be 64 bytes length
         * or less (offset value). We send the current report chunk here. */
        log_printf("[CTAPHID] Sending report chunk (offset %d)\n", idx);
        usbhid_send_report(fido_get_usbhid_handler(), &(full_resp.data[0]), USBHID_OUTPUT_REPORT, 0);
        /* updated pushed_bytes count */
        pushed_bytes = idx;
    } while (pushed_bytes < resp_len);

    /* here, all chunk(s) has been sent. All are upto CTAPHID_FRAME_MAXLEN. The total length
     * is defined by resp_len and set in the first chunk header. */

err:
    return errcode;
}

static mbed_error_t handle_rq_init(const ctaphid_cmd_t* cmd)
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
    ctaphid_resp_init_t init_resp = { 0 };
    for (uint8_t i = 0; i < 8; ++i) {
      init_resp.nonce[i] = cmd->data[i];
    }

    init_resp.chanid = newcid;
    init_resp.proto_version = USBHID_PROTO_VERSION;
    init_resp.major_n = 0;
    init_resp.minor_n = 0;
    init_resp.build_n = 0;
    init_resp.capa_f = U2FHID_CAPA_WINK;

    log_printf("[CTAPHID][INIT] Sending back response\n");
    errcode = ctaphid_send_response((uint8_t*)&init_resp, sizeof(ctaphid_resp_init_t), curcid, U2FHID_INIT|0x80);
err:
    return errcode;
}

mbed_error_t u2f_handle_request(const ctaphid_cmd_t *ctaphid_cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint8_t cmd;
    if (ctaphid_cmd == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if ((ctaphid_cmd->cmd & 0x80) == 0) {
        log_printf("[CTAPHID] CMD bit 7 must always be set\n");
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    /* cleaning bit 7 (always set, see above) */
    cmd = ctaphid_cmd->cmd & 0x7f;
    switch (cmd) {
        case U2FHID_INIT:
        {
            log_printf("[CTAPHID] received U2F INIT\n");
            errcode = handle_rq_init(ctaphid_cmd);
            break;
        }
        case U2FHID_PING:
        {
            log_printf("[CTAPHID] received U2F PING\n");
            break;
        }
        case U2FHID_MSG:
        {
            log_printf("[CTAPHID] received U2F MSG\n");
            break;
        }
        case U2FHID_ERROR:
        {
            log_printf("[CTAPHID] received U2F ERROR\n");
            break;
        }
        case U2FHID_WINK:
        {
            log_printf("[CTAPHID] received U2F WINK\n");
            break;
        }
        case U2FHID_LOCK:
        {
            log_printf("[CTAPHID] received U2F LOCK\n");
            break;
        }
        default:
            log_printf("[CTAPHID] Unkown cmd %d\n", ctaphid_cmd);
            break;
    }
err:
    return errcode;
}
