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

#include "libc/types.h"
#include "libc/string.h"
#include "libusbhid.h"
#include "api/libfido.h"
#include "u2f.h"
#include "fido.h"


#define FIDO_POLL_TIME      5 /* FIDO HID interface definition: Poll-time=5ms */
#define FIDO_DESCRIPOR_NUM  1 /* To check */

/* Some USAGE attributes are not HID level defines but 'vendor specific'. This is the case for
 * the FIDO usage page, which is a vendor specific usage page, defining its own, cusom USAGE tag values */
#define FIDO_USAGE_FIDO_U2FHID   0x01
#define FIDO_USAGE_FIDO_DATA_IN  0x20
#define FIDO_USAGE_FIDO_DATA_OUT 0x21
#define FIDO_USAGE_PAGE_BYTE1    0xd0
#define FIDO_USAGE_PAGE_BYTE0    0xf1

typedef enum {
    U2F_CMD_BUFFER_STATE_EMPTY,
    U2F_CMD_BUFFER_STATE_BUFFERING,
    U2F_CMD_BUFFER_STATE_COMPLETE,
} fido_u2f_buffer_state_t;


/* the current FIDO U2F context */
typedef struct {
    bool                          ctx_locked;
    usbhid_report_infos_t        *fido_report;
    bool                          idle;
    uint8_t                       idle_ms;
    /* below stacks handlers */
    uint8_t                       hid_handler;
    uint8_t                       usbxdci_handler;
    /* U2F commands */
    volatile bool                 report_sent;
    uint8_t                       recv_buf[CTAPHID_FRAME_MAXLEN];
    fido_u2f_buffer_state_t       u2f_cmd_buf_state;
    bool                          u2f_cmd_received;
    uint16_t                      u2f_cmd_size;
    uint16_t                      u2f_cmd_idx;
    ctaphid_cmd_t                 u2f_cmd;
} fido_u2f_context_t;

/* fido context .data initialization */
static fido_u2f_context_t fido_ctx = {
    .ctx_locked = false,
    .fido_report = NULL,
    .idle = false,
    .idle_ms = 0,
    .hid_handler = 0,
    .usbxdci_handler = 0,
    .report_sent = true,
    .recv_buf = { 0 },
    .u2f_cmd_buf_state = U2F_CMD_BUFFER_STATE_EMPTY,
    .u2f_cmd_received = false,
    .u2f_cmd_size = 0,
    .u2f_cmd_idx = 0,
    .u2f_cmd = { 0 }
};


mbed_error_t fido_extract_u2f_pkt(fido_u2f_context_t *ctx)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    switch (ctx->u2f_cmd_buf_state) {
        case U2F_CMD_BUFFER_STATE_COMPLETE:
            errcode = MBED_ERROR_INVSTATE;
            goto err;
            break;
        case U2F_CMD_BUFFER_STATE_EMPTY:
        {
            ctaphid_init_header_t *cmd = (ctaphid_init_header_t*)&ctx->recv_buf[0];
            uint16_t blen = 0;
            /* the pkt chunk in recv_pkt should be the first (maybe the only)
             * chunk. The header is a CTAPHID_INIT header holding bcnth and bcntl
             * fields */
            blen = (cmd->bcnth << 8) | cmd->bcntl;
            /* checking that len is not too long */
            if (blen > 256) {
                log_printf("[FIDO] fragmented packet too big for buffer! (%x bytes)\n", blen);
                errcode = MBED_ERROR_NOMEM;
                goto err;
            }
            ctx->u2f_cmd_size = blen;
            /* whatever the size is, we copy 64 bytes in the cmd into u2f_cmd. */
            memcpy((uint8_t*)(&ctx->u2f_cmd), &(ctx->recv_buf[0]), CTAPHID_FRAME_MAXLEN);
            /* is this the last chunk (no other) ? */
            /* set amount of data written */
            ctx->u2f_cmd_idx = CTAPHID_FRAME_MAXLEN - sizeof(ctaphid_init_header_t);
            if (ctx->u2f_cmd_idx >= blen) {
                /* all command bytes received, buffer complete */
                ctx->u2f_cmd_buf_state = U2F_CMD_BUFFER_STATE_COMPLETE;
            } else {
                /* not all requested bytes received. Just buffering and continue */
                ctx->u2f_cmd_buf_state = U2F_CMD_BUFFER_STATE_BUFFERING;
            }
            break;
        }
        case U2F_CMD_BUFFER_STATE_BUFFERING:
        {
            /* here a previous chunk has already been received. Continue then */
            /* currently received content *must* be a sequence, not an init
             * frame */
            ctaphid_seq_header_t *cmd = (ctaphid_seq_header_t*)&ctx->recv_buf;
            if (cmd->cid != ctx->u2f_cmd.cid) {
                log_printf("[FIDO] current chunk sequence CID does not match intial CID!\n");
                errcode = MBED_ERROR_INVPARAM;
                goto err;
            }
            /* TODO: sequences should be incremental, starting at 0, values, they should
             * be checked for packet ordering...*/

            /* copy the packet data only (sequence header is dropped during refragmentation */
            memcpy((uint8_t*)(&ctx->u2f_cmd.data[ctx->u2f_cmd_idx]),
                   &(ctx->recv_buf[sizeof(ctaphid_seq_header_t)]),
                   CTAPHID_FRAME_MAXLEN - sizeof(ctaphid_seq_header_t));

            ctx->u2f_cmd_idx += CTAPHID_FRAME_MAXLEN - sizeof(ctaphid_seq_header_t);
            if (ctx->u2f_cmd_idx >= ctx->u2f_cmd_size) {
                /* all command bytes received, buffer complete */
                ctx->u2f_cmd_buf_state = U2F_CMD_BUFFER_STATE_COMPLETE;
            } else {
                /* XXX: TODO: the effective calcuation of the max idx is to be done.
                 * As the packet is fragmented with multiple headers and the data
                 * size effective allowed length is 256, we must calculate how many
                 * packets of MAXLEN we can receive, and as a consequence, the copy
                 * limit properly... */
                if (ctx->u2f_cmd_idx > 210) {
                    /* Not complete, yet nearly no more space ! */
                    log_printf("[FIDO] fragmented packet too big for already consumed buffer!\n");
                    errcode = MBED_ERROR_NOMEM;
                    goto err;
                }
            }
            break;
        }
        default:
            errcode = MBED_ERROR_UNKNOWN;
            goto err;
            break;
    }

err:
    return errcode;
}


/* USB HID trigger implementation, required to be triggered on various HID events */
mbed_error_t usbhid_report_received_trigger(uint8_t hid_handler, uint16_t size)
{
   log_printf("[CTAPHID] Received FIDO cmd (size %d)\n", size);
   fido_ctx.u2f_cmd_received = true;
   fido_ctx.u2f_cmd_size = size;
   /* nothing more to do, as the received  command is already set in .u2f_cmd field */
   hid_handler = hid_handler; /* XXX to use ?*/
   return MBED_ERROR_NONE;
}

/* The FIDO HID report content declaration */
static usbhid_report_infos_t fido_std_report = {
    .num_items = 16,
    .report_id = 0,
    .items = {
        /* this is the standard, datasheet defined FIDO2 HID report */
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_USAGE_PAGE, 2, FIDO_USAGE_PAGE_BYTE1, FIDO_USAGE_PAGE_BYTE0 },
        { USBHID_ITEM_TYPE_LOCAL, USBHID_ITEM_LOCAL_TAG_USAGE, 1, FIDO_USAGE_FIDO_U2FHID, 0 },
        { USBHID_ITEM_TYPE_MAIN, USBHID_ITEM_MAIN_TAG_COLLECTION, 1, USBHID_COLL_ITEM_APPLICATION, 0 },
        { USBHID_ITEM_TYPE_LOCAL, USBHID_ITEM_LOCAL_TAG_USAGE, 1, FIDO_USAGE_FIDO_DATA_IN, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_LOGICAL_MIN, 1, 0x0, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_LOGICAL_MAX, 2, 0xff, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_REPORT_SIZE, 1, 0x8, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_REPORT_COUNT, 1, 64, 0 }, /* report count in bytes */
        { USBHID_ITEM_TYPE_MAIN, USBHID_ITEM_MAIN_TAG_INPUT, 1, USBHID_IOF_ITEM_DATA|USBHID_IOF_ITEM_CONST|USBHID_IOF_ITEM_VARIABLE|USBHID_IOF_ITEM_RELATIVE, 0 },
        { USBHID_ITEM_TYPE_LOCAL, USBHID_ITEM_LOCAL_TAG_USAGE, 1, FIDO_USAGE_FIDO_DATA_OUT, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_LOGICAL_MIN, 1, 0x0, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_LOGICAL_MAX, 2, 0xff, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_REPORT_SIZE, 1, 0x8, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_REPORT_COUNT, 1, 64, 0 }, /* report count in bytes */
        { USBHID_ITEM_TYPE_MAIN, USBHID_ITEM_MAIN_TAG_OUTPUT, 1, USBHID_IOF_ITEM_DATA|USBHID_IOF_ITEM_CONST|USBHID_IOF_ITEM_VARIABLE|USBHID_IOF_ITEM_RELATIVE, 0 },
        { USBHID_ITEM_TYPE_MAIN, USBHID_ITEM_MAIN_TAG_END_COLLECTION, 0, 0, 0 }, /* C0 */
    }
};

/***********************************************************************
 * HID requested callbacks
 */
static mbed_error_t           usbhid_set_idle(uint8_t hid_handler, uint8_t idle)
{
    hid_handler = hid_handler;
    log_printf("[CTAPHID] triggered on Set_Idle\n");
    fido_ctx.idle_ms = idle;
    fido_ctx.idle = true;
    log_printf("[CTAPHID] set idle time to %d ms\n", idle);
    return MBED_ERROR_NONE;
}


/* trigger for HID layer GET_REPORT event */
static usbhid_report_infos_t *usbhid_get_report(uint8_t hid_handler, uint8_t index)
{
    log_printf("[CTAPHID] triggered on Get_Report\n");
    usbhid_report_infos_t *report = NULL;
    hid_handler = hid_handler; /* only one iface: 0 */
    switch (index) {
        case 0:
            report = fido_ctx.fido_report;
            break;
        default:
            log_printf("[CTAPHID] unkown report index %d\n", index);
            break;
    }
    return report;
}


void usbhid_report_sent_trigger(uint8_t hid_handler, uint8_t index)
{
    hid_handler = hid_handler;
    index = index;
    fido_ctx.report_sent = true;
}



/********************************************************************
 * FIDO API
 */

mbed_error_t fido_declare(uint8_t usbxdci_handler)
{
    mbed_error_t errcode = MBED_ERROR_UNKNOWN;
    /* first initializing basics of local context */
    fido_ctx.usbxdci_handler = usbxdci_handler;
    fido_ctx.fido_report = &fido_std_report;

    log_printf("[CTAPHID] declare usbhid interface for FIDO U2F\n");
    errcode = usbhid_declare(usbxdci_handler,
                             USBHID_SUBCLASS_NONE, USBHID_PROTOCOL_NONE,
                             FIDO_DESCRIPOR_NUM, FIDO_POLL_TIME, true,
                             64, &(fido_ctx.hid_handler));
    if (errcode != MBED_ERROR_NONE) {
        log_printf("[CTAPHID] failure while declaring FIDO interface: err=%d\n", errcode);
        goto err;
    }
    /* configure HID interface */
    log_printf("[CTAPHID] configure usbhid device\n");
    errcode = usbhid_configure(fido_ctx.hid_handler,
                     usbhid_get_report,
                     NULL, /* set report */
                     NULL, /* set proto */
                     usbhid_set_idle);
    if (errcode != MBED_ERROR_NONE) {
        log_printf("[CTAPHID] failure while configuring FIDO interface: err=%d\n", errcode);
        goto err;
    }

    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}

mbed_error_t fido_configure(void)
{
    return MBED_ERROR_NONE;
}

/* we initialize our OUT EP to be ready to receive, if needed. */
mbed_error_t fido_prepare_exec(void)
{
    /*
     * First tour MUST BE a CTAPHID_INIT packet, which is less than CTAPHID_FRAME_MAXLEN size.
     */
    return usbhid_recv_report(fido_ctx.hid_handler, (uint8_t*)&fido_ctx.recv_buf, CTAPHID_FRAME_MAXLEN);
}

/*
 * Executing a single loop:
 *  - get back potential cmd
 *  - parse command, request backend execution
 *  - get back backend response
 *  - return potential response to host
 */
mbed_error_t fido_exec(void)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /*TODO: 64ms poll time, hardcoded in libusbctrl by now */
    //uint32_t wait_time = FIDO_POLL_TIME;

    /* the Get_Report() request should be transmitted before starting
     * to send periodic reports */
    if (fido_ctx.report_sent == false) {
        /* wait for previous report to be sent first */
        goto err;
    }
    /* TODO: set report to 0 */
    if (fido_ctx.u2f_cmd_received) {
        /* an U2F command has been received! handle it! */
        /* is the packet fragmented ? If yes, just buffer it and continue.... */
        if ((errcode = fido_extract_u2f_pkt(&fido_ctx)) != MBED_ERROR_NONE) {
            log_printf("[FIDO] error during recv packet refragmentation, err=%x\n", errcode);
            goto err;
        }
        if (fido_ctx.u2f_cmd_buf_state == U2F_CMD_BUFFER_STATE_COMPLETE) {
            /* not fragmented ? if the buffer should handle a CTAPHID request that is clean
             * and ready to be handled. Let's treat it. */
            errcode = u2f_handle_request(&fido_ctx.u2f_cmd);
        }
        fido_ctx.u2f_cmd_received = false;
        /* XXX: it seems that the FIFO size is hard-coded to 64 bytes */
        usbhid_recv_report(fido_ctx.hid_handler, (uint8_t*)&fido_ctx.recv_buf, CTAPHID_FRAME_MAXLEN);
        /* now that current report/response has been consumed, ready to receive
         * new U2F report. Set reception EP ready */
    }
err:
    return errcode;
}

/* local private API */

uint8_t fido_get_usbhid_handler(void)
{
    return fido_ctx.hid_handler;
}
