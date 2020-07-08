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
    bool                          u2f_cmd_received;
    uint16_t                      u2f_cmd_size;
    u2f_cmd_t                     u2f_cmd;
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
    .u2f_cmd_received = false,
    .u2f_cmd_size = 0,
    .u2f_cmd = { 0 }
};


/* USB HID trigger implementation, required to be triggered on various HID events */
mbed_error_t usbhid_report_received_trigger(uint8_t hid_handler, uint16_t size)
{
   log_printf("[FIDO] Received FIDO cmd (size %d)\n", size);
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
#include "api/libfido.h"
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
    log_printf("[FIDO] triggered on Set_Idle\n");
    fido_ctx.idle_ms = idle;
    fido_ctx.idle = true;
    log_printf("[FIDO] set idle time to %d ms\n", idle);
    return MBED_ERROR_NONE;
}


/* trigger for HID layer GET_REPORT event */
static usbhid_report_infos_t *usbhid_get_report(uint8_t hid_handler, uint8_t index)
{
    log_printf("[FIDO] triggered on Get_Report\n");
    usbhid_report_infos_t *report = NULL;
    hid_handler = hid_handler; /* only one iface: 0 */
    switch (index) {
        case 0:
            report = fido_ctx.fido_report;
            break;
        default:
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

    log_printf("[KBD] declare usbhid interface for FIDO U2F\n");
    errcode = usbhid_declare(usbxdci_handler,
                             USBHID_SUBCLASS_NONE, USBHID_PROTOCOL_NONE,
                             FIDO_DESCRIPOR_NUM, FIDO_POLL_TIME, true,
                             64, &(fido_ctx.hid_handler));
    if (errcode != MBED_ERROR_NONE) {
        log_printf("[FIDO] failure while declaring FIDO interface: err=%d\n", errcode);
        goto err;
    }
    /* configure HID interface */
    log_printf("[FIDO] configure usbhid device\n");
    errcode = usbhid_configure(fido_ctx.hid_handler,
                     usbhid_get_report,
                     NULL, /* set report */
                     NULL, /* set proto */
                     usbhid_set_idle);
    if (errcode != MBED_ERROR_NONE) {
        log_printf("[FIDO] failure while configuring FIDO interface: err=%d\n", errcode);
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
    return usbhid_recv_report(fido_ctx.hid_handler, (uint8_t*)&fido_ctx.u2f_cmd, 64);
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

        errcode = u2f_handle_request(&fido_ctx.u2f_cmd);
        fido_ctx.u2f_cmd_received = false;
        /* XXX: it seems that the FIFO size is hard-coded to 64 bytes */
        usbhid_recv_report(fido_ctx.hid_handler, (uint8_t*)&fido_ctx.u2f_cmd, 64);
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
