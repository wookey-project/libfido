/*
 * TODO:
 * FIDO U2F is using APDU (ISO7816-4 framing).
 * APDU encapsulation is handled by libiso7816, over libusbhid for IN and OUT Endpoints.
 * The overall device stacking is the following:
 *
 * [ FIDO U2F CMD  ][   FIDO Ctrl         ]   <---- this library
 *  ---------------
 * [ (APDU framing)]
 *  ---------------  ---------------------
 * [  libUSBHID    ][ libxDCI             ]
 * [ (HID stack)   ][ (USB control plane) ]
 *  ---------------  ---------------------
 * [  USB backend driver                  ]
 */
#ifndef U2F_H_
#define U2F_H_
#include "autoconf.h"
#include "libc/types.h"

/*
 * FIXME to define properly:
 * range of u2f_cmd_id for vendor specific commands
 */
#define U2FHID_VENDOR_FIRST 42
#define U2FHID_VENDOR_LAST  52

#define U2FHID_BROADCAST_CID 0xffffffff

#define USBHID_PROTO_VERSION 2

/*****************************************
 * About command
 */

typedef enum {
    U2FHID_PING      = 0x01,
    U2FHID_MSG       = 0x03,
    U2FHID_LOCK      = 0x04,
    U2FHID_INIT      = 0x06,
    U2FHID_WINK      = 0x08,
    U2FHID_CBOR      = 0x10,
    U2FHID_CANCEL    = 0x11,
    U2FHID_KEEPALIVE = 0x3b,
    U2FHID_ERROR     = 0x3f,
} u2f_cmd_id_t;


/*
 * Considering Full Speed devices, the FIDO Alliance define
 * IN and OUT interrupt endpoint as 64 bits mpsize EP.
 * In interrupt mode, the host and device can forge transfert
 * up to the mpsize (64 bytes) packets.
 * As a consequence, U2F commands can't be bigger than 64 bytes,
 * decomposed on CMD, BCNT (length) and DATA (effective content).
 * Although, to be generic to USB and avoid any risk, considering
 * BCNT as a uint8_t field, data len is up to 256 bytes.
 *
 * In case of U2FHID_MSG commands, the data hold APDU formated U2F messages
 * defined below.
 */
typedef struct __packed {
    uint32_t cid;
    uint8_t  cmd;
    uint8_t  bcnth;
    uint8_t  bcntl;
    uint8_t  data[256];
} u2f_cmd_t;


/******************************************
 * About responses
 */

/*
 * All messages are made of a header, and a differenciated data conent
 * (depending on the message type)
 */
typedef struct __packed {
    uint32_t cid;
    uint8_t cmd;
    uint8_t bcnth;
    uint8_t bcntl;
    /* differenciated resp here */
} u2f_resp_msg_t;

typedef struct __packed {
    uint8_t nonce[8];
    uint32_t chanid;
    uint8_t proto_version;
    uint8_t major_n;
    uint8_t minor_n;
    uint8_t build_n;
    uint8_t capa_f;
} u2f_resp_init_t;


/*
 * Optional response to WINK command
 */

typedef enum {
    U2FHID_CAPA_WINK  = 0x1,
    U2FHID_CAPA_LOCK  = 0x1 << 1,
    U2FHID_CAPA_CBOR  = 0x1 << 2,
    U2FHID_CAPA_NMSG  = 0x1 << 3,
} u2f_capa_id_t;



typedef enum {
    U2F_ERR_INVALID_CMD,
    U2F_ERR_INVALID_PAR,
    U2F_ERR_INVALID_LEN,
    U2F_ERR_INVALID_SEQ,
    U2F_ERR_MSG_TIMEOUT,
    U2F_ERR_CHANNEL_BUSY
} u2f_error_code_t;

/************************************************************
 * About U2FHID_MSG formats
 *
 * There is three types of U2FHID messages. All these messages are
 * formatted using the T=0 APDU format.
 */

/*
 * For these commands, the FIDO U2F raw message format datasheets specify the following
 * in chap. 3:
 * REGISTER:        INS=0x1,       P1=0x0,     P2=0x0
 * AUTHENTICATE:    INS=0x2,       P1=0x3|7|8, P2=0x0
 * VERSION:         INS=0x3,       P1=0x0,     P2=0x0
 * VENDOR-SPECIFIC: INS=0x40-0xbf, NA,         NA
 */
typedef enum {
    U2F_INS_REGISTER     = 0x1,
    U2F_INS_AUTHENTICATE = 0x2,
    U2F_INS_VERSION      = 0x3
} u2f_msg_ins_t;


/*
 * Hande U2F commands
 */
mbed_error_t u2f_handle_request(const u2f_cmd_t *cmd);

#endif/*!U2F_H_*/
