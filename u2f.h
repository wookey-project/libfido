
/*
 * TODO:
 * FIDO U2F is using APDU (ISO7816-4 framing).
 * APDU encapsulation is handled by libiso7816, over libusbhid for IN and OUT Endpoints.
 * The overall device stacking is the following:
 *
 * [ FIDO U2F CMD  ][   FIDO Ctrl         ]   <---- this library
 *  ---------------
 * [ libISO7816    ]
 * [ (APDU framing)]
 *  ---------------  ---------------------
 * [  libUSBHID    ][ libxDCI             ]
 * [ (HID stack)   ][ (USB control plane) ]
 *  ---------------  ---------------------
 * [  USB backend driver                  ]
 */

/*
 * FIXME to define properly:
 * range of u2f_cmd_id for vendor specific commands
 */
#define U2FHID_VENDOR_FIRST 42
#define U2FHID_VENDOR_LAST  52

/*****************************************
 * About command
 */

typedef enumerate {
    U2FHID_MSG,
    U2FHID_INIT,
    U2FHID_PING,
    U2FHID_ERROR,
    U2FHID_WINK,
    U2FHID_LOCK
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
 */
typedef struct __packed {
    uint8_t  cmd;
    uint8_t  bcnt;
    uint8_t  data[256];
} u2f_cmd_t;


/******************************************
 * About responses
 */

typedef struct __packed {
    uint8_t cmd;
    uint8_t bcnt;
    uint8_t data[256];
} u2f_resp_msg_t;

typedef struct __packed {
    uint8_t cmd;
    uint8_t bcnt;
    uint8_t nonce[8];
    uint8_t chanid[4];
    uint8_t proto_version;
    uint8_t major_n;
    uint8_t minor_n;
    uint8_t build_n;
    uint8_t capa_f;
} u2f_resp_init_t;

typedef struct __packed {
    uint8_t cmd;
    uint8_t bcnt;
    uint8_t data[256];
} u2f_resp_ping_t;

typedef struct __packed {
    uint8_t cmd;
    uint8_t bcnt; /*< 0 */
} u2f_resp_lock_t;


/*
 * Optional response to WINK command
 */

typedef struct __packed {
    uint8_t cmd;
    uint8_t bcnt; /*< 0 */
} u2f_resp_wink_t;

typedef enum {
    U2F_CAPABILITY_WINK,
} u2f_capability_t;

typedef enum {
    U2F_ERR_INVALID_CMD,
    U2F_ERR_INVALID_PAR,
    U2F_ERR_INVALID_LEN,
    U2F_ERR_INVALID_SEQ,
    U2F_ERR_MSG_TIMEOUT,
    U2F_ERR_CHANNEL_BUSY
}
