#include "libc/types.h"
#include "libc/random.h"
#include "libc/string.h"
#include "libsig.h"
#include "hmac.h"
//#include "u2f_platform.h"
#include "fido.h"


#define U2F_FIDO_EMULATE_USER_PRESENCE

/* Primitive to enforce user presence */
static int enforce_user_presence(uint32_t timeout __attribute__((unused)))
{
#ifdef U2F_FIDO_EMULATE_USER_PRESENCE
#ifdef U2F_FIDO_DEBUG
	log_printf("[U2F_FIDO] user presence emulated!\n");
#endif
	return 0;
#else
#ifdef U2F_FIDO_DEBUG
	log_printf("[U2F_FIDO] Wait for user presence with timeout %d seconds\n", timeout);
#endif
	/* Test for user presence with timeout in seconds */
	return platform_enforce_user_presence(timeout);
#endif
}

/* HMAC Keys for Key handle and private keys computations */
static const uint8_t master_key_hmac1[32] = { 0x01, 0x02 };
static const uint8_t master_key_hmac2[32] = { 0x11, 0x22 };

#define KEY_HANDLE_NONCE_SIZE 32

/* Key Handle generation function */
static mbed_error_t generate_key_handle(uint8_t *key_handle, uint16_t *key_handle_len, uint8_t *application_parameter, uint16_t application_parameter_len)
{
    mbed_error_t errcode;
	/* Sanity check */
	if((key_handle == NULL) || (key_handle_len == NULL)){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	/* Bad length */
	if(*key_handle_len < KEY_HANDLE_SIZE){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	*key_handle_len = KEY_HANDLE_SIZE;
	/* Get a 32 bytes random value */
	uint8_t Nonce[KEY_HANDLE_NONCE_SIZE];
	if (get_random((unsigned char*)&Nonce, KEY_HANDLE_NONCE_SIZE)){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
	memcpy(key_handle, Nonce, KEY_HANDLE_NONCE_SIZE);
	/* Now compute the hmac of the None with Key1 */
	hmac_context hmac_ctx;
	uint32_t hmac_len = 32;
	if(hmac_init(&hmac_ctx, master_key_hmac1, sizeof(master_key_hmac1), SHA256)){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
	hmac_update(&hmac_ctx, Nonce, KEY_HANDLE_NONCE_SIZE);
	if((application_parameter != NULL) && (application_parameter_len != 0)){
		hmac_update(&hmac_ctx, application_parameter, application_parameter_len);
	}
	/* Our Key handle is the concatenation of Nonce and HMAC */
	hmac_finalize(&hmac_ctx, key_handle + KEY_HANDLE_NONCE_SIZE, &hmac_len);
	if(hmac_len != 32){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}

    errcode = MBED_ERROR_NONE;
err:
	return errcode;
}

/* Key Handle check function */
static mbed_error_t check_key_handle(uint8_t *key_handle, uint16_t key_handle_len, uint8_t *application_parameter, uint16_t application_parameter_len)
{
    mbed_error_t errcode;
	/* Sanity check */
	if (key_handle == NULL) {
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	/* Bad length */
	if(key_handle_len < KEY_HANDLE_SIZE){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	/* Compute the hmac of the None with Key1 */
	hmac_context hmac_ctx;
    uint8_t hmac[SHA256_DIGEST_SIZE];
	uint32_t hmac_len = sizeof(hmac);
	if (hmac_init(&hmac_ctx, master_key_hmac1, sizeof(master_key_hmac1), SHA256)) {
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
	hmac_update(&hmac_ctx, key_handle, KEY_HANDLE_NONCE_SIZE);
	if((application_parameter != NULL) && (application_parameter_len != 0)){
		hmac_update(&hmac_ctx, application_parameter, application_parameter_len);
	}
	hmac_finalize(&hmac_ctx, hmac, &hmac_len);
	if(hmac_len != 32){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
	/* Compare our HMACs */
	if(!are_equal(hmac, key_handle + KEY_HANDLE_NONCE_SIZE, hmac_len)){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}

    errcode = MBED_ERROR_NONE;
err:
	return errcode;
}

/* Generate an ECDSA private key from a key handle */
static int generate_ECDSA_priv_key(uint8_t *key_handle, uint16_t key_handle_len, uint8_t *priv_key, uint16_t *priv_key_len, uint8_t *application_parameter, uint16_t application_parameter_len)
{
    mbed_error_t errcode;
	/* Sanity checks */
	if((key_handle == NULL) || (priv_key_len == NULL) || (priv_key == NULL)){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	if(key_handle_len != KEY_HANDLE_SIZE){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	if(*priv_key_len < PRIV_KEY_SIZE){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	/* Check the key handle authenticity */
	if(check_key_handle(key_handle, key_handle_len, application_parameter, application_parameter_len)){
        errcode = MBED_ERROR_INVCREDENCIALS;
		goto err;
	}
	(*priv_key_len) = PRIV_KEY_SIZE;
	/* We generate our private key  */
	hmac_context hmac_ctx;
	uint32_t hmac_len = (*priv_key_len);
	if(hmac_init(&hmac_ctx, master_key_hmac2, sizeof(master_key_hmac2), SHA256)){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
	hmac_update(&hmac_ctx, key_handle, KEY_HANDLE_SIZE);
	hmac_finalize(&hmac_ctx, priv_key, &hmac_len);
	if(hmac_len != 32){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
	/* We want to ensure that the private key is < q (the order of the curve) */
    /* libecc internal structure holding the curve parameters */
    const ec_str_params *the_curve_const_parameters;
    ec_params curve_params;
    the_curve_const_parameters = ec_get_curve_params_by_type(SECP256R1);
    /* Get out if getting the parameters went wrong */
    if (the_curve_const_parameters == NULL) {
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    }
    /* Now map the curve parameters to our libecc internal representation */
    import_params(&curve_params, the_curve_const_parameters);
	/* Import the private key as NN */
	nn pkey;
	nn_init_from_buf(&pkey, priv_key, *priv_key_len);
	/* Compute our modulo */
	nn_mod(&pkey, &pkey, &(curve_params.ec_gen_order));
	/* Export private key again in buffer */
	nn_export_to_buf(priv_key, *priv_key_len, &pkey);

    errcode = MBED_ERROR_NONE;
err:
	return errcode;
}


/*
 * Format a raw ECDSA signature to ASN.1 as specified in ANSI X9.62.
 *   NOTE: although we expect DER encoding for ECDSA signature (i.e. minimal possible ASN.1 encoding), the
 *   FIDO standard mandates that another (non minimal) BER encoding should be used by specifying an explicit
 *   71 to 73 bytes size encoding, which is actually *wrong* and must be 70 to 72 bytes (see below).
 *   The used encoding is to add an explicit prepending 0x00 when encoding a 256-bit big number with MSB (bit 255) set to 1, which
 *   indeed leads to 2 additional 0x00 bytes in the "worst case". Since we use 2 bytes for Tag and Length of the SEQUENCE
 *   encapsulating the two big numbers, and 2 bytes for the Tag and Length of each big number, this leads to a possible minimal size of:
 *       2 (sequence TL) + 2 (big num 1 TL) + 32 (big num 1 value) + 2 (big num 2 TL) + 32 (big num 2 value)
 *       = 70 bytes
 *   and a maximal size of:
 *       2 (sequence TL) + 2 (big num 1 TL) + 33 (big num 1 value + prepending 0x00) + 2 (big num 2 TL) + 33 (big num 2 value + prepending 0x00)
 *       = 72 bytes
 *
 */
#define ASN1_SEQUENCE_TAG		0x30
#define ASN1_INTEGER_TAG		0x02
#define ASN1_UNCOMPRESSED_POINT_TAG 	0x04

static int format_ECDSA_signature_ansi_x962(uint8_t *raw_ECDSA_signature, uint8_t siglen, uint8_t *formatted_ECDSA_signature, uint16_t *formatted_ECDSA_signature_len)
{
	/* NOTE: this is a very simple and straightforward way of encoding the signature, yet quite optimal
	 * and without appatent issues.
	 */
	/* Sanity check on raw signature length: it should be 2 256-bit big numbers (64 bytes) */
	if(siglen != (SIG_R_SIZE + SIG_S_SIZE)){
		goto err;
	}
	/* Extract r and s that are each half the raw signature */
	uint8_t *r = raw_ECDSA_signature;
	uint8_t *s = raw_ECDSA_signature + (siglen / 2);
	/* Compute our final length */
	uint16_t out_len = 2 /* SEQUENCE TL */ + 2 /* BIGNUM TL */ + SIG_R_SIZE + 2 /* BIGNUM TL */+ SIG_S_SIZE; /* = 70 byes minimum size */
	if(r[0] & 0x80){ /* Check MSB of r, add prepending 0x00 if necessary */
		out_len++;
	}
	if(s[0] & 0x80){ /* Check MSB of s, add prepending 0x00 if necessary */
		out_len++;
	}
	/* => at this point, we should have a maximum size out_len of 72 bytes */
	/* Sanity check */
	if((out_len > (*formatted_ECDSA_signature_len)) || (out_len <= 2)){
		goto err;
	}
	(*formatted_ECDSA_signature_len) = out_len;
	/* Create our sequence that will encapsulate our two big numbers */
	uint16_t offset = 0;
	memset(formatted_ECDSA_signature, 0, *formatted_ECDSA_signature_len);
	formatted_ECDSA_signature[offset] = ASN1_SEQUENCE_TAG; /* ASN.1 SEQUENCE */
	offset += 1;
	formatted_ECDSA_signature[offset] = (out_len - 2); /* Length of the sequence */
	offset += 1;
	/* Encode r */
	formatted_ECDSA_signature[offset] = ASN1_INTEGER_TAG; /* ASN.1 INTEGER for r */
	offset += 1;
	if(r[0] & 0x80){
		formatted_ECDSA_signature[offset] = SIG_R_SIZE + 1;
		offset += 1;
		formatted_ECDSA_signature[offset] = 0x00;
		offset += 1;
	}
	else{
		formatted_ECDSA_signature[offset] = SIG_R_SIZE;
		offset += 1;
	}
	memcpy(&formatted_ECDSA_signature[offset], r, SIG_R_SIZE);
	offset += SIG_R_SIZE;
	/* Encode s */
	formatted_ECDSA_signature[offset] = ASN1_INTEGER_TAG; /* ASN.1 INTEGER for s */
	offset += 1;
	if(s[0] & 0x80){
		formatted_ECDSA_signature[offset] = SIG_S_SIZE + 1;
		offset += 1;
		formatted_ECDSA_signature[offset] = 0x00;
		offset += 1;
	}
	else{
		formatted_ECDSA_signature[offset] = SIG_S_SIZE;
		offset += 1;
	}
	memcpy(&formatted_ECDSA_signature[offset], s, SIG_S_SIZE);
	offset += SIG_S_SIZE;

	/* Sanity check */
	if(offset > (*formatted_ECDSA_signature_len)){
		goto err;
	}

	return 0;
err:
	return -1;
}


/*** Version *****/
const uint8_t u2f_fido_version_str[] = "U2F_V2";

int u2f_fido_version(uint8_t u2f_param __attribute__((unused)), uint8_t * msg __attribute__((unused)), uint16_t len_in, uint8_t *resp, uint16_t *len_out)
{
	int error;

	if((len_out == NULL) || (resp == NULL)){
		error = WRONG_LENGTH;
		goto err;
	}
	/* We do not expect any data in this command */
	if(len_in != 0){
		error = WRONG_LENGTH;
		goto err;
	}
	/* Sanity check on the available output size */
	if(*len_out < (sizeof(u2f_fido_version_str) - 1)){
		error = WRONG_LENGTH;
		goto err;
	}
	/* We are asked to send the version */
	*len_out = (sizeof(u2f_fido_version_str) - 1);
	memcpy(resp, u2f_fido_version_str, sizeof(u2f_fido_version_str) - 1);

	return NO_ERROR;
err:
	*len_out = 0;
	return error;
}

/*** Register *****/
/* Our attestation certificate */
const uint8_t attestation_cert[] = {
  0x30, 0x82, 0x01, 0x67, 0x30, 0x82, 0x01, 0x0d, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x14, 0x01, 0xcf, 0x7e, 0xae, 0x4e, 0x37, 0xfb, 0x7c, 0x22,
  0x2f, 0xa1, 0xbd, 0x52, 0x3c, 0xfd, 0xfc, 0x23, 0xe5, 0xb2, 0xdc, 0x30,
  0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
  0x27, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
  0x55, 0x53, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
  0x0f, 0x48, 0x32, 0x4c, 0x41, 0x42, 0x20, 0x55, 0x32, 0x46, 0x20, 0x54,
  0x6f, 0x6b, 0x65, 0x6e, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x38,
  0x32, 0x33, 0x31, 0x36, 0x30, 0x39, 0x31, 0x39, 0x5a, 0x17, 0x0d, 0x33,
  0x30, 0x30, 0x38, 0x32, 0x31, 0x31, 0x36, 0x30, 0x39, 0x31, 0x39, 0x5a,
  0x30, 0x27, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
  0x02, 0x55, 0x53, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x0c, 0x0f, 0x48, 0x32, 0x4c, 0x41, 0x42, 0x20, 0x55, 0x32, 0x46, 0x20,
  0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
  0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x0b, 0x69, 0x57, 0x0c,
  0xed, 0x45, 0x83, 0x24, 0xd7, 0xd0, 0xf0, 0xf1, 0x4c, 0x29, 0xf4, 0xe9,
  0x62, 0x2e, 0x60, 0xdf, 0x27, 0x13, 0x9c, 0xfb, 0xd6, 0xd5, 0x87, 0x7e,
  0xbf, 0x74, 0x3b, 0x9d, 0x69, 0x63, 0x1f, 0x64, 0xda, 0x11, 0xa7, 0x0a,
  0x29, 0x2a, 0xd3, 0x8c, 0x0e, 0x84, 0xd5, 0x69, 0x7f, 0x0e, 0x55, 0x32,
  0xd3, 0xa7, 0xb9, 0xad, 0x1a, 0x51, 0x9b, 0x94, 0x77, 0x29, 0x64, 0x85,
  0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04,
  0x01, 0x82, 0xe5, 0x1c, 0x02, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x05,
  0x20, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
  0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x26, 0xa4, 0x77, 0xa1,
  0x1f, 0xa4, 0xd5, 0xe8, 0x05, 0x94, 0xee, 0xad, 0x73, 0xd4, 0x62, 0xcb,
  0x79, 0xe5, 0xd1, 0xef, 0x50, 0x1b, 0x73, 0xa3, 0x75, 0xd2, 0xf4, 0x2f,
  0x3d, 0x7a, 0xa6, 0xe9, 0x02, 0x21, 0x00, 0xd3, 0xae, 0x7f, 0x44, 0xf8,
  0xd1, 0xd7, 0x7a, 0xab, 0x7a, 0x0c, 0xb2, 0x84, 0x46, 0x08, 0x87, 0x91,
  0x41, 0x14, 0x58, 0x1a, 0x48, 0x6a, 0xb4, 0xb2, 0x92, 0x9c, 0xcd, 0xf1,
  0x9a, 0x24, 0x70
};
/* Our attestation private key */
const uint8_t attestation_priv_key_buff[] = {
  0xba, 0x08, 0x57, 0xa2, 0x65,
  0xc9, 0x32, 0xc8, 0xce, 0x65, 0xe6, 0x00, 0x5f, 0xaa, 0xe8, 0x54, 0x18,
  0x0b, 0x8f, 0x01, 0xd5, 0xa4, 0x43, 0x38, 0xa9, 0x33, 0xf8, 0x41, 0x12,
  0x75, 0x35, 0x81
};
/* Our attestation public key */
const uint8_t attestation_pub_key_buff[] = {
  0x04, 0x0b, 0x69, 0x57, 0x0c, 0xed, 0x45, 0x83, 0x24, 0xd7,
  0xd0, 0xf0, 0xf1, 0x4c, 0x29, 0xf4, 0xe9, 0x62, 0x2e, 0x60, 0xdf, 0x27,
  0x13, 0x9c, 0xfb, 0xd6, 0xd5, 0x87, 0x7e, 0xbf, 0x74, 0x3b, 0x9d, 0x69,
  0x63, 0x1f, 0x64, 0xda, 0x11, 0xa7, 0x0a, 0x29, 0x2a, 0xd3, 0x8c, 0x0e,
  0x84, 0xd5, 0x69, 0x7f, 0x0e, 0x55, 0x32, 0xd3, 0xa7, 0xb9, 0xad, 0x1a,
  0x51, 0x9b, 0x94, 0x77, 0x29, 0x64, 0x85
};

/* As defined in the FIDO U2F specification
 *    challenge_parameter (32) | application_parameter (32)
 */
typedef struct __attribute__((packed)) {
	uint8_t challenge_parameter[CHALLENGE_PARAMETER_SIZE];
	uint8_t application_parameter[APPLICATION_PARAMETER_SIZE];
} register_msg;

int u2f_fido_register(uint8_t u2f_param __attribute__((unused)), uint8_t * msg, uint16_t len_in, uint8_t *resp, uint16_t *len_out)
{
	int error = 0;
	register_msg *in_msg = (register_msg*)msg;
	log_printf("[U2F_FIDO] REGISTER called\n");

	if((len_out == NULL) || (resp == NULL) || (msg == NULL)){
		error = WRONG_LENGTH;
		goto err;
	}
	/* Sanity check on the inputs
	 * Should be:
	 *   challenge_parameter (32) | application_parameter (32)
	 */
	if(len_in != sizeof(register_msg)){
		error = WRONG_LENGTH;
		goto err;
	}
	/* We always ask for user presence in all the cases */
	if(enforce_user_presence(3)){
		error = REQUIRE_TEST_USER_PRESENCE;
		goto err;
	}

	/* Generate a Key Handle and a key pair */
	uint8_t key_handle[KEY_HANDLE_SIZE] = { 0 };
	uint16_t key_handle_len = KEY_HANDLE_SIZE;
	uint8_t priv_key_buff[PRIV_KEY_SIZE] = { 0 };
	uint16_t priv_key_buff_len = PRIV_KEY_SIZE;
	ec_priv_key priv_key;
	ec_pub_key pub_key;
	/* Generate Key Handle and private key */
	if (generate_key_handle(key_handle, &key_handle_len, in_msg->application_parameter, sizeof(in_msg->application_parameter))) {
		error = INVALID_KEY_HANDLE;
		goto err;
	}

	if(generate_ECDSA_priv_key(key_handle, key_handle_len, priv_key_buff, &priv_key_buff_len, in_msg->application_parameter, sizeof(in_msg->application_parameter))){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
	if(priv_key_buff_len != PRIV_KEY_SIZE){
		error = INVALID_KEY_HANDLE;
		goto err;
	}

	log_printf("[U2F_FIDO] REGISTER: key handle generated ...\n");
	/* libecc internal structure holding the curve parameters */
        const ec_str_params *the_curve_const_parameters;
        ec_params curve_params;
	the_curve_const_parameters = ec_get_curve_params_by_type(SECP256R1);
        /* Get out if getting the parameters went wrong */
        if (the_curve_const_parameters == NULL) {
		error = INVALID_KEY_HANDLE;
                goto err;
        }
        /* Now map the curve parameters to our libecc internal representation */
        import_params(&curve_params, the_curve_const_parameters);
	/* Import private key from buffer */
	ec_priv_key_import_from_buf(&priv_key, &curve_params, priv_key_buff, priv_key_buff_len, ECDSA);
	/* Now compute our public key */
	ecdsa_init_pub_key(&pub_key, &priv_key);
	/* Extract x and y from our public key in buffers */
	uint8_t pubkey_x[PUB_KEY_X_SIZE] = { 0 };
	uint8_t pubkey_y[PUB_KEY_Y_SIZE] = { 0 };
	aff_pt Pub_aff;
	prj_pt_to_aff(&Pub_aff, &(pub_key.y));
	fp_export_to_buf(pubkey_x, sizeof(pubkey_x), &(Pub_aff.x));
	fp_export_to_buf(pubkey_y, sizeof(pubkey_y), &(Pub_aff.y));
	/* Import attestation key pair */
	ec_key_pair attestation_key_pair;
	/* Sanity check: pub key buffer must be in uncompressed form */
	if((sizeof(attestation_pub_key_buff) != (PUB_KEY_X_SIZE + PUB_KEY_Y_SIZE + 1)) || (attestation_pub_key_buff[0] != ASN1_UNCOMPRESSED_POINT_TAG)){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
	/* Import the attestation private key and the public key */
	/* Sanity check for th eprivate key */
	if(sizeof(attestation_priv_key_buff) != PRIV_KEY_SIZE){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
	ec_priv_key_import_from_buf(&(attestation_key_pair.priv_key), &curve_params, (const uint8_t*)&attestation_priv_key_buff, sizeof(attestation_priv_key_buff), ECDSA);
	uint8_t attestation_pub_key_buff_prj[PUB_KEY_X_SIZE + PUB_KEY_Y_SIZE + PUB_KEY_Z_SIZE] = { 0 };
	memcpy(attestation_pub_key_buff_prj, &attestation_pub_key_buff[1], (PUB_KEY_X_SIZE + PUB_KEY_Y_SIZE));
	attestation_pub_key_buff_prj[sizeof(attestation_pub_key_buff_prj) - 1] = 0x01; /* Z coordinate to 1 */
	if(ec_pub_key_import_from_buf(&(attestation_key_pair.pub_key), &curve_params, (const uint8_t*)&attestation_pub_key_buff_prj[0], sizeof(attestation_pub_key_buff_prj), ECDSA)){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
	/* Sign 0x00 | application_parameter | challenge_parameter | key_handle | pub_key */
	struct ec_sign_context sig_ctx;
        if(ec_sign_init(&sig_ctx, &attestation_key_pair, ECDSA, SHA256)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }

	uint8_t reserved = 0x00;
        if(ec_sign_update(&sig_ctx, (const uint8_t*)&reserved, 1)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&(in_msg->application_parameter), sizeof(in_msg->application_parameter))){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&(in_msg->challenge_parameter), sizeof(in_msg->challenge_parameter))){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)key_handle, KEY_HANDLE_SIZE)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	uint8_t uncompressed_point = ASN1_UNCOMPRESSED_POINT_TAG;
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&uncompressed_point, 1)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&pubkey_x, sizeof(pubkey_x))){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&pubkey_y, sizeof(pubkey_y))){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	/* Finalize signature and place it in the end of the response */
	/* Get our ECDSA signature length */
	uint8_t siglen;
	uint8_t raw_ECDSA_signature[SIG_R_SIZE + SIG_S_SIZE] = { 0 };
        if(ec_get_sig_len(&curve_params, ECDSA, SHA256, &siglen)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	if(siglen != (SIG_R_SIZE + SIG_S_SIZE)){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
        if(ec_sign_finalize(&sig_ctx, (uint8_t*)&raw_ECDSA_signature, sizeof(raw_ECDSA_signature))){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	log_printf("[U2F_FIDO] REGISTER: ECDSA signature performed ...\n");

	/* Format the ECDSA signature to ANSI X9.62 */
	uint8_t formatted_ECDSA_signature[72] = { 0 };
	uint16_t formatted_ECDSA_signature_len = sizeof(formatted_ECDSA_signature);
	if(format_ECDSA_signature_ansi_x962(raw_ECDSA_signature, siglen, formatted_ECDSA_signature, &formatted_ECDSA_signature_len)){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
	/* Begin to format our output
 	 *    0x05 | user_pub_key (65) | key_handle_len (1) | key_handle (size key_handle_len) | attestation_cert | signature (71-73 per standard, actually 70-72)
	 */
	uint16_t output_size = 1 /* reserved = 0x05 */ + (PUB_KEY_X_SIZE + PUB_KEY_Y_SIZE + 1) /* user_pub_key */ \
			     + 1 /* key_handle_len */+ KEY_HANDLE_SIZE /* key_handle */ + sizeof(attestation_cert) /* attestation_cert */ \
			     + formatted_ECDSA_signature_len /* signature */;
	/* Sanity check on the available output size */
	if((*len_out) < output_size){
		error = WRONG_LENGTH;
		goto err;
	}
	*len_out = output_size;
	uint16_t offset = 0;
	resp[offset] = 0x05; /* Reserved */
	offset += 1;
	resp[offset] = ASN1_UNCOMPRESSED_POINT_TAG; /* Uncompressed point */
	offset += 1;
	local_memcpy(&resp[offset], &pubkey_x, PUB_KEY_X_SIZE);
	offset += PUB_KEY_X_SIZE;
	local_memcpy(&resp[offset], &pubkey_y, PUB_KEY_Y_SIZE);
	offset += PUB_KEY_Y_SIZE;
	resp[offset] = KEY_HANDLE_SIZE;
	offset += 1;
	local_memcpy(&resp[offset], &key_handle, KEY_HANDLE_SIZE);
	offset += KEY_HANDLE_SIZE;
	local_memcpy(&resp[offset], &attestation_cert, sizeof(attestation_cert));
	offset += sizeof(attestation_cert);
	local_memcpy(&resp[offset], &formatted_ECDSA_signature, formatted_ECDSA_signature_len);
	offset += formatted_ECDSA_signature_len;
	/* Sanity check */
	if(offset > output_size){
		error = WRONG_LENGTH;
		goto err;
	}
	log_printf("[U2F_FIDO] REGISTER: OK, returning %d bytes of data!\n", output_size);

	return NO_ERROR;
err:
	*len_out = 0;
	return error;
}


/*** Authenticate *****/

/* As defined in the standard:
 *   challenge_parameter (32) | application_parameter (32) | key_handle_len (1) | key_handle (size key_handle_len)
 * NOTE: the "control byte" is in fact the P1 of the APDU command and is not part of the encapsulated request.
 */
typedef struct __attribute__((packed)) {
	uint8_t challenge_parameter[CHALLENGE_PARAMETER_SIZE];
	uint8_t application_parameter[APPLICATION_PARAMETER_SIZE];
	uint8_t key_handle_len;
	uint8_t key_handle[KEY_HANDLE_SIZE];
} authenticate_msg;


int u2f_fido_authenticate(uint8_t u2f_param, uint8_t * msg, uint16_t len_in, uint8_t *resp, uint16_t *len_out)
{
	int error;

	log_printf("[U2F_FIDO] AUTHENTICATE called\n");

	authenticate_msg *in_msg = (authenticate_msg*)msg;

	if((len_out == NULL) || (resp == NULL) || (msg == NULL)){
		error = WRONG_LENGTH;
		goto err;
	}
	if(len_in != sizeof(authenticate_msg)){
		error = WRONG_LENGTH;
		goto err;
	}
	/* Sanity check on the length */
	if(in_msg->key_handle_len != KEY_HANDLE_SIZE){
		error = WRONG_LENGTH;
		goto err;
	}

	if(u2f_param != CHECK_ONLY){
		/* We always ask for user presence except for CHECK_ONLY */
		if(enforce_user_presence(3)){
			error = REQUIRE_TEST_USER_PRESENCE;
			goto err;
		}
	}

	/* Try private key derivation */
	uint8_t priv_key_buff[PRIV_KEY_SIZE] = { 0 };
	uint16_t priv_key_buff_len = PRIV_KEY_SIZE;
	if(generate_ECDSA_priv_key(in_msg->key_handle, in_msg->key_handle_len, priv_key_buff, &priv_key_buff_len, in_msg->application_parameter, sizeof(in_msg->application_parameter))){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
	if(priv_key_buff_len != PRIV_KEY_SIZE){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
	log_printf("[U2F_FIDO] AUTHENTICATE: key handle checked to be OK!\n");
	/* If this was a check only, this is it, leave! */
	if(u2f_param == CHECK_ONLY){
		/* NOTE: as per FIDO standard, this is in fact NOT an error but an success response for the CHECK_ONLY case! */
		log_printf("[U2F_FIDO] AUTHENTICATE: CHECK_ONLY asked and verified to be OK\n");
		error = REQUIRE_TEST_USER_PRESENCE;
		goto err;
	}
	/* libecc internal structure holding the curve parameters */
        const ec_str_params *the_curve_const_parameters;
        ec_params curve_params;
	the_curve_const_parameters = ec_get_curve_params_by_type(SECP256R1);
        /* Get out if getting the parameters went wrong */
        if (the_curve_const_parameters == NULL) {
		error = INVALID_KEY_HANDLE;
                goto err;
        }
        /* Now map the curve parameters to our libecc internal representation */
        import_params(&curve_params, the_curve_const_parameters);
	/* Get our key pair */
	ec_key_pair key_pair;
	ec_priv_key_import_from_buf(&(key_pair.priv_key), &curve_params, priv_key_buff, priv_key_buff_len, ECDSA);
	/* NOTE: we cheat here with libecc we do not need a proper public key to sign and we certainly do not
	 * want to spend so much time in a costly scalar multiplication! This is why we make a minimum effort to
	 * have our public key initialized ...
	 * This kind of ugly, but well we know what we are doing! The signature operation, even if it takes
	 * a key pair as a parameter, does not need a public key per se.
	 * This replaces the cleaner 'ecdsa_init_pub_key(&(key_pair.pub_key), &(key_pair.priv_key))' that would
	 * take approximately 800ms, which is a shame ...
	 */
	key_pair.pub_key.magic = PUB_KEY_MAGIC;
	key_pair.pub_key.key_type = ECDSA;
	/* Sign */
	struct ec_sign_context sig_ctx;

        if(ec_sign_init(&sig_ctx, &key_pair, ECDSA, SHA256)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
        if(ec_sign_update(&sig_ctx, (const uint8_t*)&(in_msg->application_parameter), sizeof(in_msg->application_parameter))){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	uint8_t user_presence = 0x01; /* user presence is enforced */
        if(ec_sign_update(&sig_ctx, (const uint8_t*)&user_presence, 1)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	/* FIXME: properly handle the counter FIXME */
	uint32_t counter = 0;
	uint8_t tmp[4] = { (counter >> 24) & 0xff, (counter >> 16) & 0xff, (counter >> 8)  & 0xff, (counter >> 0)  & 0xff };
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&tmp, 4)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
        if(ec_sign_update(&sig_ctx, (const uint8_t*)&(in_msg->challenge_parameter), sizeof(in_msg->challenge_parameter))){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	/* Finalize signature and place it in the end of the response */
	/* Get our ECDSA signature length */
	uint8_t siglen;
	uint8_t raw_ECDSA_signature[SIG_R_SIZE + SIG_S_SIZE] = { 0 };
        if(ec_get_sig_len(&curve_params, ECDSA, SHA256, &siglen)){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	if(siglen != (SIG_R_SIZE + SIG_S_SIZE)){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
        if(ec_sign_finalize(&sig_ctx, (uint8_t*)&raw_ECDSA_signature, sizeof(raw_ECDSA_signature))){
		error = INVALID_KEY_HANDLE;
                goto err;
        }
	/* Format the ECDSA signature to ANSI X9.62 */
	uint8_t formatted_ECDSA_signature[72] = { 0 };
	uint16_t formatted_ECDSA_signature_len = sizeof(formatted_ECDSA_signature);
	if(format_ECDSA_signature_ansi_x962(raw_ECDSA_signature, siglen, formatted_ECDSA_signature, &formatted_ECDSA_signature_len)){
		error = INVALID_KEY_HANDLE;
		goto err;
	}
	/* Begin to format our output
 	 *    user_presence (1) | counter (4) | signature (71-73 per standard, but actually 70-72)
	 */
	uint16_t output_size = 1 /* user_presence */ + 4 /* counter */ + formatted_ECDSA_signature_len /* signature */;
	/* Sanity check on the available output size */
	if((*len_out) < output_size){
		error = WRONG_LENGTH;
		goto err;
	}
	*len_out = output_size;
	uint16_t offset = 0;
	resp[0] = 0x01; /* we always enforce user presence */
	offset += 1;
	resp[1] = (counter >> 24) & 0xff; /* counter in big endian format */
	resp[2] = (counter >> 16) & 0xff;
	resp[3] = (counter >> 8)  & 0xff;
	resp[4] = (counter >> 0)  & 0xff;
	offset += 4;
	local_memcpy(&resp[offset], &formatted_ECDSA_signature, formatted_ECDSA_signature_len);
	offset += formatted_ECDSA_signature_len;
	/* Sanity check */
	if(offset > output_size){
		error = WRONG_LENGTH;
		goto err;
	}

	return NO_ERROR;
err:
	*len_out = 0;
	return error;
}

/* This is the callback entrypoint from the lower layer */
mbed_error_t u2f_fido_handle_cmd(uint32_t metadata, uint8_t * msg, uint16_t len_in, uint8_t *resp, uint16_t *len_out)
{
	mbed_error_t error = MBED_ERROR_UNSUPORTED_CMD;

	uint8_t u2f_ins   = metadata & 0xff;
	uint8_t u2f_param = (metadata >> 8) & 0xff;

	switch (u2f_ins) {
		case U2F_VERSION: {
			error = u2f_fido_version(u2f_param, msg, len_in, resp, len_out);
			break;
		}
		case U2F_REGISTER: {
			error = u2f_fido_register(u2f_param, msg, len_in, resp, len_out);
			break;
		}
		case U2F_AUTHENTICATE: {
			error = u2f_fido_authenticate(u2f_param, msg, len_in, resp, len_out);
			break;
		}
		default: {
			/* This should not happen thanks to the lower layer */
                    /* defaulting to UNKNOWN_CMD */
			break;
		}
	}

	return error;
}

