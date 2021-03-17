#include "libc/types.h"
#include "libc/random.h"
#include "libc/string.h"
#include "libsig.h"
#include "hmac.h"
#include "fido.h"

//#define UNSAFE_LOCAL_KEY_HANDLE_GENERATION
/* Include our private data */
#include "AUTH/FIDO/attestation.der.h"
#include "AUTH/FIDO/attestation_key.der.h"


#ifndef UNSAFE_LOCAL_KEY_HANDLE_GENERATION
extern unsigned char fido_attestation_privkey[FIDO_PRIV_KEY_SIZE];
#endif

userpresence_request_cb_t cb_userpresence = NULL;

mbed_error_t u2f_fido_initialize(userpresence_request_cb_t userpresence_cb)
{
    log_printf("[U2F_FIDO] declaring userpresence & wink backend callbacks\n");
    cb_userpresence = userpresence_cb;
    return MBED_ERROR_NONE;
}

/* Primitive to enforce user presence */
static int enforce_user_presence(uint32_t timeout __attribute__((unused)))
{
#ifdef CONFIG_USR_LIB_FIDO_EMULATE_USERPRESENCE
	log_printf("[U2F_FIDO] user presence emulated!\n");
# if USR_LIB_FIDO_EMULATE_NOUSER
	return 1;
# else
    return 0;
# endif
#else
	log_printf("[U2F_FIDO] Wait for user presence with timeout %d seconds\n", timeout);
	/* Test for user presence with timeout in seconds */
	// TODO via backend return platform_enforce_user_presence(timeout);
    if (cb_userpresence != NULL) {
        if (cb_userpresence(timeout*1000) == true) {
            return 0;
        }
    }
    return 1;
#endif
}

/************* UNSAFE_LOCAL_KEY_HANDLE_GENERATION ***********************/

#ifdef UNSAFE_LOCAL_KEY_HANDLE_GENERATION
#define KEY_HANDLE_NONCE_SIZE 32
/* HMAC Keys for Key handle and private keys computations */
static const uint8_t master_key_hmac1[32] = { 0x01, 0x02 };
static const uint8_t master_key_hmac2[32] = { 0x11, 0x22 };

/* Key Handle generation function */
static mbed_error_t generate_key_handle(uint8_t *key_handle, uint16_t *key_handle_len, const uint8_t *application_parameter, uint16_t application_parameter_len)
{
        mbed_error_t errcode = MBED_ERROR_UNKNOWN;

        log_printf("[U2F_FIDO] %s\n", __func__);
	/* Sanity check */
	if((key_handle == NULL) || (key_handle_len == NULL)){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	/* Bad length */
	if(*key_handle_len < FIDO_KEY_HANDLE_SIZE){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	*key_handle_len = FIDO_KEY_HANDLE_SIZE;
	/* Get a 32 bytes random value */
	uint8_t Nonce[KEY_HANDLE_NONCE_SIZE];
	if (get_random((unsigned char*)&Nonce, KEY_HANDLE_NONCE_SIZE)){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
        /* First compute the master key = SHA-256(key1 || key2) */
        uint8_t master_key[32] = { 0 };
        sha256_context sha256_ctx;
        sha256_init(&sha256_ctx);
        sha256_update(&sha256_ctx, master_key_hmac1, sizeof(master_key_hmac1));
        sha256_update(&sha256_ctx, master_key_hmac2, sizeof(master_key_hmac2));
        sha256_final(&sha256_ctx, master_key);
        /* Compute key handle */
	memcpy(key_handle, Nonce, KEY_HANDLE_NONCE_SIZE);
	/* Now compute the hmac of the None with Key1 */
	hmac_context hmac_ctx;
	uint32_t hmac_len = 32;
	if(hmac_init(&hmac_ctx, master_key, sizeof(master_key), SHA256)){
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
            log_printf("[U2F_FIDO] error while calculating HMAC!\n");
            errcode = MBED_ERROR_UNKNOWN;
	    goto err;
	}

        errcode = MBED_ERROR_NONE;
err:
	return errcode;
}

/* Key Handle check function */
static mbed_error_t check_key_handle(const uint8_t *key_handle, uint16_t key_handle_len, const uint8_t *application_parameter, uint16_t application_parameter_len)
{
        mbed_error_t errcode = MBED_ERROR_UNKNOWN;
        log_printf("[U2F_FIDO] %s\n", __func__);

	/* Sanity check */
	if (key_handle == NULL) {
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	/* Bad length */
	if(key_handle_len < FIDO_KEY_HANDLE_SIZE){
        errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
        /* First compute the master key = SHA-256(key1 || key2) */
        uint8_t master_key[32] = { 0 };
        sha256_context sha256_ctx;
        sha256_init(&sha256_ctx);
        sha256_update(&sha256_ctx, master_key_hmac1, sizeof(master_key_hmac1));
        sha256_update(&sha256_ctx, master_key_hmac2, sizeof(master_key_hmac2));
        sha256_final(&sha256_ctx, master_key);
	/* Compute the hmac of the Nonce with the master key */
	hmac_context hmac_ctx;
        uint8_t hmac[SHA256_DIGEST_SIZE];
	uint32_t hmac_len = sizeof(hmac);
	if (hmac_init(&hmac_ctx, master_key, sizeof(master_key), SHA256)) {
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
static mbed_error_t generate_ECDSA_priv_key(const uint8_t *key_handle, uint16_t key_handle_len, uint8_t *priv_key, uint16_t *priv_key_len, const uint8_t *application_parameter, uint16_t application_parameter_len)
{
        mbed_error_t errcode = MBED_ERROR_UNKNOWN;
        log_printf("[U2F_FIDO] %s\n", __func__);
	/* Sanity checks */
	if((key_handle == NULL) || (priv_key_len == NULL) || (priv_key == NULL)){
                errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	if(key_handle_len != FIDO_KEY_HANDLE_SIZE){
                errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	if(*priv_key_len < FIDO_PRIV_KEY_SIZE){
                errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	/* Check the key handle authenticity */
	if(check_key_handle(key_handle, key_handle_len, application_parameter, application_parameter_len)){
                errcode = MBED_ERROR_INVCREDENCIALS;
		goto err;
	}
	(*priv_key_len) = FIDO_PRIV_KEY_SIZE;
        /* First compute the master key = SHA-256(key1 || key2) */
        uint8_t master_key[32] = { 0 };
        sha256_context sha256_ctx;
        sha256_init(&sha256_ctx);
        sha256_update(&sha256_ctx, master_key_hmac1, sizeof(master_key_hmac1));
        sha256_update(&sha256_ctx, master_key_hmac2, sizeof(master_key_hmac2));
        sha256_final(&sha256_ctx, master_key);
	/* We generate our private key  */
	hmac_context hmac_ctx;
	uint32_t hmac_len = (*priv_key_len);
	if(hmac_init(&hmac_ctx, master_key, sizeof(master_key), SHA256)){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
	hmac_update(&hmac_ctx, key_handle, FIDO_KEY_HANDLE_SIZE);
	hmac_finalize(&hmac_ctx, priv_key, &hmac_len);
	if(hmac_len != FIDO_PRIV_KEY_SIZE){
        errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
#if 1
	/* We want to ensure that the private key is < q (the order of the curve) */
        /* libecc internal structure holding the curve parameters */
        const ec_str_params *the_curve_const_parameters;
        ec_params curve_params;
        the_curve_const_parameters = ec_get_curve_params_by_type(SECP256R1);
        /* Get out if getting the parameters went wrong */
        if (the_curve_const_parameters == NULL) {
            log_printf("[U2F_FIDO] error while building curve const params\n");
            errcode = MBED_ERROR_UNKNOWN;
            goto err;
        }
        /* Now map the curve parameters to our libecc internal representation */
        import_params(&curve_params, the_curve_const_parameters);
	/* Import the private key as NN */
	nn pkey;
	nn_init_from_buf(&pkey, priv_key, *priv_key_len);
	if(nn_cmp(&pkey, &(curve_params.ec_gen_order)) > 0){
printf("=========>!!!!! GREATER THAN Q\n");
printf("====== XXXXXXXXXXXX==========\n");
hexdump(priv_key, 32);
printf("====== XXXXXXXXXXXX==========\n");

	}
#if 0
	/* Compute our modulo */
	nn_mod(&pkey, &pkey, &(curve_params.ec_gen_order));
	/* Export private key again in buffer */
	nn_export_to_buf(priv_key, *priv_key_len, &pkey);
#endif
#endif
        errcode = MBED_ERROR_NONE;
err:
	return errcode;
}
#else /* !UNSAFE_LOCAL_KEY_HANDLE_GENERATION */
/* just specify prototypes, set at link time */
#if 0
extern cb_fido_register_t callback_fido_register;
extern cb_fido_authenticate_t callback_fido_authenticate;
#endif
#endif
/****************************************************************************************/

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

static mbed_error_t format_ECDSA_signature_ansi_x962(const uint8_t *raw_ECDSA_signature, uint8_t siglen, uint8_t *formatted_ECDSA_signature, uint16_t *formatted_ECDSA_signature_len)
{
	/* NOTE: this is a very simple and straightforward way of encoding the signature, yet quite optimal
	 * and without appatent issues.
	 */
        mbed_error_t errcode = MBED_ERROR_UNKNOWN;
	/* Sanity check on raw signature length: it should be 2 256-bit big numbers (64 bytes) */
	if(siglen != (FIDO_SIG_R_SIZE + FIDO_SIG_S_SIZE)){
                errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	/* Extract r and s that are each half the raw signature */
	const uint8_t *r = raw_ECDSA_signature;
	const uint8_t *s = raw_ECDSA_signature + (siglen / 2);
	/* Compute our final length */
	uint16_t out_len = 2 /* SEQUENCE TL */ + 2 /* BIGNUM TL */ + FIDO_SIG_R_SIZE + 2 /* BIGNUM TL */+ FIDO_SIG_S_SIZE; /* = 70 byes minimum size */
	if(r[0] & 0x80){ /* Check MSB of r, add prepending 0x00 if necessary */
		out_len++;
	}
	if(s[0] & 0x80){ /* Check MSB of s, add prepending 0x00 if necessary */
		out_len++;
	}
	/* => at this point, we should have a maximum size out_len of 72 bytes */
	/* Sanity check */
	if((out_len > (*formatted_ECDSA_signature_len)) || (out_len <= 2)){
                errcode = MBED_ERROR_INVPARAM;
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
		formatted_ECDSA_signature[offset] = FIDO_SIG_R_SIZE + 1;
		offset += 1;
		formatted_ECDSA_signature[offset] = 0x00;
		offset += 1;
	}
	else{
		formatted_ECDSA_signature[offset] = FIDO_SIG_R_SIZE;
		offset += 1;
	}
	memcpy(&formatted_ECDSA_signature[offset], r, FIDO_SIG_R_SIZE);
	offset += FIDO_SIG_R_SIZE;
	/* Encode s */
	formatted_ECDSA_signature[offset] = ASN1_INTEGER_TAG; /* ASN.1 INTEGER for s */
	offset += 1;
	if(s[0] & 0x80){
		formatted_ECDSA_signature[offset] = FIDO_SIG_S_SIZE + 1;
		offset += 1;
		formatted_ECDSA_signature[offset] = 0x00;
		offset += 1;
	}
	else{
		formatted_ECDSA_signature[offset] = FIDO_SIG_S_SIZE;
		offset += 1;
	}
	memcpy(&formatted_ECDSA_signature[offset], s, FIDO_SIG_S_SIZE);
	offset += FIDO_SIG_S_SIZE;

	/* Sanity check */
	if(offset > (*formatted_ECDSA_signature_len)){
                errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	errcode = MBED_ERROR_NONE;
err:
	return errcode;
}

/* FIXME: properly handle the counter FIXME */
/* XXX: For now we use a simple global counter in SRAM for tests */
static volatile uint32_t fido_global_counter = 0;
static mbed_error_t get_current_auth_counter(__attribute__((unused)) const uint8_t application_parameter[FIDO_APPLICATION_PARAMETER_SIZE], uint32_t *counter)
{
    mbed_error_t errcode = MBED_ERROR_UNKNOWN;
    if((application_parameter == NULL) || (counter == NULL)){
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

    *counter = fido_global_counter;

    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}

static mbed_error_t increment_current_auth_counter(__attribute__((unused)) const uint8_t application_parameter[FIDO_APPLICATION_PARAMETER_SIZE])
{
    mbed_error_t errcode = MBED_ERROR_UNKNOWN;

    fido_global_counter++;

    errcode = MBED_ERROR_NONE;

    return errcode;
}

/*** Version *****/
const uint8_t u2f_fido_version_str[] = "U2F_V2";

static int u2f_fido_version(uint8_t u2f_param __attribute__((unused)), const uint8_t * msg __attribute__((unused)), uint16_t len_in, uint8_t *resp, uint16_t *len_out)
{
	int error;

	if((len_out == NULL) || (resp == NULL)){
		error = FIDO_WRONG_LENGTH;
		goto err_init;
	}
	/* We do not expect any data in this command */
	if(len_in != 0){
		error = FIDO_WRONG_LENGTH;
		goto err;
	}
	/* Sanity check on the available output size */
	if(*len_out < (sizeof(u2f_fido_version_str) - 1)){
		error = FIDO_WRONG_LENGTH;
		goto err;
	}
	/* We are asked to send the version */
	*len_out = (sizeof(u2f_fido_version_str) - 1);
	memcpy(resp, u2f_fido_version_str, sizeof(u2f_fido_version_str) - 1);

	return FIDO_NO_ERROR;
err:
	*len_out = 0;
err_init:
	return error;
}

/*** Register *****/
/* As defined in the FIDO U2F specification
 *    challenge_parameter (32) | application_parameter (32)
 */
typedef struct __attribute__((packed)) {
	uint8_t challenge_parameter[FIDO_CHALLENGE_PARAMETER_SIZE];
	uint8_t application_parameter[FIDO_APPLICATION_PARAMETER_SIZE];
} register_msg;

static int u2f_fido_register(uint8_t u2f_param __attribute__((unused)), const uint8_t * msg, uint16_t len_in, uint8_t *resp, uint16_t *len_out)
{
	int error = 0;
	const register_msg *in_msg = (const register_msg*)msg;
	log_printf("[U2F_FIDO] REGISTER called\n");

	if((len_out == NULL) || (resp == NULL) || (msg == NULL)){
		error = FIDO_WRONG_LENGTH;
		goto err_init;
	}
	/* Sanity check on the inputs
	 * Should be:
	 *   challenge_parameter (32) | application_parameter (32)
	 */
	if(len_in != sizeof(register_msg)){
		error = FIDO_WRONG_LENGTH;
		goto err;
	}
	/* We always ask for user presence in all the cases */
	if(enforce_user_presence(3)){
                log_printf("[U2F_FIDO] user presence check failed\n");
		error = FIDO_REQUIRE_TEST_USER_PRESENCE;
		goto err;
	}

	/* Generate a Key Handle and a key pair */
	uint8_t key_handle[FIDO_KEY_HANDLE_SIZE] = { 0 };
	uint16_t key_handle_len = FIDO_KEY_HANDLE_SIZE;
	uint8_t priv_key_buff[FIDO_PRIV_KEY_SIZE] = { 0 };
	uint16_t priv_key_buff_len = FIDO_PRIV_KEY_SIZE;
	ec_priv_key priv_key;
	ec_pub_key pub_key;
	/* Generate Key Handle and private key */
#ifdef UNSAFE_LOCAL_KEY_HANDLE_GENERATION
	if (generate_key_handle(key_handle, &key_handle_len, in_msg->application_parameter, sizeof(in_msg->application_parameter))) {
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}

	if(generate_ECDSA_priv_key(key_handle, key_handle_len, priv_key_buff, &priv_key_buff_len, in_msg->application_parameter, sizeof(in_msg->application_parameter)) != MBED_ERROR_NONE){
                log_printf("[U2F FIDO] error while generate ECDSA priv key\n");
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
#else
	if(callback_fido_register(in_msg->application_parameter, sizeof(in_msg->application_parameter), key_handle, &key_handle_len, priv_key_buff, &priv_key_buff_len)){
                log_printf("[U2F FIDO] error in FIDO callback REGISTER (to the backend)\n");
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
printf("====== XXXXXXXXXXXX==========\n");
hexdump(priv_key_buff, 32);
printf("====== XXXXXXXXXXXX==========\n");

#endif
	if(priv_key_buff_len != FIDO_PRIV_KEY_SIZE){
                log_printf("[U2F FIDO] invalid ECDSA priv key size\n");
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}

	log_printf("[U2F_FIDO] REGISTER: key handle generated ...\n");
	/* libecc internal structure holding the curve parameters */
        const ec_str_params *the_curve_const_parameters;
        ec_params curve_params;
	the_curve_const_parameters = ec_get_curve_params_by_type(SECP256R1);
        /* Get out if getting the parameters went wrong */
        if (the_curve_const_parameters == NULL) {
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
        /* Now map the curve parameters to our libecc internal representation */
        import_params(&curve_params, the_curve_const_parameters);
	/* Import private key from buffer */
	ec_priv_key_import_from_buf(&priv_key, &curve_params, priv_key_buff, priv_key_buff_len, ECDSA);
	/* Now compute our public key */
	ecdsa_init_pub_key(&pub_key, &priv_key);
	/* Extract x and y from our public key in buffers */
	uint8_t pubkey_x_y[FIDO_PUB_KEY_X_SIZE + FIDO_PUB_KEY_Y_SIZE] = { 0 };
	/* Unique affine equivalent representation */
	prj_pt_export_to_aff_buf(&(pub_key.y), (uint8_t*)&pubkey_x_y, sizeof(pubkey_x_y));
	/* Import attestation private key for signing */
	ec_key_pair attestation_key_pair;

	/* Import the attestation private key and the public key */
	/* Sanity check for th eprivate key */
	if(sizeof(fido_attestation_privkey) != FIDO_PRIV_KEY_SIZE){
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
	ec_priv_key_import_from_buf(&(attestation_key_pair.priv_key), &curve_params, (const uint8_t*)&fido_attestation_privkey, sizeof(fido_attestation_privkey), ECDSA);
	/* NOTE: we cheat here with libecc we do not need a proper public key to sign and we certainly do not
	 * want to spend so much time in importing an unnecessary curve point with costly check operations!
         * This is why we make a minimum effort to have our public key initialized ...
	 */
	attestation_key_pair.pub_key.magic = PUB_KEY_MAGIC;
	attestation_key_pair.pub_key.key_type = ECDSA;

	/* Sign 0x00 | application_parameter | challenge_parameter | key_handle | pub_key */
	struct ec_sign_context sig_ctx;
        if(ec_sign_init(&sig_ctx, &attestation_key_pair, ECDSA, SHA256)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }

	uint8_t reserved = 0x00;
        if(ec_sign_update(&sig_ctx, (const uint8_t*)&reserved, 1)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&(in_msg->application_parameter), sizeof(in_msg->application_parameter))){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&(in_msg->challenge_parameter), sizeof(in_msg->challenge_parameter))){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)key_handle, FIDO_KEY_HANDLE_SIZE)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	uint8_t uncompressed_point = ASN1_UNCOMPRESSED_POINT_TAG;
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&uncompressed_point, 1)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&pubkey_x_y[0], FIDO_PUB_KEY_X_SIZE)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&pubkey_x_y[FIDO_PUB_KEY_X_SIZE], FIDO_PUB_KEY_Y_SIZE)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	/* Finalize signature and place it in the end of the response */
	/* Get our ECDSA signature length */
	uint8_t siglen;
	uint8_t raw_ECDSA_signature[FIDO_SIG_R_SIZE + FIDO_SIG_S_SIZE] = { 0 };
        if(ec_get_sig_len(&curve_params, ECDSA, SHA256, &siglen)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	if(siglen != (FIDO_SIG_R_SIZE + FIDO_SIG_S_SIZE)){
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
        if(ec_sign_finalize(&sig_ctx, (uint8_t*)&raw_ECDSA_signature, sizeof(raw_ECDSA_signature))){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	log_printf("[U2F_FIDO] REGISTER: ECDSA signature performed ...\n");

	/* Format the ECDSA signature to ANSI X9.62 */
	uint8_t formatted_ECDSA_signature[72] = { 0 };
	uint16_t formatted_ECDSA_signature_len = sizeof(formatted_ECDSA_signature);
	if(format_ECDSA_signature_ansi_x962(raw_ECDSA_signature, siglen, formatted_ECDSA_signature, &formatted_ECDSA_signature_len)){
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
	/* Begin to format our output
 	 *    0x05 | user_pub_key (65) | key_handle_len (1) | key_handle (size key_handle_len) | fido_attestation_cert | signature (71-73 per standard, actually 70-72)
	 */
	uint16_t output_size = 1 /* reserved = 0x05 */ + (FIDO_PUB_KEY_X_SIZE + FIDO_PUB_KEY_Y_SIZE + 1) /* user_pub_key */ \
			     + 1 /* key_handle_len */+ FIDO_KEY_HANDLE_SIZE /* key_handle */ + sizeof(fido_attestation_cert) /* fido_attestation_cert */ \
			     + formatted_ECDSA_signature_len /* signature */;
	/* Sanity check on the available output size */
	if((*len_out) < output_size){
		error = FIDO_WRONG_LENGTH;
		goto err;
	}
	*len_out = output_size;
	uint16_t offset = 0;
	resp[offset] = 0x05; /* Reserved */
	offset += 1;
	resp[offset] = ASN1_UNCOMPRESSED_POINT_TAG; /* Uncompressed point */
	offset += 1;
	local_memcpy(&resp[offset], &pubkey_x_y[0], FIDO_PUB_KEY_X_SIZE);
	offset += FIDO_PUB_KEY_X_SIZE;
	local_memcpy(&resp[offset], &pubkey_x_y[FIDO_PUB_KEY_X_SIZE], FIDO_PUB_KEY_Y_SIZE);
	offset += FIDO_PUB_KEY_Y_SIZE;
	resp[offset] = FIDO_KEY_HANDLE_SIZE;
	offset += 1;
	local_memcpy(&resp[offset], &key_handle, FIDO_KEY_HANDLE_SIZE);
	offset += FIDO_KEY_HANDLE_SIZE;
	local_memcpy(&resp[offset], &fido_attestation_cert, sizeof(fido_attestation_cert));
	offset += sizeof(fido_attestation_cert);
	local_memcpy(&resp[offset], &formatted_ECDSA_signature, formatted_ECDSA_signature_len);
	offset += formatted_ECDSA_signature_len;
	/* Sanity check */
	if(offset > output_size){
		error = FIDO_WRONG_LENGTH;
		goto err;
	}
	log_printf("[U2F_FIDO] REGISTER: OK, returning %d bytes of data!\n", output_size);

	return FIDO_NO_ERROR;
err:
	*len_out = 0;
err_init:
	return error;
}


/*** Authenticate *****/

/* As defined in the standard:
 *   challenge_parameter (32) | application_parameter (32) | key_handle_len (1) | key_handle (size key_handle_len)
 * NOTE: the "control byte" is in fact the P1 of the APDU command and is not part of the encapsulated request.
 */
typedef struct __attribute__((packed)) {
	uint8_t challenge_parameter[FIDO_CHALLENGE_PARAMETER_SIZE];
	uint8_t application_parameter[FIDO_APPLICATION_PARAMETER_SIZE];
	uint8_t key_handle_len;
	uint8_t key_handle[FIDO_KEY_HANDLE_SIZE];
} authenticate_msg;


static int u2f_fido_authenticate(uint8_t u2f_param, const uint8_t * msg, uint16_t len_in, uint8_t *resp, uint16_t *len_out)
{
	int error;

	log_printf("[U2F_FIDO] AUTHENTICATE called\n");

	const authenticate_msg *in_msg = (const authenticate_msg*)msg;

	if((len_out == NULL) || (resp == NULL) || (msg == NULL)){
		error = FIDO_WRONG_LENGTH;
		goto err_init;
	}
        /* Sanity check on the length of our authenticate request */
	if(len_in != sizeof(authenticate_msg)){
                log_printf("[U2F FIDO] invalid message size\n");
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
	/* Sanity check on the length of our key handle */
	if(in_msg->key_handle_len != FIDO_KEY_HANDLE_SIZE){
                log_printf("[U2F FIDO] invalid Key Handle size\n");
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}

	if(u2f_param != FIDO_CHECK_ONLY){
		/* We always ask for user presence except for FIDO_CHECK_ONLY */
		if(enforce_user_presence(3)){
                        log_printf("[U2F FIDO] user presence not enforce (it should be)\n");
			error = FIDO_REQUIRE_TEST_USER_PRESENCE;
			goto err;
		}
	}
	/* If this is a check only, this is it, check and leave! */
	if(u2f_param == FIDO_CHECK_ONLY){
#ifdef UNSAFE_LOCAL_KEY_HANDLE_GENERATION
		if(check_key_handle(in_msg->key_handle, in_msg->key_handle_len, in_msg->application_parameter, sizeof(in_msg->application_parameter))){
#else
		if(callback_fido_authenticate(in_msg->application_parameter, sizeof(in_msg->application_parameter), in_msg->key_handle, in_msg->key_handle_len, NULL, NULL, 1)){
#endif
                	error = FIDO_INVALID_KEY_HANDLE;
			goto err;
		}
		/* NOTE: as per FIDO standard, this is in fact NOT an error but an success response for the FIDO_CHECK_ONLY case! */
		log_printf("[U2F_FIDO] AUTHENTICATE: FIDO_CHECK_ONLY asked and verified to be OK\n");
		error = FIDO_REQUIRE_TEST_USER_PRESENCE;
		goto err;
	}
	/* This not a CHECK ONLY, we derive our private key and go on to AUTHENTICATE */
	/* Try private key derivation */
	uint8_t priv_key_buff[FIDO_PRIV_KEY_SIZE] = { 0 };
	uint16_t priv_key_buff_len = FIDO_PRIV_KEY_SIZE;
#ifdef UNSAFE_LOCAL_KEY_HANDLE_GENERATION
	if(generate_ECDSA_priv_key(in_msg->key_handle, in_msg->key_handle_len, priv_key_buff, &priv_key_buff_len, in_msg->application_parameter, sizeof(in_msg->application_parameter)) != MBED_ERROR_NONE){
#else
	if(callback_fido_authenticate(in_msg->application_parameter, sizeof(in_msg->application_parameter), in_msg->key_handle, in_msg->key_handle_len, priv_key_buff, &priv_key_buff_len, 0)){
#endif
                log_printf("[U2F FIDO] error while generate ECDSA priv key\n");
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
printf("====== XXXXXXXXXXXX==========\n");
hexdump(priv_key_buff, 32);
printf("====== XXXXXXXXXXXX==========\n");


	if(priv_key_buff_len != FIDO_PRIV_KEY_SIZE){
                log_printf("[U2F FIDO] error in private key length\n");
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
	log_printf("[U2F_FIDO] AUTHENTICATE: key handle checked to be OK!\n");
	/* libecc internal structure holding the curve parameters */
        const ec_str_params *the_curve_const_parameters;
        ec_params curve_params;
	the_curve_const_parameters = ec_get_curve_params_by_type(SECP256R1);
        /* Get out if getting the parameters went wrong */
        if (the_curve_const_parameters == NULL) {
		error = FIDO_INVALID_KEY_HANDLE;
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
	 * This is kind of ugly, but well we know what we are doing! The signature operation, even if it takes
	 * a key pair as a parameter, does not need a public key per se.
	 * This replaces the cleaner 'ecdsa_init_pub_key(&(key_pair.pub_key), &(key_pair.priv_key))' that would
	 * take approximately 800ms, which is a shame ... (in addition to potentially expose the private key
         * to side-channels leakage).
	 */
	key_pair.pub_key.magic = PUB_KEY_MAGIC;
	key_pair.pub_key.key_type = ECDSA;
	/* Sign */
	struct ec_sign_context sig_ctx;

        if(ec_sign_init(&sig_ctx, &key_pair, ECDSA, SHA256)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
        if(ec_sign_update(&sig_ctx, (const uint8_t*)&(in_msg->application_parameter), sizeof(in_msg->application_parameter))){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	uint8_t user_presence = 0x01; /* user presence is enforced */
        if(ec_sign_update(&sig_ctx, (const uint8_t*)&user_presence, 1)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
        /* Get the current authentication counter value for the application parameter */
	uint32_t counter;
        if(get_current_auth_counter(in_msg->application_parameter, &counter) != MBED_ERROR_NONE){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
        /* Increment the current authentication counter for the application parameter */
        if(increment_current_auth_counter(in_msg->application_parameter) != MBED_ERROR_NONE){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	uint8_t tmp[4] = { (counter >> 24) & 0xff, (counter >> 16) & 0xff, (counter >> 8)  & 0xff, (counter >> 0)  & 0xff };
	if(ec_sign_update(&sig_ctx, (const uint8_t*)&tmp, 4)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
        if(ec_sign_update(&sig_ctx, (const uint8_t*)&(in_msg->challenge_parameter), sizeof(in_msg->challenge_parameter))){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	/* Finalize signature and place it in the end of the response */
	/* Get our ECDSA signature length */
	uint8_t siglen;
	uint8_t raw_ECDSA_signature[FIDO_SIG_R_SIZE + FIDO_SIG_S_SIZE] = { 0 };
        if(ec_get_sig_len(&curve_params, ECDSA, SHA256, &siglen)){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	if(siglen != (FIDO_SIG_R_SIZE + FIDO_SIG_S_SIZE)){
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
        if(ec_sign_finalize(&sig_ctx, (uint8_t*)&raw_ECDSA_signature, sizeof(raw_ECDSA_signature))){
		error = FIDO_INVALID_KEY_HANDLE;
                goto err;
        }
	/* Format the ECDSA signature to ANSI X9.62 */
	uint8_t formatted_ECDSA_signature[72] = { 0 };
	uint16_t formatted_ECDSA_signature_len = sizeof(formatted_ECDSA_signature);
	if(format_ECDSA_signature_ansi_x962(raw_ECDSA_signature, siglen, formatted_ECDSA_signature, &formatted_ECDSA_signature_len)){
		error = FIDO_INVALID_KEY_HANDLE;
		goto err;
	}
	/* Begin to format our output
 	 *    user_presence (1) | counter (4) | signature (71-73 per standard, but actually 70-72)
	 */
	uint16_t output_size = 1 /* user_presence */ + 4 /* counter */ + formatted_ECDSA_signature_len /* signature */;
	/* Sanity check on the available output size */
	if((*len_out) < output_size){
		error = FIDO_WRONG_LENGTH;
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
		error = FIDO_WRONG_LENGTH;
		goto err;
	}

	return FIDO_NO_ERROR;
err:
	*len_out = 0;
err_init:
	return error;
}

/* This is the callback entrypoint from the lower layer */
mbed_error_t u2f_fido_handle_cmd(uint32_t metadata, const uint8_t *msg, uint16_t len_in, uint8_t *resp, uint16_t *len_out)
{
	mbed_error_t error = MBED_ERROR_UNSUPORTED_CMD;

	uint8_t u2f_ins   = metadata & 0xff;
	uint8_t u2f_param = (metadata >> 8) & 0xff;

	switch (u2f_ins) {
		case FIDO_VERSION: {
			error = u2f_fido_version(u2f_param, msg, len_in, resp, len_out);
			break;
		}
		case FIDO_REGISTER: {
			error = u2f_fido_register(u2f_param, msg, len_in, resp, len_out);
			break;
		}
		case FIDO_AUTHENTICATE: {
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

