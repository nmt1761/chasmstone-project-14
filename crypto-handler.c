#include "falcon.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>


void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len % 32 != 0) printf("\n");
    printf("\n");
}


int save_key(const char *filename, const uint8_t *data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (!f) return -1;
    fwrite(data, 1, len, f);
    fclose(f);
    return 0;
}


int load_key(const char *filename, uint8_t *data, size_t *len, size_t maxlen) {
    FILE *f = fopen(filename, "rb");
    if (!f) return -1;
    size_t readlen = fread(data, 1, maxlen, f);
    fclose(f);
    *len = readlen;
    return 0;
}




int key_gen(unsigned int logn, bool save,
			uint8_t *privkey, size_t priv_len,
			uint8_t *pubkey, size_t pub_len,
			bool debug) {

	// temp buffer based on security level
	// logn = 9 -> security level 1 (128)
	// logn = 10 -> security level 5 (256)
	uint8_t tmp[FALCON_TMPSIZE_KEYGEN(logn)];

	// setup RNG
	int r;
	shake256_context rng;
	r = shake256_init_prng_from_system(&rng);
	if (r != 0) {
		printf("RNG initialization failed: %d\n", r);
		return 1;
	}

	// generate keys
	r = falcon_keygen_make(&rng, logn,
						   privkey, priv_len,
						   pubkey, pub_len,
						   tmp, sizeof(tmp));
	if (r != 0) {
		printf("Key gen failed: %d\n", r);
		return 1;
	}
	printf("keypair generated.\n\n");

	if (debug) {
		print_hex("Private Key", privkey, priv_len);
		print_hex("Public Key", pubkey, pub_len);
	}

	if (save) {
		// save keys
		save_key("priv.key", privkey, priv_len);
		save_key("pub.key", pubkey, pub_len);
	}

	return 0;
}

int sign_message(unsigned int logn, const char *message,
				uint8_t *sig, size_t sig_len,
				uint8_t *privkey, size_t priv_len,
				uint8_t *pubkey, size_t pub_len,
				bool debug) {

	uint8_t tmp[FALCON_TMPSIZE_SIGNDYN(logn)];

	shake256_context rng;
	shake256_init_prng_from_system(&rng);

	unsigned int r;
	r = falcon_sign_dyn(&rng,
			sig, &sig_len, FALCON_SIG_PADDED,
			privkey, priv_len,
			message, strlen(message),
			tmp, sizeof(tmp));

	if (r != 0) {
			printf("signing failed: %d\n", r);
			return 1;
		}

	if (debug) {
		print_hex("Signature", sig, sig_len);
	}

	return 0;
}

int verify_signature(unsigned int logn, const char *message,
				uint8_t *sig, size_t sig_len,
				uint8_t *pubkey, size_t pub_len,
				bool debug) {

	uint8_t tmp[FALCON_TMPSIZE_VERIFY(logn)];

	unsigned int r;
	r = falcon_verify(sig, sig_len, FALCON_SIG_PADDED,
			  pubkey, pub_len,
			  message, strlen(message),
			  tmp, sizeof(tmp));

	if (debug == true && r == 0) {
			printf("Verified\n");
		} else if (debug == true) {
			printf("Verification failed: %d\n", r);
		}

	return r;
}
