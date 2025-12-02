/*
 * crypto-handler.h
 *
 *  Created on: Nov 9, 2025
 *      Author: duser
 */

#ifndef CRYPTO_HANDLER_H_
#define CRYPTO_HANDLER_H_

#include <stdbool.h>


void print_hex(const char *label,
				const uint8_t *buf,
				size_t len);

int save_key(const char *filename,
				const uint8_t *data,
				size_t len);

int load_key(const char *filename, uint8_t *data,
				size_t *len, size_t maxlen);

int key_gen(unsigned int logn, bool save,
				uint8_t *privkey, size_t priv_len,
				uint8_t *pubkey, size_t pub_len,
				bool debug);

int sign_message(unsigned int logn, const char *message,
				uint8_t *sig, size_t sig_len,
				uint8_t *privkey, size_t priv_len,
				uint8_t *pubkey, size_t pub_len,
				bool debug);

int verify_signature(unsigned int logn, const char *message,
				uint8_t *sig, size_t sig_len,
				uint8_t *pubkey, size_t pub_len,
				bool debug);



#endif /* CRYPTO_HANDLER_H_ */
