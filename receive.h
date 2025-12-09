/*
 * receive.h
 *
 *  Created on: Dec 2, 2025
 *      Author: duser
 */

#ifndef RECEIVE_H_
#define RECEIVE_H_


int verifyCert(int logn, hybridCertificate *cert,
			   uint8_t *pubkey, size_t pub_len);


int processFragment(fragment frag, storedFragments storage);

#endif /* RECEIVE_H_ */




