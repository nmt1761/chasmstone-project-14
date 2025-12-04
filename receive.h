/*
 * receive.h
 *
 *  Created on: Dec 2, 2025
 *      Author: duser
 */

#ifndef RECEIVE_H_
#define RECEIVE_H_

hybridCertificate *createTestCert(uint8_t *id, bool genCAKey,
								  uint8_t *privkey, size_t priv_len,
								  uint8_t *pubkey, size_t pub_len);


int processSPDU(SPDU *spdu);

#endif /* RECEIVE_H_ */




