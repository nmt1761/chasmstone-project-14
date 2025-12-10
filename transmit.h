/*
 *
 * Author: Nathan M Trumble
 *
 * Date 12/04/2025
 */

#include "CHASM-structs.h"

#ifndef TRANSMIT_H_
#define TRANSMIT_H_


unsigned char *serializeCertificate(hybridCertificate *HCid);

SPDU *createSPDU(unsigned int logn,
				    uint8_t *privKey, size_t privLen,
		  	  	    uint8_t *pubKey, size_t pubLen);

fragmentHead *FRAGMENT(hybridCertificate HCid, int q, float r, int B, int Nrb, BSMData *M);

int transmit();

#endif
