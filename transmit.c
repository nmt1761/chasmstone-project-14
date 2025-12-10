#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "crypto-handler.h"
#include "CHASM-structs.h"
#include "falcon.h"


unsigned char *serializeCertificate(hybridCertificate *HCid) {
	  // turning a struct hybridCertificate into one long string of hex values for our fragmentation protocol to digest
	  unsigned char *serializedHC = (unsigned char *)malloc(COMPLETE_HYBRID_CERT_FRAGMENT_SIZE);;

	  int curIndex = 0;

	  memcpy(serializedHC, HCid->id, 4);
	  curIndex += VEHICLE_ID_SIZE;

	  serializedHC[curIndex] = (unsigned char)HCid->securityHeaders;
	  curIndex += SECURITY_HEADERS_SIZE;

	  memcpy(serializedHC + curIndex, HCid->ECDSAPublickey, ECDSA_PUBLIC_KEY_SIZE);
	  curIndex += ECDSA_PUBLIC_KEY_SIZE;

	  memcpy(serializedHC + curIndex, HCid->PQCPublicKey, PQC_PUBLIC_KEY_SIZE);
	  curIndex += PQC_PUBLIC_KEY_SIZE;

	  memcpy(serializedHC + curIndex, HCid->ECDSASignatureCA, ECDSA_SIG_SIZE);
	  curIndex += ECDSA_SIG_SIZE;

	  memcpy(serializedHC + curIndex, HCid->PQCSignatureCA, PQC_SIG_SIZE);
	  curIndex += PQC_SIG_SIZE;


	  return serializedHC;
}

  // FRAGMENT function will return storedFragments struct containing (number of certificate fragments, (an array of all fragments) )
fragmentHead *FRAGMENT(hybridCertificate *HCid, int q, float r, int B, int Nrb, BSMData *M) {
    printf("start of fragment\n");
    // Calculating some variables needed for fragmentation function

	// minimum size of an SPDU
    //float minS = sizeof(HCid.securityHeaders) + sizeof(S.data) + sizeof(HCid->ECDSASignatureCA) + sizeof(HCid->PQCSignatureCA);
	printf("A\n");
    size_t minS = SECURITY_HEADERS_SIZE
    			  + 64 //strlen(M->data)
    			  + ECDSA_SIG_SIZE
				  + PQC_SIG_SIZE;
    printf("minS=%d, ", minS);
    
    // maximum size of transport block given our MCS 
    //float maxTB  = 12 * 10 * log2(q) * r * (Nrb - 2) * (1.0 / 8.0);
    float bitsPerSymbol = log2f(q);
    float rb = (float)(Nrb - 2);
    printf("Nrb=%f, rb=%f, ", Nrb, rb);
    float bits = 12.0f * 10.0f
    		* bitsPerSymbol * r * rb;
    printf("bitsPerSymbol=%f, r=%f, bits=%f, ", bitsPerSymbol, r, bits);
    size_t maxTB = bits / 8.0f;
    printf("maxTB=%d, ", maxTB);

    // maxmimum size of HCf (certificate fragment)
    //float maxHCf = sizeof(maxTB) - sizeof(minS); //possibly check if double sizeof causes error
    float maxHCF = maxTB - minS;
    // number of certificate fragments
    printf("\n%f / %f, ", (float)COMPLETE_HYBRID_CERT_FRAGMENT_SIZE, (float)maxHCF);
    float ratio = 1888.0f / (float)maxHCF; //should be COMPLETE_HYBRID_CERT_FRAGMENT_SIZE not hard coded but weird things happen
    printf("ratio=%f, \n", ratio);
    float nf = ceilf(ratio);  // uses ceiling function, possibly change to (certLength + maxHCF - 1) / maxHCF
    printf("maxHCF=%f, nf=%f\n", maxHCF, nf);

    unsigned char *serializedHC = serializeCertificate(HCid); //double check validity
    fragmentHead *head = malloc(sizeof(fragmentHead));		//fragment head initialized
    memcpy(head->id, HCid->id, 4);
    head->headFragment = malloc(sizeof(fragment));
    head->headFragment->fragmentString = malloc(maxHCF);	//headfragment value complete

    printf("A\n");
    fragment *prev = NULL;
    size_t offset = 0;	//length of certificate currently fragmented
    size_t certLength = COMPLETE_HYBRID_CERT_FRAGMENT_SIZE;	//length of serialized certificate

    int count = 0;
    while (offset < certLength){
		size_t chunk = certLength - offset;		//length of certificate left to fragment
		if (chunk > maxHCF) {		//if certificate is not done, chunk equals the amount of data we want to fragment
			chunk = maxHCF;
		}

		fragment *frag = malloc(sizeof(fragment));
		frag->fragmentLen = chunk;
		frag->fragmentString = malloc(chunk);
		memcpy(frag->fragmentString, serializedHC + offset, chunk);
		frag->nextFragment = NULL;
		if (count == 0) {
			head->headFragment = frag;
		}

		prev->nextFragment = frag;
		prev = frag;
		offset += chunk;
		count ++;
		printf("%d", count);
	}

    
    return head; // (nf, {HC1, ..., HCnf}) <- maybe no nf
  }
  

SPDU *createSPDU(unsigned int logn,
				    uint8_t *privKey, size_t privLen,
		  	  	    uint8_t *pubKey, size_t pubLen) {

	size_t sigLen  = FALCON_SIG_PADDED_SIZE(logn);
	uint8_t id[4] = {0x01,0x01,0x01,0x01};
	char idStr[9];
	for (int i = 0; i < 4; i++) {
		snprintf(&idStr[i * 2], 3, "%02X", id[i]);
	}

	hybridCertificate *cert = createTestCert(id, false,
											 privKey, privLen,
											 pubKey, pubLen,
											 sigLen);

	uint8_t vehicleSig[sigLen];
	sign_message(logn, idStr,
						vehicleSig, sigLen,
						privKey, privLen,
						pubKey, pubLen,
						false);

	// create spdu
	SPDU *spdu = malloc(sizeof(SPDU));
	spdu->cert = cert;
	spdu->data = NULL;
	spdu->ECDSASignature = NULL;
	spdu->PQCSignature = malloc(sigLen);
	memcpy(spdu->PQCSignature, vehicleSig, sigLen);

	return spdu;
}


int transmit() {

	// in mHz at QPSK 0.30, bandwidth from pre-configured C-V2X settings
	const int B = 20;

	// q, r outlined in Section V table 1 of chasm paper (16-QAM, q = 4, r = 0.36)
	const int q = 2;
	const float r = 0.66; // sourced from MCS (Modulation and Coding Scheme)

	// can also be 100 number of Resource Blocks ? may depend on bandwidth
	const int Nrb = 100;

	// certificate transmission interval in ms (default)
	int TC = 500;

	// BSM interval in ms (default)
	int TM = 100;

	// IEEE 1609.2 security headers
	uint8_t HdrSec = 1;

	// classic signature
	uint8_t SigC = 1;

	// quantum resistant signature
	uint8_t SigQR = 1;

	// vehicle id
	uint8_t id[4] = {0x01,0x01,0x01,0x01};


	/* test the receiver */
	// falcon 512
	unsigned int logn = 9;

	// buffer lengths
	size_t privLen = FALCON_PRIVKEY_SIZE(logn);
	size_t pubLen  = FALCON_PUBKEY_SIZE(logn);
	size_t sigLen  = FALCON_SIG_PADDED_SIZE(logn);

	// key buffers
	uint8_t vehiclePrivKey[privLen];
	uint8_t vehiclePubKey[pubLen];
	uint8_t vehicleSig[sigLen];

	key_gen(logn, false,
			vehiclePrivKey, privLen,
			vehiclePubKey, pubLen,
			false);

	//current certificate
	hybridCertificate *HCid = createTestCert(id, false,
											 vehiclePrivKey, privLen,
											 vehiclePubKey, pubLen,
											 sigLen);

	//current BSM
	BSMData *M = malloc(sizeof(BSMData));
	M->data = malloc(64);
	memset(M->data, 0x32, 64);

	char idStr[9];
	for (int i = 0; i < 4; i++) {
		snprintf(&idStr[i * 2], 3, "%02X", id[i]);
	}
	sign_message(logn, idStr,
				 vehicleSig, sigLen,
				 vehiclePrivKey, privLen,
				 vehiclePubKey, pubLen,
				 false);

	printf("after sign\n");

	SPDU *S = malloc(sizeof(SPDU));
	S->ECDSASignature = malloc(ECDSA_SIG_SIZE);
	memset(S->ECDSASignature, 0x43, ECDSA_SIG_SIZE);
	S->PQCSignature = malloc(sigLen);
	memcpy(S->PQCSignature, vehicleSig, sigLen);
	S->cert = HCid;
	S->data = M;

	// overarching while loop starts here
	printf("starting fragment\n");
	fragmentHead *head = FRAGMENT(HCid, q, r, B, Nrb, M);
	printf("%d", head->headFragment->fragmentLen);
	printf("after fragment\n");

	int nf = 0; // just a placeholder, this variable should be returned from FRAGMENT function
	int t = 0;	//current time in ms
	int i = 1;

	// receiver stuff that would normally be done on another device
	size_t maxFragments = 10;
	storedFragments *storage = malloc(sizeof(storedFragments) + sizeof(fragmentHead *) * maxFragments);
	for (size_t i = 0; i < maxFragments; i++) {
		storage->ids[i] = NULL;
	}
	storage->idCount = 0;


	printf("at for\n");
	fragment *curFrag = head->headFragment;



	for(t = 0; t < TC; t + TM){
		if (i <= nf){ 		//this line is why nf must be returned by FRAGMENT
			// fill signature variables and SPDU
			// transmit using rx or sendwsm or just send to recieve code


			addFragToStorage(id, storage, curFrag);
			curFrag->nextFragment;

			i += 1;
		} else {
			// fill signature variables and SPDU
			// transmit SPDU
		}
	}
	// while loop ends here
	/*
	  while HCid (the current certificate) is active do:
	  select q (modulation order) and r (code rate) values (sourced from MCS to be used)
	  nf = 0 // number of fragments

	  (nf, {HC1, ..., HCnf}) = FRAGMENT(HCid, q, r, B)

	  t0 = 0 // current time (in ms).
	  i = 1

	  for t in {t0, t0 + TM, ..., TC} do
		if i <= nf then:

		  SigC = classic signature
		  SigQR = quantum resistent signature
		  M = current BSM
		  skIDc = classic secret key for device ID  	// key_gen() for ECDSA sig
		  skIDqr = quantum resistent key for device ID  // key_gen() for FALCON sig

		  SigC, SigQR = signatures over M using skIDc, skIDqr // sign_message()?
		  Si = SPDU containing M, HCi, SigC, SigQR

		  Transmit Si									// raw_tx()
		  i = i + 1

		else:

		  SigC, SigQR = signatures over M using skIDc, skIDqr
		  S = SPDU containing M, SigC, SigQR
		  Transmit S									// raw_tx()

		end if
	  end for
	end while
	*/

	return 0;
}
