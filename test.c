#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "CHASM-structs.h"
#include "falcon.h"
#include "crypto-handler.h"
#include "receive.h"



void test_fragments() {
	size_t fragLen = 3;

	fragment *frag1 = malloc(sizeof(fragment));
	fragment *frag2 = malloc(sizeof(fragment));
	fragment *frag3 = malloc(sizeof(fragment));

	frag1->fragmentLen = fragLen;
	frag2->fragmentLen = fragLen;
	frag3->fragmentLen = fragLen;

	frag1->fragmentString = "\x01\x01\x01";
	frag2->fragmentString = "\x02\x02\x02";
	frag3->fragmentString = "\x03\x03\x03";

	frag1->nextFragment = frag2;
	frag2->nextFragment = frag3;
	frag3->nextFragment = NULL;

	fragmentHead *fragHead = malloc(sizeof(fragmentHead));
	uint8_t vehicleid[4] = {0x01,0x01,0x01,0x01};
	memcpy(fragHead->id, vehicleid, 4);
	fragHead->headFragment = frag1;

	storedFragments *storage = malloc(sizeof(storedFragments));
	storage->ids[0] = fragHead;
	fragment *curFrag = storage->ids[0]->headFragment;
	fragment *nextFrag = NULL;
	do {
		if (nextFrag != NULL) {
			curFrag = nextFrag;
		}
		for (int i = 0; i < curFrag->fragmentLen; i++) {
			printf("%02X ", curFrag->fragmentString[i]);
			}
		printf("\n");

		 nextFrag = curFrag->nextFragment;
	}
	while (curFrag->nextFragment != NULL);

}

void test_certificate() {
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
	uint8_t privKey[privLen];
	uint8_t pubKey[pubLen];

	key_gen(logn, false,
				privKey, privLen,
				pubKey, pubLen,
				false);

	printf("after keypair\n");

	printf("creating test cert\n");
	hybridCertificate *cert = createTestCert(id, false,
											 pubKey, pubLen,
											 privKey, privLen);
	printf("created test cert\n");

	print_hex("Cert Public Key", cert->PQCPublicKey, pubLen);
	print_hex("Cert Signature", cert->PQCSignatureCA, sigLen);

	/*printf("received cert from vehicle: ");
	for (int i = 0; i < 4; i++) {
		printf("%02X", cert->id[i]);
	}
	printf("\n");*/

	char certID[9];
	for (int i = 0; i < 4; i++) {
		snprintf(&certID[i * 2], 3, "%02X", cert->id[i]);
	}
	printf("received cert from vehicle: %s\n", certID);

	int res = verify_signature(logn, certID,
					cert->PQCSignatureCA, sigLen,
					cert->PQCPublicKey, pubLen,
					false);

	if (res == 0) {
		printf("verifed cert using vehicle id %s\n", certID);
	}
	else {
		printf("verification failed: %d\n", res);
	}
}

SPDU *createTestSPDU(unsigned int logn,
				    uint8_t *privKey, size_t privLen,
		  	  	    uint8_t *pubKey, size_t pubLen) {

	uint8_t id[4] = {0x01,0x01,0x01,0x01};
	char idStr[9];
	for (int i = 0; i < 4; i++) {
		snprintf(&idStr[i * 2], 3, "%02X", id[i]);
	}

	hybridCertificate *cert = createTestCert(id, false,
											 privKey, privLen,
											 pubKey, pubLen);

	size_t sigLen  = FALCON_SIG_PADDED_SIZE(logn);
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


void test_receive() {

	/* create fabricated spdu to use to test receive */
	// falcon 512
	unsigned int logn = 9;

	// buffer lengths
	size_t privLen = FALCON_PRIVKEY_SIZE(logn);
	size_t pubLen  = FALCON_PUBKEY_SIZE(logn);


	// key buffers
	uint8_t privKey[privLen];
	uint8_t pubKey[pubLen];

	key_gen(logn, false,
				  privKey, privLen,
				  pubKey, pubLen,
				  false);

	SPDU *spdu = createTestSPDU(logn,
							    privKey, privLen,
							    pubKey, pubLen);

	/* receiving logic */
	hybridCertificate *cert = spdu->cert;
	int res = verifyCert(logn, cert,
			   	   	     pubKey, pubLen);

	if (res != 0) {
		printf("verification failed failed: %d", res);
		return;
	}

}
