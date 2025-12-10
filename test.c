#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "CHASM-structs.h"
#include "falcon.h"
#include "crypto-handler.h"
#include "receive.h"
#include "transmit.h"



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
		//printf("\n");

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
											 privKey, privLen,
											 sigLen);
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


void test_receive_random_frags() {

	uint8_t id[4] = {0x01,0x01,0x01,0x01};
	char idStr[9];
	for (int i = 0; i < 4; i++) {
		snprintf(&idStr[i * 2], 3, "%02X", id[i]);
	}

	size_t maxFragments = 10;
	storedFragments *storage = malloc(sizeof(storedFragments) + sizeof(fragmentHead *) * maxFragments);
	for (size_t i = 0; i < maxFragments; i++) {
	    storage->ids[i] = NULL;
	}
	storage->idCount = 0;

	unsigned int strNumVal;
	for (unsigned int i = 1; i < 476; i++) {
		//printf("\nloop %d\n", i);
		fragment *newFrag = malloc(sizeof(fragment));
		newFrag->fragmentString = malloc(5);
		strNumVal = (i % 256);
		if (strNumVal == 0) {
			strNumVal++;
		}
		newFrag->fragmentString[0] = (unsigned char)strNumVal;
		newFrag->fragmentString[1] = (unsigned char)strNumVal;
		newFrag->fragmentString[2] = (unsigned char)strNumVal;
		newFrag->fragmentString[3] = (unsigned char)strNumVal;
		newFrag->fragmentString[4] = '\0';
		newFrag->fragmentLen = 4;
		newFrag->nextFragment = NULL;

		addFragToStorage(id, storage, newFrag);

//		printf("frag added\n");
	}

	//printHead(storage->ids[0]);
}




void test_receive() {

}



void test_serialize_certificate() {


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

	hybridCertificate *cert = createTestCert(id, true,
				privKey, privLen,
				pubKey, pubLen,
				sigLen);

	print_hex("ecdsa pub", cert->ECDSAPublickey, ECDSA_PUBLIC_KEY_SIZE);

	serializeCertificate(cert);
}



void test_fragment() {


	transmit();


}



