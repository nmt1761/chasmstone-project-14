#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "CHASM-structs.h"
#include "falcon.h"
#include "crypto-handler.h"
#include "receive.h"


void test_fragments() {
	// set constant sizes for test
	size_t count = 3;
	size_t fragLen = 3;

	// create fragment holder and allocate space for as many fragments as was specified
	fragmentHolder *fragmentHold = malloc(sizeof(fragmentHolder));
	fragmentHold->fragmentCount = count;
	fragmentHold->fragments = calloc(count, sizeof(fragment));

	// populate fragment objects with their strings and lengths
	fragmentHold->fragments[0].fragmentLen = fragLen;
	fragmentHold->fragments[0].fragmentString = "\x01\x01\x01";
	fragmentHold->fragments[1].fragmentLen = fragLen;
	fragmentHold->fragments[1].fragmentString = "\x02\x02\x02";
	fragmentHold->fragments[2].fragmentLen = fragLen;
	fragmentHold->fragments[2].fragmentString = "\x03\x03\x03";

	// iteratively go through each fragment in the holder and print
	for (int i = 0; i < fragmentHold->fragmentCount; i++) {
		char *str = (char *)fragmentHold->fragments[i].fragmentString;

			// iteratively print each value in a fragment
			for (int j = 0; j < fragmentHold->fragments[0].fragmentLen; j++) {
				printf("%02X ", str[j]);
			}
		printf("\n");
	}
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
	hybridCertificate *cert = createTestCert(id, true,
											 pubKey, pubLen,
											 privKey, privLen);
	printf("created test cert\n");

	//print_hex("Cert Public Key", cert->PQCPublicKey, pubLen);
	//print_hex("Cert Signature", cert->PQCSignatureCA, sigLen);

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
		printf("verification failed");
	}
}

int main() {

	printf("starting\n");
	//test_fragments();

	test_certificate();


}
