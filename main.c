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


int main() {

	//test_fragments();

	unsigned int logn = 9;
	size_t pub_len  = FALCON_PUBKEY_SIZE(logn);
	hybridCertificate *cert = createTestCert();
	print_hex("Cert Public Key", cert->PQCPublicKey, pub_len);


}
