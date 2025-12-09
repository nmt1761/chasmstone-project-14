#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "CHASM-structs.h"
#include "falcon.h"
#include "crypto-handler.h"
#include "receive.h"
#include "test.h"


void printHead(fragmentHead *fragHead) {
	fragment *curFrag = fragHead->headFragment;
	fragment *nextFrag = NULL;
	printf("\n\nstarting frag printing\n");
	do {
		if (nextFrag != NULL) {
			curFrag = nextFrag;
		}
		if (curFrag->fragmentString == NULL) {
			printf("fragment has no string\n");
			return;
		}
		for (int i = 0; i < curFrag->fragmentLen; i++) {
			printf("%02X ", (unsigned char)curFrag->fragmentString[i]);
			}
		printf("\n");

		nextFrag = curFrag->nextFragment;
	}
	while (curFrag->nextFragment != NULL);
//	printf("finished printing fragments\n");
}


int idInFragmentStorage(uint8_t *id, storedFragments *storage) {

	size_t idCount = storage->idCount;
//	printf("got storage id count %d\n", (int)idCount);

	if (idCount == 0) {
//		printf("empty storage\n");
		return -1;
	}

	for (int i = 0; i < storage->idCount; i++) {
		if (memcmp(id, storage->ids[i]->id, 4) == 0) {
//			printf("same\n");
//			printf("id at index %d\n", i);
			return i;
		}
//		printf("different\n");
	}

//	printf("not in there\n");
	return -1;
}



int addFragToHead(fragment *newFrag, fragmentHead *head) {
//	printf("A\n");
	bool fullFragment = false;
	if (head->headFragment == NULL) {
//		printf("B\n");
		head->headFragment = newFrag;
//		printf("early return\n");
		return 0;
	}

//	printf("more before do\n");
	fragment *curFrag = head->headFragment;
	fragment *nextFrag = curFrag->nextFragment;
	size_t countFrag = 0;
//	printf("before do\n");
	unsigned int fragLen = 0;
	while (1) {
		if (nextFrag != NULL) {
			curFrag = nextFrag;
		}
		if (curFrag->fragmentString != NULL) {
			fragLen += (int)newFrag->fragmentLen;
		}
		if (curFrag->nextFragment == NULL) {
//			printf("nextFrag is null\n");
			break;
		}
		nextFrag = curFrag->nextFragment;
		countFrag++;
	}
	printf("done iterating frags\n");
	//(int)newFrag->fragmentLen
	printf("fraglen %d", fragLen);
	if (fragLen >= COMPLETE_HYBRID_CERT_FRAGMENT_SIZE - 1) {
		fullFragment = true;
	}
	printf("fraglen %d\n", fragLen);
	curFrag->nextFragment = newFrag;

//	printf("end of addFragToHead\n");
	if (fullFragment) {
		printf("fullFragment\n");
		fragLen += (int)newFrag->fragmentLen;
		return 1;
	}
	return 0;
}


int addFragToStorage(uint8_t *id, storedFragments *storage, fragment *frag) {
	int idIndex = idInFragmentStorage(id, storage);
	fragmentHead *head;
	if (idIndex == -1) {
//		printf("new frag made\n");
		head = malloc(sizeof(fragmentHead));
		memcpy(head->id, id, 4);
		head->headFragment = frag;
		storage->ids[storage->idCount] = head;
		//storage->ids[storage->idCount] = malloc(sizeof(fragmentHead));
		//storage->ids[storage->idCount]->headFragment = frag;
//		printf("added new frag\n");
		storage->idCount++;
//		printf("new storage id count: %d\n", (int)storage->idCount);
	}
	else {
//		printf("existing frag\n");
//		printf("idIndex: %d\n", idIndex);
		head = storage->ids[idIndex];
//		printf("right before addtohead\n");
		int res = addFragToHead(frag, head);
//		printf("made it past addtohead\n");
		if (res == 1) {
			hybridCertificate *cert = processCompleteCert(idIndex, storage);
			printf("got cert\n");
			print_hex("ECDSA pub key", cert->ECDSAPublickey, ECDSA_PUBLIC_KEY_SIZE);
			print_hex("PQC pub key", cert->PQCPublicKey, PQC_PUBLIC_KEY_SIZE);
		}
	}

	return 0;
}


int populateCertFromString(hybridCertificate *cert, unsigned char *fragmentBytes) {
	int curIndex = 0;
	memcpy(cert->id, fragmentBytes + curIndex, VEHICLE_ID_SIZE);
	curIndex += VEHICLE_ID_SIZE;

	cert->securityHeaders = fragmentBytes[curIndex];
	curIndex += SECURITY_HEADERS_SIZE;

	cert->ECDSAPublickey = malloc(ECDSA_PUBLIC_KEY_SIZE);
	memcpy(cert->ECDSAPublickey, fragmentBytes + curIndex, ECDSA_PUBLIC_KEY_SIZE);
	curIndex += ECDSA_PUBLIC_KEY_SIZE;

	cert->PQCPublicKey = malloc(PQC_PUBLIC_KEY_SIZE);
	memcpy(cert->PQCPublicKey, fragmentBytes + curIndex, PQC_PUBLIC_KEY_SIZE);
	curIndex += PQC_PUBLIC_KEY_SIZE;

	cert->ECDSASignatureCA = malloc(ECDSA_SIG_SIZE);
	memcpy(cert->ECDSASignatureCA, fragmentBytes + curIndex, ECDSA_SIG_SIZE);
	curIndex += ECDSA_SIG_SIZE;

	cert->PQCSignatureCA = malloc(PQC_SIG_SIZE);
	memcpy(cert->PQCSignatureCA, fragmentBytes + curIndex, PQC_SIG_SIZE);
	curIndex += PQC_SIG_SIZE;

	printf("hit return\n");
	return 0;
}


hybridCertificate *processCompleteCert(int id, storedFragments *storage) {

	printf("processCompleteCert start\n");
	unsigned char certStr[COMPLETE_HYBRID_CERT_FRAGMENT_SIZE+4];
	int curIndex = 0;
	fragmentHead *fragHead = storage->ids[id];
	fragment *curFrag = fragHead->headFragment;
	fragment *nextFrag = NULL;
	printf("\n\nstarting frag reading\n");
	int fragCount = 0;
	do {
		if (nextFrag != NULL) {
			curFrag = nextFrag;
		}
		if (curFrag->fragmentString == NULL) {
			printf("fragment has no string\n");
			return -1;
		}
		printf("if statement: %d + %d + 1\n", curIndex,curFrag->fragmentLen);
		if (curIndex + curFrag->fragmentLen > COMPLETE_HYBRID_CERT_FRAGMENT_SIZE+1) {
			printf("ERROR\n");
			break;
		}
		for (int i = 0; i < curFrag->fragmentLen; i++) {

			//printf("%02X ", (unsigned char)curFrag->fragmentString[i]);
			memcpy((unsigned char *)certStr + curIndex,
					&curFrag->fragmentString[i],
					1);
			//printf("frag: %d; index: %d; adding: %02X; len %d\n", fragCount, i, certStr[curIndex], curIndex);
			/*if (curIndex != 30) {
				for (int i = 0; i < strlen((char *)certStr); i++) {
					printf("%02X", certStr[i]);
				}
				printf("\n");
			}*/
			curIndex += 1;
		}
		certStr[curIndex+1] = '\0';
		nextFrag = curFrag->nextFragment;
		fragCount++;
	}
	while (curFrag->nextFragment != NULL);

	printf("(0):");
	for (int i = 0; i < strlen(certStr); i++) {
		printf("%02X ", certStr[i]);
		if ((i + 1) % 32 == 0) {
			printf("\n(%d): ", i);
		}
	}
	printf("\n");

	printf("strlen: %d\n", strlen(certStr));

	storage->ids[id] = NULL;
	storage->idCount -= 1;

	printf("made it\n");
	hybridCertificate *assembledCert = malloc(sizeof(hybridCertificate));
	printf("after malloc\n");
	populateCertFromString(assembledCert, certStr);
	printf("returning\n");

	return assembledCert;
}
