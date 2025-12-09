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
	if (fragLen == COMPLETE_HYBRID_CERT_FRAGMENT_SIZE - (int)newFrag->fragmentLen) {
		fullFragment = true;
	}
	curFrag->nextFragment = newFrag;

//	printf("end of addFragToHead\n");
	if (fullFragment) {
		fragLen += (int)newFrag->fragmentLen;
		printf("finished fragment grouping: %d\n", fragLen);
		return 1;
	}
	return 0;
}


int addFragToStorage(uint8_t *id, storedFragments *storage, fragment *frag) {
	printf("\n");
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
			processCompleteCert(idIndex, storage);
		}
	}

	return 0;
}


int processCompleteCert(int id, storedFragments *storage) {

	unsigned char certStr[COMPLETE_HYBRID_CERT_FRAGMENT_SIZE+3];
	int curIndex = 0;
	fragmentHead *fragHead = storage->ids[id];
	fragment *curFrag = fragHead->headFragment;
		fragment *nextFrag = NULL;
		printf("\n\nstarting frag reading\n");
		do {
			if (nextFrag != NULL) {
				curFrag = nextFrag;
			}
			if (curFrag->fragmentString == NULL) {
				printf("fragment has no string\n");
				return -1;
			}
			for (int i = 0; i < curFrag->fragmentLen; i++) {
				printf("%d\n", curIndex);
				if (curIndex + 2 > COMPLETE_HYBRID_CERT_FRAGMENT_SIZE+3) {
					printf("ERROR\n");
					break;
				}
				//printf("%02X ", (unsigned char)curFrag->fragmentString[i]);
				memcpy((unsigned char *)certStr + curIndex,
						&curFrag->fragmentString[i],
						1);
				curIndex += 1;
			}

			nextFrag = curFrag->nextFragment;
		}
		while (curFrag->nextFragment != NULL);

		for (int i = 0; i < strlen(certStr); i++) {
			printf("%02X\n", certStr[i]);
		}


	return 0;
}
