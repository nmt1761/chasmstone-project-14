#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	size_t fragmentLen;
	char *fragmentString;
} fragment;

typedef struct {
	size_t fragmentCount;
	fragment *fragments;
} fragmentHolder;





int main() {
	size_t count = 3;
	size_t fragLen = 3;


	fragmentHolder *fragmentHold = malloc(sizeof(fragmentHolder));
	fragmentHold->fragmentCount = count;
	fragmentHold->fragments = calloc(count, sizeof(fragment));

	/*
	fragment *fragment1 = malloc(sizeof(fragment));
	fragment *fragment2 = malloc(sizeof(fragment));
	fragment *fragment3 = malloc(sizeof(fragment));

	fragment1->fragmentLen = fragLen;
	fragment2->fragmentLen = fragLen;
	fragment3->fragmentLen = fragLen;
	fragment1->fragmentString = "\x01\x01\x01";
	fragment2->fragmentString = "\x02\x02\x02";
	fragment3->fragmentString = "\x03\x03\x03";

	fragmentHold->fragments[0] = *fragment1;
	fragmentHold->fragments[1] = *fragment2;
	fragmentHold->fragments[2] = *fragment3;
	*/
	fragmentHold->fragments[0].fragmentLen = fragLen;
	fragmentHold->fragments[0].fragmentString = "\x01\x01\x01";
	fragmentHold->fragments[1].fragmentString = "\x02\x02\x02";
	fragmentHold->fragments[1].fragmentLen = fragLen;
	fragmentHold->fragments[2].fragmentString = "\x03\x03\x03";
	fragmentHold->fragments[2].fragmentLen = fragLen;

	for (int i = 0; i < fragmentHold->fragmentCount; i++) {
		char *str = (char *)fragmentHold->fragments[i].fragmentString;
			for (int j = 0; j < fragmentHold->fragments[0].fragmentLen; j++) {
				printf("%02X ", str[j]);
			}
		printf("\n");
	}


}
