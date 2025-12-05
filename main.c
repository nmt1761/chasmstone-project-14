#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "CHASM-structs.h"
#include "falcon.h"
#include "crypto-handler.h"
#include "receive.h"
#include "test.h"


int main() {

	printf("starting\n");

	//test_fragments();
	//test_certificate();

	test_receive();

	printf("done\n");
}
