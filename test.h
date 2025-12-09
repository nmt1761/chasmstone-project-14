#ifndef TEST_H_
#define TEST_H_

void test_fragments();

void test_certificate();

SPDU *createTestSPDU(unsigned int logn,
				    uint8_t *privKey, size_t privLen,
		  	  	    uint8_t *pubKey, size_t pubLen);

void test_receive_random_frags();

void test_receive();

void test_serialize_certificate();


#endif /* TEST_H_ */
