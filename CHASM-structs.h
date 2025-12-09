#ifndef CHASM_STRUCTS_H_
#define CHASM_STRUCTS_H_

#include <stdint.h>
#include <stddef.h>


#define VEHICLE_ID_SIZE							4
#define SECURITY_HEADERS_SIZE					1
#define ECDSA_PUBLIC_KEY_SIZE					256
#define PQC_PUBLIC_KEY_SIZE						897
#define ECDSA_SIG_SIZE							64
#define PQC_SIG_SIZE							666
#define COMPLETE_HYBRID_CERT_FRAGMENT_SIZE		VEHICLE_ID_SIZE + SECURITY_HEADERS_SIZE + ECDSA_PUBLIC_KEY_SIZE + PQC_PUBLIC_KEY_SIZE + ECDSA_SIG_SIZE + PQC_SIG_SIZE

// retains a single fragment, its length, and the next fragment
typedef struct fragment {
	size_t fragmentLen;
	char *fragmentString;
	struct fragment *nextFragment;
} fragment;

typedef struct fragmentHead {
	uint8_t id[4];
	fragment *headFragment;
} fragmentHead;

typedef struct storedFragments {
	size_t idCount;
	fragmentHead *ids[];
} storedFragments;
/* example of how to use fragment structs is in main.c test_fragments() */

int addFragToHead(fragment *newFrag, fragmentHead *head);

int idInFragmentStorage(uint8_t *id,
						storedFragments *storage);

int addFragToStorage(uint8_t *id,
					storedFragments *storage,
					fragment *frag);

void printHead(fragmentHead *head);

typedef struct {
	// vehicle id
	uint8_t id[4];
	// security headers
	uint8_t securityHeaders;
	// vehicle's ECDSA public key
	uint8_t *ECDSAPublickey;
	// vehicle's PQC public key
	uint8_t *PQCPublicKey;
	// CA ECDSA signature of certificate
	uint8_t *ECDSASignatureCA;
	// CA PQC signature of certificate
	uint8_t *PQCSignatureCA;
} hybridCertificate;

typedef struct {
	// BSM data, needs to be expanded for a full implementation
	char *data;
} BSMData;

typedef struct {
	// certificate with vehicle's public keys
	hybridCertificate *cert;
	// BSM data
	BSMData *data;
	// vechicle ECDSA signture of message
	uint8_t *ECDSASignature;
	// vehicle PQC signature of message
	uint8_t *PQCSignature;
} SPDU;

hybridCertificate *processCompleteCert(int id, storedFragments *storage);

int populateCertFromString(hybridCertificate *cert, unsigned char *fragmentBytes);



#endif /* CHASM_STRUCTS_H_ */
