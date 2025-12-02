#ifndef CHASM_STRUCTS_H_
#define CHASM_STRUCTS_H_


// retains a single fragment and its length
typedef struct {
	size_t fragmentLen;
	char *fragmentString;
} fragment;


// manages a set number of fragments
typedef struct {
	size_t fragmentCount;
	fragment *fragments;
} fragmentHolder;

/* example of how to use fragment structs is in main.c test_fragments() */


typedef struct {
	// security headers
	uint8_t securityHeaders;
	// vehicle's ECDSA public key
	uint8_t *ECDSAPublickey;
	// vehicle's PQC public key
	uint8_t *PQCKey;
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
	BSMData data;
	// vechicle ECDSA signture of message
	uint8_t *ECDSASignature;
	// vehicle PQC signature of message
	uint8_t *PQCSignature;
} SPDU;



#endif /* CHASM_STRUCTS_H_ */
