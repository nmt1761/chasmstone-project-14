/*
Algorithm2CHASM:ReceivingandVerifyingSPDUs
 1: procedurePROCESSSPDU(S∗)
 2: id←extractvehicleIDfromS∗
 3: if idcorresponds toaknown,verifiedcertificatethen
 4: HCid←loadknowncertificate
 5: VERIFYSPDUHCid,S
 6: else
 7: ifScontainsacertificatefragmentHCid
 f then
 8: CacheHCid
 f for reassemblyafterall fragmentsarereceived.
 9: endif
 10: CacheSforprocessingoncecertificateisobtainedandverified.
 11: ifall fragmentsforcertificateof idhavebeenreceivedthen
 12: HCid←reassemblecertificatefragmentsfor id
 13: r←VERIFYCERTIFICATE HCid
 14: if r==Truethen
 15: RecordHCid asknownandvalidcertificatefor id
 16: foreachcachedSPDUS∗ receivedfromiddo
 17: VERIFYSPDU(id,S∗)
 18: endfor
 19: endif
 20: endif
 21: endif
 22: endprocedure
 23: procedureVERIFYSPDU(HCid,S∗)
 24: pk𝑐
 id,pk𝑞𝑟
 id ←extractpublickeysfromHCid
 25: VerifysignaturesofS∗ using pk𝑐
 id,pk𝑞𝑟
 id
 26: ifverificationofsignaturesforS∗ issuccessful then
 27: AcceptS
 28: else
 29: RejectS∗
 30: endif
 31: endprocedure
 32: procedureVERIFYCERTIFICATE(HCid)
 33: VerifycertificateusingPKIandtrust rootasper IEEE1609.2[24].
 34: ifverificationissuccessful then
 35: returnTrue
 36: else
 37: returnFalse
 38: endif
 39: endprocedure
 */

#include "CHASM-structs.h"
#include "crypto-handler.h"
#include "falcon.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>


hybridCertificate *createTestCert(uint8_t *id, bool genCAKey,
								  uint8_t *privKey, size_t vPrivLen,
								  uint8_t *pubKey, size_t vPubLen) {

	// falcon 512
	unsigned int logn = 9;

	// buffer lengths
	size_t privLen = FALCON_PRIVKEY_SIZE(logn);
	size_t pubLen  = FALCON_PUBKEY_SIZE(logn);
	size_t sigLen  = FALCON_SIG_PADDED_SIZE(logn);

	// CA buffers
	uint8_t CAPrivKey[privLen];
	uint8_t CAPubKey[pubLen];
	uint8_t CASig[sigLen];

	if (genCAKey) {
		printf("generating new CA keypair\n");

		// generate a new CA keypair
		key_gen(logn, false,
				CAPrivKey, privLen,
				CAPubKey, pubLen,
				false);

		// save the CA keypair
		save_key("CA-pub",
				CAPubKey,
				pubLen);
		save_key("CA-priv",
				CAPubKey,
				pubLen);

	} else {
		printf("loading CA keypair\n");

		// load an existing CA keypair
		load_key("CA-pub", CAPubKey,
				&pubLen, sizeof(CAPubKey));
		load_key("CA-pub", CAPrivKey,
				&pubLen, sizeof(CAPrivKey));
	}

	printf("CA key set\n");

	sign_message(logn, "test",
					CASig, sigLen,
					CAPrivKey, privLen,
					CAPubKey, pubLen,
					false);


	// initialize certificate
	hybridCertificate *cert = malloc(sizeof(hybridCertificate));

	// populate certificate
	cert->securityHeaders = 0x00;
	cert->ECDSAPublickey = NULL;
	cert->PQCPublicKey = malloc(pubLen);
	memcpy(cert->PQCPublicKey, CAPubKey, pubLen);
	cert->ECDSASignatureCA = NULL;
	cert->PQCSignatureCA = malloc(sigLen);
	memcpy(cert->PQCSignatureCA, CASig, sigLen);

	return cert;
}





