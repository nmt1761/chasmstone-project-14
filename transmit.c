#include <math.h>
#include <stdio.h>
#include <string.h>
#include "crypto-handler.h"
#include "CHASM-structs.h"


char *serializeCertificate(hybridCertificate *HCid) {
	  // turning a struct hybridCertificate into one long string of hex values for our fragmentation protocol to digest
	  unsigned char serializedHC[COMPLETE_HYBRID_CERT_FRAGMENT_SIZE];

	  int curIndex = 0;

	  memcpy(serializedHC, HCid->id, 4);
	  curIndex += VEHICLE_ID_SIZE;

	  serializedHC[curIndex] = (unsigned char)HCid->securityHeaders;
	  curIndex += SECURITY_HEADERS_SIZE;

	  memcpy(serializedHC + curIndex, HCid->ECDSAPublickey, ECDSA_PUBLIC_KEY_SIZE);
	  curIndex += ECDSA_PUBLIC_KEY_SIZE;

	  memcpy(serializedHC + curIndex, HCid->PQCPublicKey, PQC_PUBLIC_KEY_SIZE);
	  curIndex += PQC_PUBLIC_KEY_SIZE;

	  memcpy(serializedHC + curIndex, HCid->ECDSASignatureCA, ECDSA_SIG_SIZE);
	  curIndex += ECDSA_SIG_SIZE;

	  memcpy(serializedHC + curIndex, HCid->PQCSignatureCA, PQC_SIG_SIZE);
	  curIndex += PQC_SIG_SIZE;


	  return serializedHC;
}

  // FRAGMENT function will return storedFragments struct containing (number of certificate fragments, (an array of all fragments) )
  storedFragments FRAGMENT(hybridCertificate *HCid, int q, float r, int B, int Nrb, BSMData M) {
    

	storedFragments *result = {0};
    // Calculating some variables needed for fragmentation function

	// minimum size of an SPDU
    //float minS = sizeof(HCid.securityHeaders) + sizeof(S.data) + sizeof(HCid->ECDSASignatureCA) + sizeof(HCid->PQCSignatureCA);
    size_t minS = SECURITY_HEADERS_SIZE + strlen(M) + ECDSA_SIG_SIZE + PQC_SIG_SIZE;
    
    // maximum size of transport block given our MCS 
    //float maxTB  = 12 * 10 * log2(q) * r * (Nrb - 2) * (1.0 / 8.0);
    float bitsPerSymbol = log2f(q);
    float rb = (float)(Nrb - 2);
    float bits = 12.0f * 10.0f * bitsPerSymbol * r * rb;
    size_t maxTB = bits / 8.0f;

  
    // maxmimum size of HCf (certificate fragment)
    //float maxHCf = sizeof(maxTB) - sizeof(minS); //possibly check if double sizeof causes error
    size_t maxHCF = maxTB - minS;
    // number of certificate fragments
    int nf = (int)ceilf( COMPLETE_HYBRID_CERT_FRAGMENT_SIZE / maxHCF );  // uses ceiling function, possibly change to (certLength + maxHCF - 1) / maxHCF
    printf("%d\n", nf);

    char* serializedHC = serializeCertificate(HCid); //double check validity
    fragmentHead *head = malloc(sizeof(fragmentHead));		//fragment head initialized
    memcpy(head->id, HCid->id, 4);
    head->headFragment = malloc(sizeof(fragment));
    head->headFragment->fragmentString = malloc(maxHCF);	//headfragment value complete

    head->headFragment->nextFragment = malloc(sizeof(fragment));	//allocated memory for next fragment
    head->headFragment->nextFragment = NULL;


    fragment *prev = NULL;
    size_t offset = 0;	//length of certificate currently fragmented
    size_t certLength = COMPLETE_HYBRID_CERT_FRAGMENT_SIZE;	//length of serialized certificate
    fragment temp = malloc(sizeof(fragment));

    while (offset < certLength){
			size_t chunk = certLength - offset;		//length of certificate left to fragment
			if (chunk > maxHCF) {		//if certificate is not done, chunk equals the amount of data we want to fragment
				chunk = maxHCF;
			}

			fragment *frag = malloc(sizeof(fragment));
			frag->fragmentLen = chunk;
			frag->fragmentString = malloc(chunk);
			memcpy(frag->fragmentString, serializedHC + offset, chunk);
			frag->nextFragment = NULL;

			prev->nextFragment = frag;
			prev = frag;
			offset += chunk;
    	}

    
    return result; // (nf, {HC1, ..., HCnf}) <- maybe no nf
  }
  
	int transmit(SPDU *S) {


				// in mHz at QPSK 0.30, bandwidth from pre-configured C-V2X settings
		const int B = 20;

		// q, r outlined in Section V table 1 of chasm paper (16-QAM, q = 4, r = 0.36)
		const int q = 2;
		const float r = 0.66; // sourced from MCS (Modulation and Coding Scheme)

		// can also be 100 number of Resource Blocks ? may depend on bandwidth
		const int Nrb = 50;

		// certificate transmission interval in ms (default)
		int TC = 500;

		// BSM interval in ms (default)
		int TM = 100;

		// IEEE 1609.2 security headers
		uint8_t HdrSec = 1;

		// classic signature
		uint8_t SigC = 1;

		// quantum resistant signature
		uint8_t SigQR = 1;

		//current certificate
		hybridCertificate *HCid = malloc(sizeof(hybridCertificate));
		uint8_t id_bytes[4] = {0x01,0x01,0x01,0x01};
		memcpy(HCid->id, id_bytes, 4);
		HCid->securityHeaders = NULL;
		HCid->ECDSAPublickey = NULL;
		HCid->PQCPublicKey = NULL;
		HCid->ECDSASignatureCA = NULL;
		HCid->PQCSignatureCA = NULL;

		//current BSM
		BSMData *M = malloc(sizeof(S->data));

		// overarching while loop starts here
		storedFragments fragments = FRAGMENT(HCid, q, r, B, Nrb, M);

		int t = 0;	//current time in ms
		int i = 1;

		for(t = 0; t < TC; t + TM){
			if (i <= nf){ 		//this line is why nf must be returned by FRAGMENT
				// fill signature variables and SPDU
				// transmit using rx or sendwsm or just send to recieve code
				i += 1;
			} else {
				// fill signature variables and SPDU
				// transmit SPDU
			}
		}
		// while loop ends here
	/*
		  while HCid (the current certificate) is active do:
		  select q (modulation order) and r (code rate) values (sourced from MCS to be used)
		  nf = 0 // number of fragments

		  (nf, {HC1, ..., HCnf}) = FRAGMENT(HCid, q, r, B)

		  t0 = 0 // current time (in ms).
		  i = 1

		  for t in {t0, t0 + TM, ..., TC} do
			if i <= nf then:

			  SigC = classic signature
			  SigQR = quantum resistent signature
			  M = current BSM
			  skIDc = classic secret key for device ID  	// key_gen() for ECDSA sig
			  skIDqr = quantum resistent key for device ID  // key_gen() for FALCON sig

			  SigC, SigQR = signatures over M using skIDc, skIDqr // sign_message()?
			  Si = SPDU containing M, HCi, SigC, SigQR

			  Transmit Si									// raw_tx()
			  i = i + 1

			else:

			  SigC, SigQR = signatures over M using skIDc, skIDqr
			  S = SPDU containing M, SigC, SigQR
			  Transmit S									// raw_tx()

			end if
		  end for
		end while
		*/

	return 0;
   }
