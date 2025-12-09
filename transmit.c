#include <math.h>
#include "crypto-handler.h"
#include "CHASM-structs.h"



  char listifyHC(HCid){
	  // turning a struct hybridCertificate into one long string of hex values for our fragmentation protocol to digest
	return 0
  }

  // FRAGMENT function will return storedFragments struct containing (number of certificate fragments, (an array of all fragments) )
  storedFragments FRAGMENT(HCid, q, r, B, Nrb) {
    
    // Calculating some variables needed for fragmentation function

	// minimum size of an SPDU
    float minS = sizeof(HCid.securityHeaders) + sizeof(S.data) + sizeof(HCid->ECDSASignatureCA) + sizeof(HCid->PQCSignatureCA);
    
    // maximum size of transport block given our MCS 
    float maxTB  = 12 * 10 * log2(q) * r * (Nrb - 2) * 1/8;
  
    // maxmimum size of HCf (certificate fragment)
    float maxHCf = sizeof(maxTB) - sizeof(minS); //possibly check if double sizeof causes error
  
    // number of certificate fragments
    double nf = ceil( sizeof(HC) / sizeof(maxHCf) );  // uses ceiling function

    char longAhString[] = listifyHC(HCid);

	fragment cF; // current Fragment
    // from here you divide HCid by nf in a way in which preserves the content/uses B (bandwidth) in some way?
	{HC1, ..., HCnf} = 0;
	storedFragments fragments = 1;
    
    return fragments; // (nf, {HC1, ..., HCnf}) <- maybe no nf
  }
  
	int transmit(HCid) {


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

		// current BSM Message
		BSMData M = 1;

		// classic signature
		uint8_t SigC = 1;

		// quantum resistant signature
		uint8_t SigQR = 1;

		//current certificate
		hybridCertificate *HCid = malloc(sizeof(hybridCertificate));

		// current SPDU
		SPDU *S = malloc(sizeof(SPDU));

		storedFragments fragments = FRAGMENT(HCid, q, r, B, Nrb);
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
	return 0
   }
