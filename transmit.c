#include <math.h>
#include <crypto-handler.h>
/*

B = 1; // bandwidth from pre-configured C-V2X settings
TC = 500; // certificate transmission interval in ms (default)
TM = 100; // BSM interval in ms (default)
HC = 1; // current certificate
HdrSec = 1; // IEEE 1609.2 security headers
M = 1; // current BSM Message
SigC = 1; // classic signature
SigQR = 1; // quantum resistent signature
q = 2;     // q, r outlined in Section V table 1 of chasm paper (16-QAM, q = 4, r = 0.36)
r = 0.66; // sourced from MCS (Modulation and Coding Scheme)
Nrb = 50; // can also be 100 number of Resource Blocks ? may depend on bandwidth
HCid = 1; //authenticated certificate


  // FRAGMENT function will return a struct containg (number of certificate fragments, (an array of all fragments) )
  // \/ int is a placeholder
  int FRAGMENT(HCid, q, r, B) {
    
    // Calculating some variables needed for fragmentation function
    // minimum size of an SPDU
    minS = sizeof(HdrSec) + sizeof(M) + sizeof(SigC) + sizeof(SigQR);
    
    // maximum size of transport block given our MCS 
    maxTB  = 12 * 10 * log2(q) * r * (Nrb - 2) * 1/8;
  
    // maxmimum size of HCf (certificate fragment)
    maxHCf = sizeof(maxTB) - sizeof(min); //possibly check if double sizeof causes error
  
    // number of certificate fragments
    nf = ceilingFunction(sizeof(HC)/(sizeof(maxHCf);

    // from here you divide HCid by nf in a way in which preserves the content/uses B (bandwidth) in some way?
{HC1, ..., HCnf} = 0; 
    
    return (nf, {HC1, ..., HCnf});
  

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
