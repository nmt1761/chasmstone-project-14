B = 1 // bandwidth from pre-configured C-V2X settings
TC = 1 // certificate transmission interval (defaults to 500 ms).
TM = 1 // BSM interval (defaults to 100 ms).
HC = 1 // current certificate

/*
  Pseduocode below huzzah!

  HdrSec = IEEE 1609.2 security headers
  min|S| = |HdrSec| + |M| + |SigC| + |SigQR|
  max|TB| = 12 * 10 * log2(q) * r * (Nrb - 2) * 1/8
  max|HCf| = max|TB| - min|S|
  nf = ceilingFunction(|HC|/max|HCf|)


  while the current certificate is active do:
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
      skIDc = classic secret key for device ID
      skIDqr = quantum resistent key for device ID

      SigC, SigQR = signatures over M using skIDc, skIDqr
      Si = SPDU containing M, HCi, SigC, SigQR
      
      Transmit Si
      i = i + 1
      
    else:
    
      SigC, SigQR = signatures over M using skIDc, skIDqr
      S = SPDU containing M, SigC, SigQR
      Transmit S
      
    end if
  end for
end while
*/
