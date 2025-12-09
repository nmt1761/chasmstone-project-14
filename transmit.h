/*
 *
 * Author: Nathan M Trumble
 *
 * Date 12/04/2025
 */

#ifndef TRANSMIT_H_
#define TRANSMIT_H_

char listifyHC(hybridCertificate HCid);

storedFragments FRAGMENT(hybridCertificate HCid, int q, float r, int B, int Nrb);

int transmit(hybridCertificate HCid);
