/*
 *
 * Author: Nathan M Trumble
 *
 * Date 12/04/2025
 */

#ifndef TRANSMIT_H_
#define TRANSMIT_H_

char serializeCertificate(hybridCertificate HCid);

storedFragments FRAGMENT(hybridCertificate HCid, int q, float r, int B, int Nrb);

int transmit(hybridCertificate HCid);
