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
