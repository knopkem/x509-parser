#![allow(non_snake_case)]
use serde::{Deserialize, Serialize};
use tsify::Tsify;

/*
Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }
*/

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: String,
    pub subjectPublicKey: String,   
}

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Validity {
    pub notBefore: String,
    pub notAfter: String,
}

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Signature {
    pub algorithm: String,
    pub parameters: String,
}

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Extension {
    pub critical: bool,
    pub value: String,
}

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct TBSCertificate {
    pub version: u32,    
    pub serialNumber: String, //should be bigint but not possible with js
    pub signature: Signature,
    pub issuer: String,
    pub validity: Validity,
    pub subject: String,
    pub subjectPublicKeyInfo: SubjectPublicKeyInfo,
    pub extensions: Vec<Extension>,
}

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Certificate {
    pub tbsCertificate: TBSCertificate,
    pub signatureAlgorithm: String,
    pub signatureValue: String,
}