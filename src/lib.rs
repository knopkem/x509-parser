mod utils;
mod types;

use hex::ToHex;
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use x509_parser::{parse_x509_certificate, pem};

use crate::{types::*, utils::format_oid_simple};



#[wasm_bindgen]
pub fn parse_certificate(input: &str) -> Certificate {
    set_panic_hook();
    print!("{}", input);
    let (_, pem) =  pem::parse_x509_pem(&input.as_bytes()).unwrap();
    let (_, cert) = parse_x509_certificate(&pem.contents).unwrap();
    let extensions: Vec<Extension> = cert.extensions().iter().map(|f| Extension { critical: f.critical, value: f.value.encode_hex() }).collect();

    Certificate {
        tbsCertificate: TBSCertificate {
            version: cert.version.0,
            subject: cert.subject().to_string(),
            serialNumber: cert.serial.to_string(),
            signature: Signature {
                algorithm: cert.signature.algorithm.to_string(),
                parameters: cert.signature.parameters.iter().map(|f| f.header.tag().0.to_string()).collect(),
            },
            issuer: cert.issuer().to_string(),
            validity: Validity {
                notBefore: cert.validity.not_before.to_string(),
                notAfter: cert.validity.not_after.to_string(),
            },
            subjectPublicKeyInfo:  SubjectPublicKeyInfo {
                algorithm: format_oid_simple(cert.signature_algorithm.oid()),
                subjectPublicKey: format_oid_simple(&cert.public_key().algorithm.algorithm),
            },
            extensions,
        },
        signatureAlgorithm: format_oid_simple(cert.signature_algorithm.oid()),
        signatureValue: cert.signature_value.encode_hex(),

    }
}
