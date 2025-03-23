export interface PublicKeyEC {
  type: "EC";
  curve: string;
  x: bigint;
  y: bigint;
}

export interface PublicKeyECb64 {
  type: "EC";
  curve: string;
  x: string;
  y: string;
}

export interface SignatureEC {
  r: bigint;
  s: bigint;
}

interface SignatureECb64 {
  type: string;
  r: string;
  s: string;
}

export interface RSAPublicKey {
  type: "RSA";
  modulus: bigint;
  exponent: bigint;
}

interface RSAPublicKeyB64 {
  type: "RSA";
  modulus: string;
  exponent: string;
}

export interface BundleBase64 {
  dg1: string;
  lds: string;
  signed_attrs: string;
  digest_algo: string;
  document_signature: SignatureECb64;
  cert_local_pubkey: PublicKeyECb64;
  cert_local_tbs: string;
  cert_local_tbs_digest_algo: string;
  cert_local_signature: SignatureECb64;
  cert_master_subject_key_id: string;
  cert_master_pubkey: PublicKeyECb64;
}

export interface Bundle {
  dg1: Uint8Array;
  lds: Uint8Array;
  signed_attrs: Uint8Array;
  digest_algo: string;
  document_signature: SignatureEC;
  cert_local_pubkey: PublicKeyEC;
  cert_local_tbs: Uint8Array;
  cert_local_tbs_digest_algo: string;
  cert_local_signature: SignatureEC;
  cert_master_subject_key_id: Uint8Array;
  cert_master_pubkey: PublicKeyEC;
}

interface MasterCertB64 {
  pubkey: RSAPublicKeyB64 | PublicKeyECb64;
  subject_key_id: string;
}

export interface MasterCert {
  pubkey: RSAPublicKey | PublicKeyEC;
  subject_key_id: Uint8Array;
}

// function b64ToBigint(b64: string): bigint {
//   // x: BigInt("0x" + encodeHex(decodeBase64(pk.x))),

//   // @ts-ignore
//   return BigInt("0x" + Uint8Array.fromBase64(b64).toHex());
// }

// function decodeBase64(b64: string): Uint8Array {
//   // @ts-ignore
//   return Uint8Array.fromBase64(b64);
// }

export function b64ToBigint(b64: string): bigint {
  const buffer = Buffer.from(b64, "base64");
  const hex = buffer.toString("hex");
  return BigInt("0x" + hex);
}

export function decodeBase64(b64: string): Uint8Array {
  const buffer = Buffer.from(b64, "base64");
  return new Uint8Array(buffer);
}

function parsePublicKeyEC(pk: PublicKeyECb64): PublicKeyEC {
  if (pk.type !== "EC") {
    throw new Error("not EC pk");
  }
  return {
    type: "EC",
    curve: pk.curve,
    x: b64ToBigint(pk.x),
    y: b64ToBigint(pk.y),
  };
}

function parseSignatureECB64(sig: SignatureECb64): SignatureEC {
  if (sig.type !== "EC") {
    throw new Error("not EC sig");
  }
  return {
    r: b64ToBigint(sig.r),
    s: b64ToBigint(sig.s),
  };
}

function parseRSAPublicKey(pk: RSAPublicKeyB64): RSAPublicKey {
  return {
    type: "RSA",
    modulus: b64ToBigint(pk.modulus),
    exponent: b64ToBigint(pk.exponent),
  };
}

export function parseBundleB64(b: BundleBase64): Bundle {
  // if (
  //   b.digest_algo !== "id-sha256" ||
  //   b.cert_local_tbs_digest_algo !== "id-sha256"
  // ) {
  //   throw new Error("not sha256");
  // }
  return {
    dg1: decodeBase64(b.dg1),
    lds: decodeBase64(b.lds),
    signed_attrs: decodeBase64(b.signed_attrs),
    digest_algo: b.digest_algo,
    document_signature: parseSignatureECB64(b.document_signature),
    cert_local_pubkey: parsePublicKeyEC(b.cert_local_pubkey),
    cert_local_tbs: decodeBase64(b.cert_local_tbs),
    cert_local_tbs_digest_algo: b.cert_local_tbs_digest_algo,
    cert_local_signature: parseSignatureECB64(b.cert_local_signature),
    cert_master_subject_key_id: decodeBase64(b.cert_master_subject_key_id),
    cert_master_pubkey: parsePublicKeyEC(b.cert_master_pubkey),
  };
}

function parseMasterCert(cert: MasterCertB64): MasterCert {
  return {
    pubkey:
      cert.pubkey.type === "RSA"
        ? parseRSAPublicKey(cert.pubkey as RSAPublicKeyB64)
        : parsePublicKeyEC(cert.pubkey as PublicKeyECb64),
    subject_key_id: decodeBase64(cert.subject_key_id),
  };
}

export function parseBundle(bundleJson: string): Bundle {
  const bundleB64: BundleBase64 = JSON.parse(bundleJson);
  return parseBundleB64(bundleB64);
}

export function parseMasterlist(masterlistJson: string): MasterCert[] {
  const masterlistB64: MasterCertB64[] = JSON.parse(masterlistJson);
  return masterlistB64.map(parseMasterCert);
}
