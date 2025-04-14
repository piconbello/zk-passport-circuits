// --- Base64 Utilities ---

export function b64ToBigint(b64: string): bigint {
  const buffer = Buffer.from(b64, "base64");
  const hex = buffer.toString("hex");
  // Handle empty buffer case, results in 0n
  return hex ? BigInt("0x" + hex) : 0n;
}

export function decodeBase64(b64: string): Uint8Array {
  const buffer = Buffer.from(b64, "base64");
  return new Uint8Array(buffer);
}

// --- EC Types ---

export interface PublicKeyEC {
  type: "EC";
  curve: string;
  x: bigint;
  y: bigint;
  encoded: Uint8Array;
}

export interface PublicKeyECb64 {
  type: "EC";
  curve: string;
  x: string;
  y: string;
  encoded: string;
}

export interface SignatureEC {
  type: "EC"; // Keep type for consistency after parsing
  r: bigint;
  s: bigint;
}

interface SignatureECb64 {
  type: "EC";
  r: string;
  s: string;
}

// --- RSA Types ---

export interface RSAPublicKey {
  type: "RSA";
  modulus: bigint;
  exponent: bigint;
  key_size_bits: number;
  encoded: Uint8Array;
  is_modulus_prefixed_with_zero: boolean;
}

interface RSAPublicKeyB64 {
  type: "RSA";
  modulus: string;
  exponent: string;
  key_size_bits: number;
  encoded: string;
  is_modulus_prefixed_with_zero: boolean;
}

// RSA Signature Types (Based on JSON example)
// We need distinct types because they have different fields (salt_size_bits etc.)

export interface SignatureRsaPss {
  type: "RsaPss";
  signature: Uint8Array;
  salt_size_bits: number;
  message_hash_algorithm: string;
  mgf_hash_algorithm: string;
}

interface SignatureRsaPssB64 {
  type: "RsaPss";
  signature: string; // base64
  salt_size_bits: number;
  message_hash_algorithm: string;
  mgf_hash_algorithm: string;
}

export interface SignatureRsaPkcs {
  type: "RsaPkcs";
  signature: Uint8Array;
  message_hash_algorithm: string;
}

interface SignatureRsaPkcsB64 {
  type: "RsaPkcs";
  signature: string; // base64
  message_hash_algorithm: string;
}

// --- Union Types ---

export type PublicKey = PublicKeyEC | RSAPublicKey;
type PublicKeyB64 = PublicKeyECb64 | RSAPublicKeyB64;

export type Signature = SignatureEC | SignatureRsaPss | SignatureRsaPkcs;
type SignatureB64 = SignatureECb64 | SignatureRsaPssB64 | SignatureRsaPkcsB64;

// --- Bundle Interfaces ---

export interface BundleBase64 {
  dg1: string;
  dg1_variant: string; // e.g., "TD3"
  lds: string;
  signed_attrs: string;
  digest_algo: string; // e.g., "SHA256"
  document_signature: SignatureB64;
  cert_local_pubkey: PublicKeyB64;
  cert_local_tbs: string;
  cert_local_tbs_digest_algo: string; // e.g., "SHA256"
  cert_local_signature: SignatureB64;
  cert_master_subject_key_id: string | null; // Can be null
  cert_master_pubkey: PublicKeyB64;
}

export interface Bundle {
  dg1: Uint8Array;
  dg1_variant: string;
  lds: Uint8Array;
  signed_attrs: Uint8Array;
  digest_algo: string;
  document_signature: Signature;
  cert_local_pubkey: PublicKey;
  cert_local_tbs: Uint8Array;
  cert_local_tbs_digest_algo: string;
  cert_local_signature: Signature;
  cert_master_subject_key_id: Uint8Array | null; // Parsed optional field
  cert_master_pubkey: PublicKey;
}

// --- Master Cert Types ---

export interface MasterCert {
  pubkey: PublicKey;
  subject_key_id: Uint8Array;
}

interface MasterCertB64 {
  pubkey: PublicKeyB64;
  subject_key_id: string;
}

// --- Parsing Functions ---

function parsePublicKeyECB64(pk: PublicKeyECb64): PublicKeyEC {
  // Type assertion already done by caller
  return {
    type: "EC",
    curve: pk.curve,
    x: b64ToBigint(pk.x),
    y: b64ToBigint(pk.y),
    encoded: decodeBase64(pk.encoded),
  };
}

function parseRSAPublicKeyB64(pk: RSAPublicKeyB64): RSAPublicKey {
  // Type assertion already done by caller
  return {
    type: "RSA",
    modulus: b64ToBigint(pk.modulus),
    exponent: b64ToBigint(pk.exponent),
    key_size_bits: pk.key_size_bits,
    encoded: decodeBase64(pk.encoded),
    is_modulus_prefixed_with_zero: pk.is_modulus_prefixed_with_zero,
  };
}

function parsePublicKeyB64(pk: PublicKeyB64): PublicKey {
  switch (pk.type) {
    case "EC":
      return parsePublicKeyECB64(pk);
    case "RSA":
      return parseRSAPublicKeyB64(pk);
    default:
      throw new Error(`Unsupported public key type: ${(pk as any).type}`);
  }
}

function parseSignatureECB64(sig: SignatureECb64): SignatureEC {
  // Type assertion already done by caller
  return {
    type: "EC",
    r: b64ToBigint(sig.r),
    s: b64ToBigint(sig.s),
  };
}

function parseSignatureRsaPssB64(sig: SignatureRsaPssB64): SignatureRsaPss {
  // Type assertion already done by caller
  return {
    type: "RsaPss",
    signature: decodeBase64(sig.signature),
    salt_size_bits: sig.salt_size_bits,
    message_hash_algorithm: sig.message_hash_algorithm,
    mgf_hash_algorithm: sig.mgf_hash_algorithm,
  };
}

function parseSignatureRsaPkcsB64(sig: SignatureRsaPkcsB64): SignatureRsaPkcs {
  // Type assertion already done by caller
  return {
    type: "RsaPkcs",
    signature: decodeBase64(sig.signature),
    message_hash_algorithm: sig.message_hash_algorithm,
  };
}

function parseSignatureB64(sig: SignatureB64): Signature {
  switch (sig.type) {
    case "EC":
      return parseSignatureECB64(sig);
    case "RsaPss":
      return parseSignatureRsaPssB64(sig);
    case "RsaPkcs":
      return parseSignatureRsaPkcsB64(sig);
    default:
      throw new Error(`Unsupported signature type: ${(sig as any).type}`);
  }
}

// --- Main Bundle Parser ---

export function parseBundleB64(b: BundleBase64): Bundle {
  return {
    dg1: decodeBase64(b.dg1),
    dg1_variant: b.dg1_variant,
    lds: decodeBase64(b.lds),
    signed_attrs: decodeBase64(b.signed_attrs),
    digest_algo: b.digest_algo,
    document_signature: parseSignatureB64(b.document_signature),
    cert_local_pubkey: parsePublicKeyB64(b.cert_local_pubkey),
    cert_local_tbs: decodeBase64(b.cert_local_tbs),
    cert_local_tbs_digest_algo: b.cert_local_tbs_digest_algo,
    cert_local_signature: parseSignatureB64(b.cert_local_signature),
    cert_master_subject_key_id: b.cert_master_subject_key_id
      ? decodeBase64(b.cert_master_subject_key_id)
      : null,
    cert_master_pubkey: parsePublicKeyB64(b.cert_master_pubkey),
  };
}

// --- Master Cert List Parser ---

function parseMasterCertB64(cert: MasterCertB64): MasterCert {
  return {
    pubkey: parsePublicKeyB64(cert.pubkey),
    subject_key_id: decodeBase64(cert.subject_key_id),
  };
}

export function parseBundle(bundleJson: string): Bundle {
  const bundleB64: BundleBase64 = JSON.parse(bundleJson);
  return parseBundleB64(bundleB64);
}

export function parseMasterlist(masterlistJson: string): MasterCert[] {
  const masterlistB64: MasterCertB64[] = JSON.parse(masterlistJson);
  return masterlistB64.map(parseMasterCertB64); // Use the renamed function
}
