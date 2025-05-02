import { z } from "zod";

const B64StringSchema = z.string().base64().or(z.literal(""));

const PublicKeyECSchemaBase = z.object({
  type: z.literal("EC"),
  curve: z.string(),
  x: B64StringSchema,
  y: B64StringSchema,
  encoded: B64StringSchema,
});

const RSAPublicKeySchemaBase = z.object({
  type: z.literal("RSA"),
  modulus: B64StringSchema,
  exponent: B64StringSchema,
  key_size_bits: z.number().int(),
  encoded: B64StringSchema,
  is_modulus_prefixed_with_zero: z.boolean(),
});

const PublicKeySchema = z.discriminatedUnion("type", [
  PublicKeyECSchemaBase,
  RSAPublicKeySchemaBase,
]);

const SignatureECSchemaBase = z.object({
  type: z.literal("EC"),
  r: B64StringSchema, // Store as string
  s: B64StringSchema, // Store as string
});

const SignatureRsaPssSchemaBase = z.object({
  type: z.literal("RsaPss"),
  signature: B64StringSchema, // Store as string
  salt_size_bits: z.number().int(),
  message_hash_algorithm: z.string(),
  mgf_hash_algorithm: z.string(),
});

const SignatureRsaPkcsSchemaBase = z.object({
  type: z.literal("RsaPkcs"),
  signature: B64StringSchema, // Store as string
  message_hash_algorithm: z.string(),
});

const SignatureSchema = z.discriminatedUnion("type", [
  SignatureECSchemaBase,
  SignatureRsaPssSchemaBase,
  SignatureRsaPkcsSchemaBase,
]);

// Bundle Schema using only string validation for b64 fields
const BundleStringSchema = z.object({
  dg1: B64StringSchema,
  dg1_variant: z.string(),
  lds: B64StringSchema,
  signed_attrs: B64StringSchema,
  digest_algo: z.string(),
  document_signature: SignatureSchema, // Will contain string fields
  cert_local_pubkey: PublicKeySchema, // Will contain string fields
  cert_local_tbs: B64StringSchema,
  cert_local_tbs_digest_algo: z.string(),
  cert_local_signature: SignatureSchema, // Will contain string fields
  cert_master_subject_key_id: B64StringSchema.nullable(),
  cert_master_pubkey: PublicKeySchema, // Will contain string fields
});

// Master Cert Schema using only string validation
const MasterCertStringSchema = z.object({
  pubkey: PublicKeySchema, // Will contain string fields
  subject_key_id: B64StringSchema,
});

const MasterListStringSchema = z.object({
  pairs: z.array(MasterCertStringSchema),
});

// --- Exported Types (will contain strings for b64 data) ---
// export type PublicKeyEC = z.infer<typeof PublicKeyECSchemaBase>;
export type RSAPublicKey = z.infer<typeof RSAPublicKeySchemaBase>;
export type PublicKey = z.infer<typeof PublicKeySchema>;

// export type SignatureEC = z.infer<typeof SignatureECSchemaBase>;
export type SignatureRsaPss = z.infer<typeof SignatureRsaPssSchemaBase>;
export type SignatureRsaPkcs = z.infer<typeof SignatureRsaPkcsSchemaBase>;
export type Signature = z.infer<typeof SignatureSchema>;

export type Bundle = z.infer<typeof BundleStringSchema>;
export type MasterCert = z.infer<typeof MasterCertStringSchema>;

// --- Parsing Functions ---
export function parseBundle(bundleJson: string): Bundle {
  const rawBundle = JSON.parse(bundleJson);
  // Parse using the schema that keeps strings as strings
  return BundleStringSchema.parse(rawBundle);
}

export function parseMasterlist(masterlistJson: string): MasterCert[] {
  const rawMasterlist = JSON.parse(masterlistJson);
  // Parse using the schema that keeps strings as strings
  const parsed = MasterListStringSchema.parse(rawMasterlist);
  return parsed.pairs;
}

// --- Example Usage ---
async function main() {
  const b64ToUint8Array = (val: string): Uint8Array =>
    Uint8Array.from(Buffer.from(val, "base64"));

  const b64ToBigint = (b64: string): bigint => {
    const buffer = Buffer.from(b64, "base64");
    if (buffer.length === 0) {
      return 0n; // Handle empty buffer explicitly
    }
    const hex = buffer.toString("hex");
    return BigInt("0x" + hex);
  };

  try {
    // Assuming the file exists relative to where the script is run
    const t = await Bun.file("./files/masterlist_284.json").text();
    console.log("parsing masterlist in bundle.ts");
    const masters = parseMasterlist(t);
    console.log(masters);
  } catch (error) {
    console.error("Error during processing:", error);
    if (error instanceof z.ZodError) {
      console.error("Validation Issues:", error.errors);
    }
  }
}

// main();
