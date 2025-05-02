import { z } from "zod";

const B64 = z
  .string()
  .base64()
  .transform((val) => Uint8Array.from(Buffer.from(val, "base64")));

export function b64ToBigint(b64: string): bigint {
  const buffer = Buffer.from(b64, "base64");
  const hex = buffer.toString("hex");
  // Handle empty buffer case, results in 0n
  return hex ? BigInt("0x" + hex) : 0n;
}

export function bigintToB64(n: bigint): string {
  if (n < 0n) {
    throw new Error("Input BigInt must be non-negative.");
  }
  if (n === 0n) {
    return "";
  }
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  const buffer = Buffer.from(hex, "hex");
  return buffer.toString("base64");
}

const B64Bigint = z.string().base64();

export const S_DG1 = z.object({
  variant: z.literal("TD3"),
  digestAlgo: z.literal("sha256"),
  dg1: B64,
});

export const S_LDS = z.object({
  digestAlgo: z.literal("sha256"),
  dg1: B64,
  lds: B64,
});

export const S_SIGNEDATTRS = z.object({
  digestAlgo: z.literal("sha256"),
  lds: B64,
  signedAttrs: B64,
});

export const S_RSA_EXP_LOCAL = z.object({
  keySize: z.literal(2048),
  modulus: B64Bigint,
  signature: B64,
  exponent: B64Bigint,
  signedAttrs: B64,
});

export const S_RSA_VERIFY_LOCAL_PSS = z.object({
  keySize: z.literal(2048),
  isModulusPrefixedWithZero: z.boolean(),
  digestSizeBytes: z.number().int().positive(),
  saltSizeBytes: z.number().int().positive(),
  modulus: B64Bigint,
  signature: B64,
  exponent: B64Bigint,
  signedAttrs: B64,
});

export const S_PUBKEY_IN_CERT = z.object({
  certLocalTbs: B64,
  pubkeyLocalEncoded: B64,
});

export const S_DIGEST_CERT = z.object({
  digestAlgo: z.literal("sha256"),
  certLocalTbs: B64,
});

export const S_RSA_EXP_MASTER = z.object({
  keySize: z.literal(4096),
  modulus: B64Bigint,
  signature: B64,
  exponent: B64Bigint,
  message: B64,
});

export const S_RSA_VERIFY_MASTER_PKCS = z.object({
  keySize: z.literal(4096),
  digestSizeBytes: z.number().int().positive(),
  modulus: B64Bigint,
  signature: B64,
  exponent: B64Bigint,
  message: B64,
});

export const S_MASTERLIST_CONTAINS = z.object({
  masterlistLeaves: z.array(B64Bigint),
  leaf: B64Bigint,
  maxTreeDepth: z.number().int().positive(),
});

export const StepSchema = z.discriminatedUnion("step", [
  z.object({
    step: z.literal("DG1"),
    data: S_DG1,
  }),
  z.object({
    step: z.literal("LDS"),
    data: S_LDS,
  }),
  z.object({
    step: z.literal("SIGNEDATTRS"),
    data: S_SIGNEDATTRS,
  }),
  z.object({
    step: z.literal("RSA_EXP_LOCAL"),
    data: S_RSA_EXP_LOCAL,
  }),
  z.object({
    step: z.literal("RSA_VERIFY_LOCAL_PSS"),
    data: S_RSA_VERIFY_LOCAL_PSS,
  }),
  z.object({
    step: z.literal("PUBKEY_IN_CERT"),
    data: S_PUBKEY_IN_CERT,
  }),
  z.object({
    step: z.literal("DIGEST_CERT"),
    data: S_DIGEST_CERT,
  }),
  z.object({
    step: z.literal("RSA_EXP_MASTER"),
    data: S_RSA_EXP_MASTER,
  }),
  z.object({
    step: z.literal("RSA_VERIFY_MASTER_PKCS"),
    data: S_RSA_VERIFY_MASTER_PKCS,
  }),
  z.object({
    step: z.literal("MASTERLIST_CONTAINS"),
    data: S_MASTERLIST_CONTAINS,
  }),
]);

export type Step = z.infer<typeof StepSchema>;
export type StepSerial = z.input<typeof StepSchema>;

// const stepData: StepSerial = {
//   step: "DG1",
//   data: {
//     variant: "TD3",
//     digestAlgo: "sha256",
//     dg1: "aGVsbG8gd29ybGQ=",
//   },
// };

// console.log(stepData);

// console.log(parsed);
