import {
  parseBundleB64,
  type RSAPublicKey,
  type SignatureRsaPss,
} from "../src/parseBundle";
import bundleJson from "../files/bundle.emre.expired.json";
import { generateCalls as generateCallsDG1 } from "../unrolled_leaves/dg1_td3_256";
import { generateCalls as generateCallsLDS } from "../unrolled_leaves/lds_256";
import { generateCall as generateCallSignedAttrs } from "../unrolled_leaves/signedAttrs_256_256";
import { generateCall as generateCallLocalExponentiate } from "../unrolled_leaves/rsa/exponentiation_2048";

import { generateCall as generateCallsLocalRsaVerify } from "../unrolled_leaves/rsa/validate_local_2048_pss";

import type { PerProgram } from "../unrolled_meta/interface";
import {
  createProvableBigint,
  rsaExponentiation,
} from "../unrolled_meta/rsa/provableBigint";
import { Bytes, Field, Poseidon } from "o1js";
import {
  Exp2048_Input,
  Exp2048_Output,
  ExpExponentiation2048_Methods,
} from "../unrolled_leaves/rsa/exponentiation_2048";
import { sha256 } from "@noble/hashes/sha256";
import { getRsaValidationLocal2048Pss } from "../unrolled_leaves/rsa/validate_local_2048_pss";
import type { Length } from "../unrolled_meta/rsa/constants";
import { processFast } from "./processPipelineFast";
import { serializedLengthOf } from "../unrolled_meta/utils";
import { processPipeline } from "./processPipelineSlow";

const Bigint2048 = createProvableBigint(2048);

// function generateCallLocalRsaExponentiate(
//   signedAttrs: Uint8Array,
//   modulus: bigint,
//   signature: Uint8Array,
//   exponent: bigint,
// ): PerProgram {
//   const signatureHex = Buffer.from(signature).toString("hex");
//   const signatureBigint = signatureHex ? BigInt("0x" + signatureHex) : 0n;
//   const messageShaDigest = Bytes.from(sha256(signedAttrs));
//   const messageShaDigestPoseidon = Poseidon.hash(
//     messageShaDigest.bytes.map((b) => b.value),
//   );
//   const expInput = new Exp2048_Input({
//     modulus: Bigint2048.fromBigint(modulus),
//     signature: Bigint2048.fromBigint(signatureBigint),
//     exponent: Field(exponent),
//     carry: messageShaDigestPoseidon,
//   });
//   return {
//     methods: ExpExponentiation2048_Methods,
//     calls: [
//       {
//         methodName: "exponentiate",
//         args: [expInput],
//       },
//     ],
//   };
// }

// function generateCallsLocalRsaVerify(
//   signedAttrs: Uint8Array,
//   modulus: bigint,
//   signature: Uint8Array,
//   exponent: bigint,
//   isModulusPrefixedWithZero: boolean,
//   saltDigestBytesLen: number,
// ): PerProgram {
//   const signatureHex = Buffer.from(signature).toString("hex");
//   const signatureBigint = signatureHex ? BigInt("0x" + signatureHex) : 0n;
//   const messageShaDigest = Bytes.from(sha256(signedAttrs));
//   const messageShaDigestPoseidon = Poseidon.hash(
//     messageShaDigest.bytes.map((b) => b.value),
//   );
//   const modulusPBN = Bigint2048.fromBigint(modulus);
//   const signaturePBN = Bigint2048.fromBigint(signatureBigint);

//   const expResult = rsaExponentiation(
//     Bigint2048,
//     signaturePBN,
//     modulusPBN,
//     Field(exponent),
//   );
//   const expOutput = new Exp2048_Output({
//     result: expResult,
//     modulus: modulusPBN,
//     signature: signaturePBN,
//     exponent: Field(exponent),
//     carry: messageShaDigestPoseidon,
//   });

//   const exponentLength = serializedLengthOf(exponent);
//   console.log(exponent);
//   console.log("exponentLength", exponentLength);
//   const validationMethods = getRsaValidationLocal2048Pss(
//     isModulusPrefixedWithZero,
//     exponentLength,
//     32,
//     saltDigestBytesLen as Length,
//   );
//   const encodedMessageBuf = Buffer.from(
//     expResult.toBigint().toString(16),
//     "hex",
//   );
//   const encodedMessage = Bytes.from(encodedMessageBuf);
//   const encodedModulusBuf = Buffer.from(modulus.toString(16), "hex");
//   const encodedModulus = Bytes.from(encodedModulusBuf);

//   return {
//     methods: validationMethods,
//     calls: [
//       {
//         methodName: "validatePss",
//         args: [
//           expOutput,
//           messageShaDigest,
//           encodedMessage,
//           encodedModulus,
//           Field(exponent),
//         ],
//       },
//     ],
//   };
// }

function getPipeline() {
  const bundle = parseBundleB64(bundleJson as any);
  const pubkeyLocal = bundle.cert_local_pubkey as RSAPublicKey;
  const signatureDoc = bundle.document_signature as SignatureRsaPss;

  const callsPerProgram: PerProgram[] = [
    generateCallsDG1(bundle.dg1),
    ...generateCallsLDS(bundle.lds, bundle.dg1),
    generateCallSignedAttrs(bundle.signed_attrs, bundle.lds),
    generateCallLocalExponentiate(
      pubkeyLocal.modulus,
      signatureDoc.signature,
      pubkeyLocal.exponent,
      bundle.signed_attrs,
    ),
    generateCallsLocalRsaVerify(
      pubkeyLocal.is_modulus_prefixed_with_zero,
      32,
      32,
      pubkeyLocal.modulus,
      signatureDoc.signature,
      pubkeyLocal.exponent,
      bundle.signed_attrs,
    ),
  ];

  return callsPerProgram;
}

const allOut = await processFast(getPipeline());
console.log(allOut);
