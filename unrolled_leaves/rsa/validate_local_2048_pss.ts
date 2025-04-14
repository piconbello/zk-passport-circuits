import { Bytes, Field, Poseidon } from "o1js";
import type {
  PerProgram,
  ZkProgramMethods,
} from "../../unrolled_meta/interface";
import { Exp2048_Output } from "./exponentiation_2048";
import { pssVerify } from "../../unrolled_meta/rsa/padding_pss";
import {
  encodeRsaPubkeyFromParts,
  parseFromBE,
} from "../../unrolled_meta/rsa/parsingStatic";
import { ProvableBigint2048, RsaMessage2048 } from "./constants";
import { serializedLengthOf } from "../../unrolled_meta/utils";
import { rsaExponentiationFast } from "../../unrolled_meta/rsa/provableBigint";
import { sha256 } from "@noble/hashes/sha256";

const KEY_SIZE_BITS = 2048n;

export function getRsaValidationLocal2048Pss(
  isModulusPrefixedWithZero: boolean,
  exponentByteLength: number,
  messageDigestAlgoSizeBytes: number,
  saltSizeBytes: number,
): ZkProgramMethods {
  class DigestBytes extends Bytes(messageDigestAlgoSizeBytes) {}
  return {
    validatePss: {
      privateInputs: [
        Exp2048_Output,
        DigestBytes,
        RsaMessage2048,
        RsaMessage2048,
      ],
      async method(
        expOut: Exp2048_Output,
        messageShaDigest: DigestBytes,
        encodedMessage: RsaMessage2048,
        encodedModulus: RsaMessage2048,
      ) {
        const encodedMessageBigint = parseFromBE(
          ProvableBigint2048,
          encodedMessage.bytes,
        );
        expOut.result.assertEquals(
          encodedMessageBigint,
          "encoded message parsed",
        );
        pssVerify(
          encodedMessage.bytes,
          KEY_SIZE_BITS - 1n,
          messageShaDigest,
          saltSizeBytes,
        );

        const modulus = parseFromBE(ProvableBigint2048, encodedModulus.bytes);
        modulus.assertEquals(expOut.modulus);
        const encodedPubkey = encodeRsaPubkeyFromParts(
          Number(KEY_SIZE_BITS),
          isModulusPrefixedWithZero,
          exponentByteLength,
          encodedModulus.bytes,
          expOut.exponent,
        );

        return {
          publicOutput: {
            left: expOut.hashPoseidon(),
            right: Poseidon.hash(encodedPubkey),
            vkDigest: Field(0),
          },
        };
      },
    },
  };
}

const methods = getRsaValidationLocal2048Pss(true, 3, 32, 32);
// console.log(methods);

export function generateCall(
  isModulusPrefixedWithZero: boolean,
  digestSizeBytes: number,
  saltSizeBytes: number,
  modulus: bigint,
  signature: Uint8Array,
  exponent: bigint,
  signedAttrs: Uint8Array,
): PerProgram {
  const signHex = Buffer.from(signature).toString("hex");
  const signBn = signHex ? BigInt("0x" + signHex) : 0n;
  const expResult = rsaExponentiationFast(signBn, modulus, exponent);
  let emHex = expResult.toString(16);
  // Add a leading zero if the length is odd to ensure proper byte alignment
  if (emHex.length % 2 !== 0) {
    emHex = "0" + emHex;
  }
  const encodedMessage = Bytes.from(Buffer.from(emHex, "hex"));
  let modulusHex = modulus.toString(16);
  if (modulusHex.length % 2 !== 0) {
    modulusHex = "0" + modulusHex;
  }
  const encodedModulus = Bytes.from(Buffer.from(modulusHex, "hex"));
  return {
    methods: getRsaValidationLocal2048Pss(
      isModulusPrefixedWithZero,
      serializedLengthOf(exponent),
      digestSizeBytes,
      saltSizeBytes,
    ),
    calls: [
      {
        methodName: "validatePss",
        args: [
          new Exp2048_Output({
            modulus: ProvableBigint2048.fromBigint(modulus),
            signature: ProvableBigint2048.fromBytes(signature),
            exponent: Field(exponent),
            result: ProvableBigint2048.fromBigint(expResult),
          }),
          Bytes.from(sha256(signedAttrs)),
          encodedMessage,
          encodedModulus,
        ],
      },
    ],
  };
}
