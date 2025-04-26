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
import {
  arrToBigint,
  bigintToArr,
  serializedLengthOf,
} from "../../unrolled_meta/utils";
import { rsaExponentiationFast } from "../../unrolled_meta/rsa/provableBigint";
import { sha256 } from "@noble/hashes/sha256";
import Contains from "../../unrolled_meta/contains";

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
        expOut.messageDigest.assertEquals(
          Poseidon.hash(messageShaDigest.bytes.map((b) => b.value)),
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
            right: Poseidon.hash([
              Poseidon.hash(encodedPubkey),
              ...Contains.init().toFields(),
            ]),
            vkDigest: Field(0),
          },
        };
      },
    },
  };
}

export function generateCall(
  isModulusPrefixedWithZero: boolean,
  digestSizeBytes: number,
  saltSizeBytes: number,
  modulus: bigint,
  signature: Uint8Array,
  exponent: bigint,
  signedAttrs: Uint8Array,
): PerProgram {
  const signBn = arrToBigint(signature);
  const expResult = rsaExponentiationFast(signBn, modulus, exponent);
  const encodedMessage = Bytes.from(bigintToArr(expResult));
  const encodedModulus = Bytes.from(bigintToArr(modulus));
  if (digestSizeBytes !== 32) throw new Error("support digest size");
  const messageShaDigest = Bytes.from(sha256(signedAttrs));
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
            messageDigest: Poseidon.hash(
              messageShaDigest.bytes.map((b) => b.value),
            ),
          }),
          messageShaDigest,
          encodedMessage,
          encodedModulus,
        ],
      },
    ],
  };
}
