import { Bytes, Field, Poseidon } from "o1js";
import type {
  PerProgram,
  ZkProgramMethods,
} from "../../unrolled_meta/interface";
import { ProvableBigint4096 } from "./constants";
import { Exp4096_Output } from "./exponentiation_4096";
import { rsaMessageFromDigest } from "../../unrolled_meta/rsa/padding_pkcs";
import {
  rsaExponentiationFast,
  rsaExponentiationFastStepped,
} from "../../unrolled_meta/rsa/provableBigint";
import { arrToBigint, bigintToArr } from "../../unrolled_meta/utils";
import { sha256 } from "@noble/hashes/sha256";

function getRsaValidationMaster4096Pkcs(
  messageDigestAlgoSizeBytes: number,
): ZkProgramMethods {
  class DigestBytes extends Bytes(messageDigestAlgoSizeBytes) {}
  return {
    validatePkcs: {
      privateInputs: [Exp4096_Output, DigestBytes],
      async method(expOut: Exp4096_Output, messageShaDigest: DigestBytes) {
        const encodedMessage = rsaMessageFromDigest(
          ProvableBigint4096,
          messageShaDigest,
        );
        expOut.result.assertEquals(encodedMessage);
        return {
          publicOutput: {
            left: expOut.hashPoseidon(),
            right: Poseidon.hash([...expOut.modulus.fields, expOut.exponent]),
            vkDigest: Field(0),
          },
        };
      },
    },
  };
}

export function generateCall(
  digestSizeBytes: number,
  modulus: bigint,
  signature: Uint8Array,
  exponent: bigint,
  certTbs: Uint8Array,
): PerProgram {
  const signBn = arrToBigint(signature);
  const expResult = rsaExponentiationFast(signBn, modulus, exponent);
  if (digestSizeBytes !== 32) throw new Error("support digest size");
  const messageShaDigest = Bytes.from(sha256(certTbs));

  return {
    methods: getRsaValidationMaster4096Pkcs(digestSizeBytes),
    calls: [
      {
        methodName: "validatePkcs",
        args: [
          new Exp4096_Output({
            modulus: ProvableBigint4096.fromBigint(modulus),
            signature: ProvableBigint4096.fromBytes(signature),
            exponent: Field(exponent),
            result: ProvableBigint4096.fromBigint(expResult),
            messageDigest: Poseidon.hash(
              messageShaDigest.bytes.map((b) => b.value),
            ),
          }),
          messageShaDigest,
        ],
      },
    ],
  };
}
