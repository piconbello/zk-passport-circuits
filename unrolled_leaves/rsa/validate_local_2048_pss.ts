import { Bytes, Field, ZkProgram, Poseidon, Struct } from "o1js";
import type { ZkProgramMethods } from "../../unrolled_meta/interface";
import { Exp2048_Output } from "./exponentiation_2048";
import { pssVerify } from "../../unrolled_meta/rsa/padding_pss";
import {
  encodeRsaPubkeyFromParts,
  parseFromBE,
} from "../../unrolled_meta/rsa/parsingStatic";
import type { Length } from "../../unrolled_meta/rsa/constants";
import { Out } from "../../unrolled_meta/out";
import { mapObject } from "../../tests/common";
import { ProvableBigint2048, RsaMessage2048 } from "./constants";

const KEY_SIZE_BITS = 2048n;

export function getRsaValidationLocal2048Pss(
  isModulusPrefixedWithZero: boolean,
  exponentByteLength: number,
  messageDigestAlgoSizeBytes: Length,
  saltSizeBytes: Length,
): ZkProgramMethods {
  class DigestBytes extends Bytes(messageDigestAlgoSizeBytes) {}
  return {
    validatePss: {
      privateInputs: [
        Exp2048_Output,
        DigestBytes,
        RsaMessage2048,
        RsaMessage2048,
        Field,
      ],
      async method(
        expOut: Exp2048_Output,
        messageShaDigest: DigestBytes,
        encodedMessage: RsaMessage2048,
        encodedModulus: RsaMessage2048,
        exponent: Field,
      ) {
        expOut.carry.assertEquals(
          Poseidon.hash(messageShaDigest.bytes.map((b) => b.value)),
          "message sha digest poseidon digest",
        );
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
        exponent.assertEquals(expOut.exponent);
        const encodedPubkey = encodeRsaPubkeyFromParts(
          Number(KEY_SIZE_BITS),
          isModulusPrefixedWithZero,
          exponentByteLength,
          encodedModulus.bytes,
          exponent,
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

const ValidateLocal = ZkProgram({
  name: "validate-local",
  publicOutput: Out,
  methods: methods,
});

async function analyze() {
  const analysis = await ValidateLocal.analyzeMethods();
  console.log(mapObject(analysis, (m) => m.summary()["Total rows"]));
}

await analyze();
