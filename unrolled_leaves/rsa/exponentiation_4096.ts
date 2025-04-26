import { Bytes, Field, Poseidon, Provable, Struct, ZkProgram } from "o1js";
import {
  createProvableBigint,
  EXP_BIT_COUNT,
  rsaExponentiationFastStepped,
} from "../../unrolled_meta/rsa/provableBigint";
import type {
  PerProgram,
  ZkProgramMethods,
} from "../../unrolled_meta/interface";
import { sha256 } from "@noble/hashes/sha256";
import { arrToBigint } from "../../unrolled_meta/utils";

const ProvableBigint4096 = createProvableBigint(4096);
const ONE = ProvableBigint4096.fromBigint(1n);

export class Exp4096_Input extends Struct({
  modulus: ProvableBigint4096,
  signature: ProvableBigint4096,
  exponent: Field,
  messageDigest: Field,
}) {}

export class Exp4096_Output extends Struct({
  result: ProvableBigint4096,
  modulus: ProvableBigint4096,
  signature: ProvableBigint4096,
  exponent: Field,
  messageDigest: Field,
}) {
  hashPoseidon() {
    return Poseidon.hash([
      ...this.result.fields,
      ...this.modulus.fields,
      ...this.signature.fields,
      this.exponent,
      this.messageDigest,
    ]);
  }
}

export const RsaExponentiation_4096_Methods: ZkProgramMethods = {
  first: {
    privateInputs: [Exp4096_Input],
    async method(inp: Exp4096_Input) {
      let acc = ONE;

      const bits = inp.exponent.toBits(EXP_BIT_COUNT);

      // Square-and-multiply exponentiation: First half of bits (MSB downwards)
      // Loop from MSB (EXP_BIT_COUNT - 1) down to the splitPoint (exclusive)
      for (let i = EXP_BIT_COUNT - 1; i >= EXP_BIT_COUNT / 2; i--) {
        acc = ProvableBigint4096.modSquare(acc, inp.modulus);
        let multiplied = acc.modMul(inp.signature, inp.modulus);
        // @ts-ignore
        acc = Provable.if(bits[i], ProvableBigint4096, multiplied, acc);
      }

      const right = new Exp4096_Output({
        ...inp,
        result: acc,
      });
      return {
        publicOutput: {
          left: inp.messageDigest,
          right: right.hashPoseidon(),
          vkDigest: Field(0),
        },
      };
    },
  },

  second: {
    privateInputs: [Exp4096_Output],
    async method(inp: Exp4096_Output) {
      let acc = inp.result;
      acc.assertNotEquals(ONE);

      const bits = inp.exponent.toBits(EXP_BIT_COUNT);

      // Square-and-multiply exponentiation: Second half of bits
      // Loop from index (EXP_BIT_COUNT / 2 - 1) down to LSB (0)
      // Use Math.floor in case EXP_BIT_COUNT is odd, although it's usually even.
      const startIndex = Math.floor(EXP_BIT_COUNT / 2) - 1;
      for (let i = startIndex; i >= 0; i--) {
        acc = ProvableBigint4096.modSquare(acc, inp.modulus);
        let multiplied = acc.modMul(inp.signature, inp.modulus);
        // @ts-ignore
        acc = Provable.if(bits[i], ProvableBigint4096, multiplied, acc);
      }
      const left = inp.hashPoseidon();
      inp.result = acc;
      const right = inp.hashPoseidon();
      return {
        publicOutput: {
          left,
          right,
          vkDigest: Field(0),
        },
      };
    },
  },
};

export function generateCall(
  modulus: bigint,
  signature: Uint8Array,
  exponent: bigint,
  message: Uint8Array,
): PerProgram {
  const messageShaDigest = Bytes.from(sha256(message));
  const messageDigest = Poseidon.hash(
    messageShaDigest.bytes.map((b) => b.value),
  );
  const signBn = arrToBigint(signature);
  const expResults = rsaExponentiationFastStepped(
    signBn,
    modulus,
    exponent,
    [10, 10],
  );
  return {
    methods: RsaExponentiation_4096_Methods,
    calls: [
      {
        methodName: "first",
        args: [
          new Exp4096_Input({
            modulus: ProvableBigint4096.fromBigint(modulus),
            signature: ProvableBigint4096.fromBytes(signature),
            exponent: Field(exponent),
            messageDigest: messageDigest,
          }),
        ],
      },
      {
        methodName: "second",
        args: [
          new Exp4096_Output({
            result: ProvableBigint4096.fromBigint(expResults[0]),
            modulus: ProvableBigint4096.fromBigint(modulus),
            signature: ProvableBigint4096.fromBytes(signature),
            exponent: Field(exponent),
            messageDigest: messageDigest,
          }),
        ],
      },
    ],
  };
}
