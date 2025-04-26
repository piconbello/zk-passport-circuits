import { Field, Provable, Struct, Poseidon, Bytes } from "o1js";
import {
  createProvableBigint,
  EXP_BIT_COUNT,
} from "../../unrolled_meta/rsa/provableBigint";
import type {
  PerProgram,
  ZkProgramMethods,
} from "../../unrolled_meta/interface";
import { sha256 } from "@noble/hashes/sha256";

const ProvableBigint2048 = createProvableBigint(2048);
const ONE = ProvableBigint2048.fromBigint(1n);

export class Exp2048_Input extends Struct({
  modulus: ProvableBigint2048,
  signature: ProvableBigint2048,
  exponent: Field,
  messageDigest: Field,
}) {}

export class Exp2048_Output extends Struct({
  result: ProvableBigint2048,
  modulus: ProvableBigint2048,
  signature: ProvableBigint2048,
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

export const RsaExponentiation_2048_Methods: ZkProgramMethods = {
  exponentiate: {
    privateInputs: [Exp2048_Input],

    async method(inp: Exp2048_Input) {
      let acc = ONE;
      const bits = inp.exponent.toBits(EXP_BIT_COUNT);

      // Perform square-and-multiply exponentiation: acc = signature^exponent mod modulus
      // Loop through all bits from MSB down to LSB
      for (let i = EXP_BIT_COUNT - 1; i >= 0; i--) {
        acc = ProvableBigint2048.modSquare(acc, inp.modulus);
        let multiplied = acc.modMul(inp.signature, inp.modulus);
        // @ts-ignore
        acc = Provable.if(bits[i], ProvableBigint2048, multiplied, acc);
      }

      const out = new Exp2048_Output({
        ...inp,
        result: acc,
      });
      return {
        publicOutput: {
          left: inp.messageDigest,
          right: out.hashPoseidon(),
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
  signedAttrs: Uint8Array,
): PerProgram {
  return {
    methods: RsaExponentiation_2048_Methods,
    calls: [
      {
        methodName: "exponentiate",
        args: [
          new Exp2048_Input({
            modulus: ProvableBigint2048.fromBigint(modulus),
            signature: ProvableBigint2048.fromBytes(signature),
            exponent: Field(exponent),
            messageDigest: Poseidon.hash(
              Bytes.from(sha256(signedAttrs)).bytes.map((b) => b.value),
            ),
          }),
        ],
      },
    ],
  };
}
