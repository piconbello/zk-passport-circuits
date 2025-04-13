import { Field, Provable, Struct, ZkProgram, Poseidon } from "o1js";
import {
  createProvableBigint,
  EXP_BIT_COUNT,
} from "../../unrolled_meta/rsa/provableBigint";
import { mapObject } from "../../tests/common";
import { Out } from "../../unrolled_meta/out";
import type { ZkProgramMethods } from "../../unrolled_meta/interface";

const ProvableBigint2048 = createProvableBigint(2048);
const ONE = ProvableBigint2048.fromBigint(1n);

export class Exp2048_Input extends Struct({
  modulus: ProvableBigint2048,
  signature: ProvableBigint2048,
  exponent: Field,
  carry: Field,
}) {
  hashPoseidon() {
    return Poseidon.hash([
      ...this.modulus.fields,
      ...this.signature.fields,
      this.exponent,
      this.carry,
    ]);
  }
}

export class Exp2048_Output extends Struct({
  result: ProvableBigint2048,
  modulus: ProvableBigint2048,
  signature: ProvableBigint2048,
  exponent: Field,
  carry: Field,
}) {
  hashPoseidon() {
    const inpDigest = Poseidon.hash([
      ...this.modulus.fields,
      ...this.signature.fields,
      this.exponent,
      this.carry,
    ]);
    return Poseidon.hash([inpDigest, ...this.result.fields]);
  }
}

export const ExpExponentiation2048_Methods: ZkProgramMethods = {
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
          left: inp.hashPoseidon(),
          right: out.hashPoseidon(),
          vkDigest: Field(0),
        },
      };
    },
  },
};

export const RsaVerificationSingle_2048 = ZkProgram({
  name: "rsa-verify-2048-single",
  publicOutput: Out,
  methods: ExpExponentiation2048_Methods,
});

// --- Analysis (Optional) ---
async function analyze() {
  const analysis = await RsaVerificationSingle_2048.analyzeMethods();
  console.log(mapObject(analysis, (m) => m.summary()["Total rows"]));
}

// analyze();
