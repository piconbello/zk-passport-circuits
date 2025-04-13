import { Field, Poseidon, Provable, Struct, ZkProgram } from "o1js";
import {
  createProvableBigint,
  EXP_BIT_COUNT,
} from "../../unrolled_meta/rsa/provableBigint";
import type { ZkProgramMethods } from "../../unrolled_meta/interface";
import { Out } from "../../unrolled_meta/out";
import { mapObject } from "../../tests/common";

const ProvableBigint4096 = createProvableBigint(4096);

export class ExpState4096 extends Struct({
  acc: ProvableBigint4096,
  modulus: ProvableBigint4096,
  signature: ProvableBigint4096,
  exponent: Field,
  messageHashPoseidon: Field,
}) {
  hashPoseidon() {
    return Poseidon.hash([
      ...this.acc.fields,
      ...this.modulus.fields,
      ...this.signature.fields,
      this.exponent,
      this.messageHashPoseidon,
    ]);
  }
}
const ONE = ProvableBigint4096.fromBigint(1n);

export const RsaExponentiation_4096_Methods: ZkProgramMethods = {
  first: {
    privateInputs: [ExpState4096],
    async method(state: ExpState4096) {
      state.acc.assertEquals(ONE);
      let acc = ONE;

      const bits = state.exponent.toBits(EXP_BIT_COUNT);

      // Square-and-multiply exponentiation: First half of bits (MSB downwards)
      // Loop from MSB (EXP_BIT_COUNT - 1) down to the splitPoint (exclusive)
      for (let i = EXP_BIT_COUNT - 1; i >= EXP_BIT_COUNT / 2; i--) {
        acc = ProvableBigint4096.modSquare(acc, state.modulus);
        let multiplied = acc.modMul(state.signature, state.modulus);
        // @ts-ignore
        acc = Provable.if(bits[i], ProvableBigint4096, multiplied, acc);
      }

      state.acc = acc;
      return {
        publicOutput: {
          left: state.messageHashPoseidon,
          right: state.hashPoseidon(),
          vkDigest: Field(0),
        },
      };
    },
  },

  second: {
    privateInputs: [ExpState4096],
    async method(state: ExpState4096) {
      let acc = state.acc;
      acc.assertNotEquals(ONE);

      const bits = state.exponent.toBits(EXP_BIT_COUNT);

      // Square-and-multiply exponentiation: Second half of bits
      // Loop from index (EXP_BIT_COUNT / 2 - 1) down to LSB (0)
      // Use Math.floor in case EXP_BIT_COUNT is odd, although it's usually even.
      const startIndex = Math.floor(EXP_BIT_COUNT / 2) - 1;
      for (let i = startIndex; i >= 0; i--) {
        acc = ProvableBigint4096.modSquare(acc, state.modulus);
        let multiplied = acc.modMul(state.signature, state.modulus);
        // @ts-ignore
        acc = Provable.if(bits[i], ProvableBigint4096, multiplied, acc);
      }
      const left = state.hashPoseidon();
      state.acc = acc;
      return {
        publicOutput: {
          left,
          right: state.hashPoseidon(),
          vkDigest: Field(0),
        },
      };
    },
  },
};

const Exponentiation = ZkProgram({
  name: "exp",
  publicOutput: Out,
  methods: RsaExponentiation_4096_Methods,
});

console.log(
  mapObject(
    await Exponentiation.analyzeMethods(),
    (m) => m.summary()["Total rows"],
  ),
);
