import { Bool, Field, Provable, Struct, UInt8, ZkProgram, UInt32 } from "o1js";
import { Bigint4096, EXP_BIT_COUNT } from "./core";

const ZERO = Bigint4096.from(0n);
const ONE = Bigint4096.from(1n);
// @ts-ignore
if (EXP_BIT_COUNT !== 20) {
  throw new Error("I hardcoded 10+10 two steps for rsa");
}

export class Rsa4096State extends Struct({
  acc: Bigint4096,
  modulus: Bigint4096,
  signature: Bigint4096,
  exponentBits: Provable.Array(Bool, EXP_BIT_COUNT),
}) {}

export const Rsa4096 = ZkProgram({
  name: "rsa4096",
  publicInput: Rsa4096State,
  publicOutput: Rsa4096State,

  methods: {
    first: {
      privateInputs: [],
      async method(state: Rsa4096State) {
        // Checks for a clean start
        state.acc.equals(ZERO).assertTrue();
        let acc = Provable.if(state.exponentBits[0], state.signature, ONE);
        for (let i = 1; i < 10; i++) {
          acc = state.modulus.modSquare(acc);
          acc = state.modulus.modMul(
            acc,
            Provable.if(state.exponentBits[i], state.signature, ONE),
          );
        }
        state.acc = acc;
        return { publicOutput: state };
      },
    },

    second: {
      privateInputs: [],
      async method(state: Rsa4096State) {
        // Checks for a worked accumulator from first step
        state.acc.equals(ZERO).assertFalse();
        let acc = state.acc;

        for (let i = 10; i < EXP_BIT_COUNT; i++) {
          acc = state.modulus.modSquare(acc);
          acc = state.modulus.modMul(
            acc,
            Provable.if(state.exponentBits[i], state.signature, ONE),
          );
        }

        state.acc = acc;
        return { publicOutput: state };
      },
    },
  },
});

export class Rsa4096Proof extends ZkProgram.Proof(Rsa4096) {}

// console.log(mapObject(await Rsa4096.analyzeMethods(), (m) => m.summary()));

export async function verifyRsaProvable4096(
  modulus: bigint,
  exponent: bigint,
  signature: bigint,
  status_callback: (status: string) => void = () => {
    /* noop as default */
  },
) {
  const modulusField = Bigint4096.from(modulus);
  const signatureField = Bigint4096.from(signature);
  const exponentBits = Field.from(exponent).toBits(EXP_BIT_COUNT).reverse();

  const initialState = new Rsa4096State({
    acc: ZERO,
    modulus: modulusField,
    signature: signatureField,
    exponentBits: exponentBits,
  });

  const firstStepProof = (await Rsa4096.first(initialState)).proof;

  return (await Rsa4096.second(firstStepProof.publicOutput)).proof;
}
