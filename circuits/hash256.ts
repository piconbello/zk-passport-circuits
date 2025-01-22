import { Field, SelfProof, ZkProgram } from "o1js";
import {
  DynamicSHA2,
  Sha2IterationState,
  Sha2Iteration,
  Sha2FinalIteration,
  DynamicBytes,
} from "@egemengol/mina-credentials/dynamic";

const BLOCKS_PER_ITERATION = 10; // can be less but more fails compilation
class State extends Sha2IterationState(256) {}
class Iteration extends Sha2Iteration(256, BLOCKS_PER_ITERATION) {}
class FinalIteration extends Sha2FinalIteration(256, BLOCKS_PER_ITERATION) {}

export const Hash256 = ZkProgram({
  name: "hash256",
  publicOutput: State,

  methods: {
    initial: {
      privateInputs: [],
      async method() {
        let state = State.initial();
        // let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput: state };
      },
    },

    step: {
      privateInputs: [SelfProof, Iteration],
      async method(proof: SelfProof<undefined, State>, iteration: Iteration) {
        proof.verify();
        let state = proof.publicOutput;
        let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },

    finalize: {
      privateInputs: [SelfProof, FinalIteration],
      async method(
        proof: SelfProof<undefined, State>,
        finalIteration: FinalIteration,
      ) {
        proof.verify();
        let state = proof.publicOutput;
        let stateOut = DynamicSHA2.finalizeOnly(state, finalIteration);
        return { publicOutput: stateOut };
      },
    },
  },
});

export class Hash256Proof extends ZkProgram.Proof(Hash256) {}

export async function hashProvable256(
  payload: DynamicBytes,
  status_callback: (status: string) => void = () => {
    /* noop as default */
  },
) {
  if (payload.length.equals(Field(0)).toBoolean()) {
    throw Error("Empty payload is not permitted");
  }
  const { iterations, final } = DynamicSHA2.split(
    256,
    BLOCKS_PER_ITERATION,
    payload,
  );

  let curProof = (await Hash256.initial()).proof;
  status_callback("proved initial");

  for (const [index, iter] of iterations.entries()) {
    const proof = await Hash256.step(curProof, iter);
    curProof = proof.proof;
    status_callback(`proved step ${index + 1}`);
  }

  const proofFinal: Hash256Proof = (await Hash256.finalize(curProof, final))
    .proof;
  status_callback("proved final");

  return proofFinal;
}
