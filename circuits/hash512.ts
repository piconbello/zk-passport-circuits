import { Field, SelfProof, ZkProgram } from "o1js";
import {
  DynamicSHA2,
  Sha2IterationState,
  Sha2Iteration,
  Sha2FinalIteration,
  DynamicBytes,
} from "@egemengol/mina-credentials/dynamic";

const BLOCKS_PER_ITERATION = 5;
class State extends Sha2IterationState(512) {}
class Iteration extends Sha2Iteration(512, BLOCKS_PER_ITERATION) {}
class FinalIteration extends Sha2FinalIteration(512, BLOCKS_PER_ITERATION) {}

export const Hash512 = ZkProgram({
  name: "hash512",
  publicOutput: State,

  methods: {
    initial: {
      privateInputs: [Iteration],
      async method(iteration: Iteration) {
        let state = State.initial();
        let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },

    recursive: {
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

export class Hash512Proof extends ZkProgram.Proof(Hash512) {}

export async function hashProvable512(
  payload: DynamicBytes,
  status_callback: (status: string) => void = () => {
    /* noop as default */
  },
) {
  if (payload.length.equals(Field(0)).toBoolean()) {
    throw Error("Empty payload is not permitted");
  }
  const { iterations, final } = DynamicSHA2.split(
    512,
    BLOCKS_PER_ITERATION,
    payload,
  );

  const [first, ...rest] = iterations;

  let updateProof = (await Hash512.initial(first)).proof;
  status_callback("proved initial");

  for (const [index, iter] of rest.entries()) {
    const proof = await Hash512.recursive(updateProof, iter);
    updateProof = proof.proof;
    status_callback(`proved step ${index + 1}`);
  }

  const proofFinal: Hash512Proof = (await Hash512.finalize(updateProof, final))
    .proof;
  status_callback("proved final");

  return proofFinal;
}
