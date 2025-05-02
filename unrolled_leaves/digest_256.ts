import { Field, Poseidon, Bytes, Struct, Provable } from "o1js";
import {
  DynamicBytes,
  DynamicSHA2,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";

export const DIGEST_BLOCKS_PER_ITERATION_256 = 6; // can be less but more fails compilation
export class DigestIteration_256 extends Sha2Iteration(
  256,
  DIGEST_BLOCKS_PER_ITERATION_256,
) {}
export class DigestIterationFinal_256 extends Sha2FinalIteration(
  256,
  DIGEST_BLOCKS_PER_ITERATION_256,
) {}

export class DigestState_256 extends Struct({
  digestState: Sha2IterationState(256),
  carry: Field,
}) {
  hashPoseidon(): Field {
    return Poseidon.hash([
      Field(this.digestState.len),
      ...this.digestState.state.array.map((u32) => u32.value),
      this.digestState.commitment,
      this.carry,
    ]);
  }

  static initWithCarry(carry: Field) {
    return new DigestState_256({
      digestState: Sha2IterationState(256).initial(),
      carry,
    });
  }

  step(iter: DigestIteration_256) {
    return new DigestState_256({
      digestState: DynamicSHA2.update(this.digestState, iter),
      carry: this.carry,
    });
  }

  finalizeOnly(iter: DigestIterationFinal_256) {
    return new DigestState_256({
      digestState: DynamicSHA2.finalizeOnly(this.digestState, iter),
      carry: this.carry,
    });
  }

  validate(message: DynamicBytes): Bytes {
    return DynamicSHA2.validate(256, this.digestState, message);
  }
}

export const Digest_Step_256_Methods: ZkProgramMethods = {
  // ident: {
  //   privateInputs: [Field],
  //   async method(carry: Field) {
  //     return {
  //       publicOutput: new Out({
  //         left: carry,
  //         right: carry,
  //         vkDigest: Field(0),
  //       }),
  //     };
  //   },
  // },
  step: {
    privateInputs: [DigestState_256, DigestIteration_256],
    async method(state: DigestState_256, iteration: DigestIteration_256) {
      let stateNext = state.step(iteration);
      return {
        publicOutput: new Out({
          left: state.hashPoseidon(),
          right: stateNext.hashPoseidon(),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

const Digest_Finalize_256_Methods: ZkProgramMethods = {
  finalize: {
    privateInputs: [DigestState_256, DigestIterationFinal_256],
    async method(state: DigestState_256, iteration: DigestIterationFinal_256) {
      let stateNext = state.finalizeOnly(iteration);
      // Provable.asProver(() => {
      //   console.log("finalize carry", stateNext.carry.toBigInt());
      //   console.log(
      //     "finalize com",
      //     stateNext.digestState.commitment.toBigInt(),
      //   );
      //   console.log("finalize state", stateNext.digestState.state.toValue());
      //   console.log("finalize right", stateNext.hashPoseidon().toBigInt());
      // });
      return {
        publicOutput: new Out({
          left: state.hashPoseidon(),
          right: stateNext.hashPoseidon(),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export function generateCalls(carry: Field, message: DynamicBytes) {
  const pps = [];

  const { iterations: steps, final: laststep } = DynamicSHA2.split(
    256,
    DIGEST_BLOCKS_PER_ITERATION_256,
    message,
  );

  const stepper: PerProgram = {
    id: "Digest_Step_256",
    methods: Digest_Step_256_Methods,
    calls: [],
  };
  let curState = DigestState_256.initWithCarry(carry);
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    stepper.calls.push({
      methodName: "step",
      args: [curState, step],
    });
    // This should not overwrite the state we saved into args
    curState = curState.step(step);
  }
  if (stepper.calls.length !== 0) {
    pps.push(stepper);
  }

  if (laststep.blocks.length.toBigInt() !== 0n) {
    const finalize: PerProgram = {
      id: "Digest_Finalize_256",
      methods: Digest_Finalize_256_Methods,
      calls: [
        {
          methodName: "finalize",
          args: [curState, laststep],
        },
      ],
    };
    //TODO sometimes laststep is empty, then finalize is noop and can be skipped.
    // console.log("finalize state before", curState.hashPoseidon().toBigInt());
    curState = curState.finalizeOnly(laststep);
    // console.log("finalize state after", curState.hashPoseidon().toBigInt());
    pps.push(finalize);
  }

  // const finalize: PerProgram = {
  //   methods: Digest_Finalize_256_Methods,
  //   calls: [
  //     {
  //       methodName: "finalize",
  //       args: [curState, laststep],
  //     },
  //   ],
  // };
  // //TODO sometimes laststep is empty, then finalize is noop and can be skipped.
  // console.log("finalize state before", curState.hashPoseidon().toBigInt());
  // curState = curState.finalizeOnly(laststep);
  // console.log("finalize state after", curState.hashPoseidon().toBigInt());

  // const pps = [];
  // if (stepper.calls.length !== 0) {
  //   pps.push(stepper);
  // }
  // pps.push(finalize);

  return {
    perPrograms: pps,
    state: curState,
  };
}
