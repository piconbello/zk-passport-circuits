import { Field, Poseidon, ZkProgram, SelfProof, Bytes, Provable } from "o1js";
import { Bytes32, LDS_256 } from "./constants";
import {
  DynamicSHA2,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "@egemengol/mina-credentials/dynamic";
import { assertSubarray } from "./utils";
import { Out } from "../unrolled_meta/out";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { sha256 } from "@noble/hashes/sha256";

// TODO maybe use poseidon-safe implementation that encodes length??
export const OFFSET_DG1_IN_LDS_256 = 27;

export const LDS_DIGEST_BLOCKS_PER_ITERATION_256 = 6; // can be less but more fails compilation
export class LdsDigestState_256 extends Sha2IterationState(256) {
  hash(): Field {
    const posDigestState = Poseidon.initialState();
    Poseidon.update(posDigestState, [Field(this.len)]);
    Poseidon.update(
      posDigestState,
      this.state.array.map((u32) => u32.value),
    );
    Poseidon.update(posDigestState, [this.commitment]);
    return posDigestState[0];
  }
}
export class LdsDigestIteration_256 extends Sha2Iteration(
  256,
  LDS_DIGEST_BLOCKS_PER_ITERATION_256,
) {}
export class LdsDigestIterationFinal_256 extends Sha2FinalIteration(
  256,
  LDS_DIGEST_BLOCKS_PER_ITERATION_256,
) {}

export const LDS_256_Step_Methods: ZkProgramMethods = {
  step_dummy_256: {
    privateInputs: [Field],
    async method(carry: Field) {
      return {
        publicOutput: new Out({
          left: carry,
          right: carry,
          vkDigest: Field(0),
        }),
      };
    },
  },
  step_256: {
    privateInputs: [Field, LdsDigestState_256, LdsDigestIteration_256],
    async method(
      carry: Field,
      state: LdsDigestState_256,
      iteration: LdsDigestIteration_256,
    ) {
      let ldsDigestNew = new LdsDigestState_256(
        DynamicSHA2.update(state, iteration),
      );
      return {
        publicOutput: new Out({
          left: Poseidon.hash([carry, state.hash()]),
          right: Poseidon.hash([carry, ldsDigestNew.hash()]),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

const LDS_256_LastStep_Methods: ZkProgramMethods = {
  laststep_256: {
    privateInputs: [Field, LdsDigestState_256, LdsDigestIterationFinal_256],
    async method(
      carry: Field,
      state: LdsDigestState_256,
      iteration: LdsDigestIterationFinal_256,
    ) {
      let ldsDigestNew = new LdsDigestState_256(
        DynamicSHA2.finalizeOnly(state, iteration),
      );
      return {
        publicOutput: new Out({
          left: Poseidon.hash([carry, state.hash()]),
          right: Poseidon.hash([carry, ldsDigestNew.hash()]),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

const LDS_256_Verifier_Methods: ZkProgramMethods = {
  verifyLDS: {
    privateInputs: [Field, LdsDigestState_256, LDS_256, Bytes32],
    async method(
      carry: Field,
      state: LdsDigestState_256,
      lds: LDS_256,
      dg1Digest: Bytes32,
    ) {
      carry.assertEquals(Poseidon.hash(dg1Digest.bytes.map((v) => v.value)));

      lds.length.assertGreaterThan(OFFSET_DG1_IN_LDS_256 + 32);
      assertSubarray(
        lds.array,
        dg1Digest.bytes,
        32,
        OFFSET_DG1_IN_LDS_256,
        "dg1Digest in lds",
      );
      const ldsDigest: Bytes = DynamicSHA2.validate(256, state, lds);
      const ldsDigestFields = ldsDigest.bytes.map((u8) => u8.value);

      return {
        publicOutput: new Out({
          left: Poseidon.hash([carry, state.hash()]),
          right: Poseidon.hash(ldsDigestFields),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export function generateCalls(
  ldsArr: Uint8Array,
  dg1Arr: Uint8Array,
): PerProgram[] {
  const lds = LDS_256.fromBytes(ldsArr);
  const { iterations: steps, final: laststep } = DynamicSHA2.split(
    256,
    LDS_DIGEST_BLOCKS_PER_ITERATION_256,
    lds,
  );

  const dg1Digest = Bytes.from(sha256(dg1Arr));
  const carry = Poseidon.hash(dg1Digest.bytes.map((b) => b.value));

  const stepper: PerProgram = {
    methods: LDS_256_Step_Methods,
    calls: [],
  };
  let curState = new LdsDigestState_256(LdsDigestState_256.initial());
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    stepper.calls.push({
      methodName: "step_256",
      args: [carry, curState, step],
    });
    // This should not overwrite the state we saved into args
    curState = new LdsDigestState_256(DynamicSHA2.update(curState, step));
  }

  const lastStep: PerProgram = {
    methods: LDS_256_LastStep_Methods,
    calls: [
      {
        methodName: "laststep_256",
        args: [carry, curState, laststep],
      },
    ],
  };
  curState = new LdsDigestState_256(
    DynamicSHA2.finalizeOnly(curState, laststep),
  );

  const verify: PerProgram = {
    methods: LDS_256_Verifier_Methods,
    calls: [
      {
        methodName: "verifyLDS",
        args: [carry, curState, lds, dg1Digest],
      },
    ],
  };

  const pps = [];
  if (stepper.calls.length !== 0) {
    pps.push(stepper);
  }

  return pps.concat([lastStep, verify]);
}
