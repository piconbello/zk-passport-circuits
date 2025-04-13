import { Field, Poseidon, ZkProgram, SelfProof, Bytes, Provable } from "o1js";
import { Bytes32, LDS_512 } from "./constants";
import {
  DynamicSHA2,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "@egemengol/mina-credentials/dynamic";
import { assertSubarray } from "./utils";
import { Out } from "../unrolled_meta/out";
import type { ZkProgramMethods } from "../unrolled_meta/interface";

// TODO maybe use poseidon-safe implementation that encodes length??
export const OFFSET_DG1_IN_LDS_512 = 28;

export const LDS_DIGEST_BLOCKS_PER_ITERATION_512 = 6;
export class LdsDigestState_512 extends Sha2IterationState(512) {
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
export class LdsDigestIteration_512 extends Sha2Iteration(
  512,
  LDS_DIGEST_BLOCKS_PER_ITERATION_512,
) {}
export class LdsDigestIterationFinal_512 extends Sha2FinalIteration(
  512,
  LDS_DIGEST_BLOCKS_PER_ITERATION_512,
) {}

const LDS_512_Step_Methods: ZkProgramMethods = {
  step_dummy_512: {
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
  step_512: {
    privateInputs: [Field, LdsDigestState_512, LdsDigestIteration_512],
    async method(
      carry: Field,
      state: LdsDigestState_512,
      iteration: LdsDigestIteration_512,
    ) {
      let ldsDigestNew = new LdsDigestState_512(
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

export const LDS_512_Step = ZkProgram({
  name: "lds-512-step",
  publicOutput: Out,
  methods: LDS_512_Step_Methods,
});

const LDS_512_LastStep_Methods: ZkProgramMethods = {
  laststep_512: {
    privateInputs: [Field, LdsDigestState_512, LdsDigestIterationFinal_512],
    async method(
      carry: Field,
      state: LdsDigestState_512,
      iteration: LdsDigestIterationFinal_512,
    ) {
      let ldsDigestNew = new LdsDigestState_512(
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

export const LDS_512_LastStep = ZkProgram({
  name: "lds-512-laststep",
  publicOutput: Out,
  methods: LDS_512_LastStep_Methods,
});

const LDS_512_Verifier_Methods: ZkProgramMethods = {
  verifyLDS: {
    privateInputs: [Field, LdsDigestState_512, LDS_512, Bytes32],
    async method(
      carry: Field,
      state: LdsDigestState_512,
      lds: LDS_512,
      dg1Digest: Bytes32,
    ) {
      carry.assertEquals(Poseidon.hash(dg1Digest.bytes.map((v) => v.value)));

      lds.length.assertGreaterThan(OFFSET_DG1_IN_LDS_512 + 32);
      assertSubarray(
        lds.array,
        dg1Digest.bytes,
        32,
        OFFSET_DG1_IN_LDS_512,
        "dg1Digest in lds",
      );
      const ldsDigest: Bytes = DynamicSHA2.validate(512, state, lds);

      return {
        publicOutput: new Out({
          left: Poseidon.hash([carry, state.hash()]),
          right: Poseidon.hash(ldsDigest.bytes.map((u8) => u8.value)),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export const LDS_512_Verifier = ZkProgram({
  name: "lds-512-verifier",
  publicOutput: Out,
  methods: LDS_512_Verifier_Methods,
});
