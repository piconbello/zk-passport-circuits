import { Field, Poseidon, ZkProgram, SelfProof, Bytes, Provable } from "o1js";
import { Bytes32, LDS_256 } from "./constants";
import {
  DynamicSHA2,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "@egemengol/mina-credentials/dynamic";
import { assertSubarray } from "./utils";
import { Out } from "./common";

// TODO maybe use poseidon-safe implementation that encodes length??
export const OFFSET_DG1_IN_LDS_256 = 28;

export const LDS_DIGEST_BLOCKS_PER_ITERATION = 6; // can be less but more fails compilation
export class LdsDigestState extends Sha2IterationState(256) {
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
export class LdsDigestIteration extends Sha2Iteration(
  256,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
) {}
export class LdsDigestIterationFinal extends Sha2FinalIteration(
  256,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
) {}

export const DigestLDS_step = ZkProgram({
  name: "digest-lds-step",
  publicOutput: Out,

  methods: {
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
      privateInputs: [Field, LdsDigestState, LdsDigestIteration],
      async method(
        carry: Field,
        state: LdsDigestState,
        iteration: LdsDigestIteration,
      ) {
        let ldsDigestNew = new LdsDigestState(
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
  },
});

export const DigestLDS_laststep = ZkProgram({
  name: "digest-lds-laststep",
  publicOutput: Out,

  methods: {
    laststep_256: {
      privateInputs: [Field, LdsDigestState, LdsDigestIterationFinal],
      async method(
        carry: Field,
        state: LdsDigestState,
        iteration: LdsDigestIterationFinal,
      ) {
        let ldsDigestNew = new LdsDigestState(
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
  },
});

export const DigestLDS_verifier = ZkProgram({
  name: "digest-lds-verifier",
  publicOutput: Out,

  methods: {
    verifyLDS: {
      privateInputs: [Field, LdsDigestState, LDS_256, Bytes32],
      async method(
        carry: Field,
        state: LdsDigestState,
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

        return {
          publicOutput: new Out({
            left: Poseidon.hash([carry, state.hash()]),
            right: Poseidon.hash(ldsDigest.bytes.map((u8) => u8.value)),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});
