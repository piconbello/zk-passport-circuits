import { Field, Poseidon, ZkProgram, SelfProof, Bytes } from "o1js";
import { Bytes32, LDS_256 } from "../constants";
import {
  DynamicSHA2,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "@egemengol/mina-credentials/dynamic";
import { assertSubarray } from "../utils";
import { mapObject } from "../../tests/common";
import { Out } from "./common";

// TODO maybe use poseidon-safe implementation that encodes length??
export const OFFSET_DG1_IN_LDS_256 = 28;

// export class LDS_256 extends DynamicBytes({ maxLength: 800 }) {}
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

export const DigestLDS = ZkProgram({
  name: "digest-lds",
  publicOutput: Out,

  methods: {
    init_256: {
      privateInputs: [],
      async method() {
        const initState = new LdsDigestState(LdsDigestState.initial());
        return {
          publicOutput: new Out({
            left: initState.hash(),
            right: Field(0),
            vkDigest: Field(0),
          }),
        };
      },
    },
    step_256: {
      privateInputs: [SelfProof, LdsDigestState, LdsDigestIteration],
      async method(
        proof: SelfProof<void, Out>,
        state: LdsDigestState,
        iteration: LdsDigestIteration,
      ) {
        proof.verify();
        proof.publicOutput.left.assertEquals(state.hash());
        let ldsDigestNew = new LdsDigestState(
          DynamicSHA2.update(state, iteration),
        );
        return {
          publicOutput: new Out({
            left: ldsDigestNew.hash(),
            right: Field(0),
            vkDigest: Field(0),
          }),
        };
      },
    },
    step_final_256: {
      privateInputs: [SelfProof, LdsDigestState, LdsDigestIterationFinal],
      async method(
        proof: SelfProof<void, Out>,
        state: LdsDigestState,
        iteration: LdsDigestIterationFinal,
      ) {
        proof.verify();
        proof.publicOutput.left.assertEquals(state.hash());
        let ldsDigestNew = new LdsDigestState(
          DynamicSHA2.finalizeOnly(state, iteration),
        );
        return {
          publicOutput: new Out({
            left: ldsDigestNew.hash(),
            right: Field(0),
            vkDigest: Field(0),
          }),
        };
      },
    },
    finalize_256: {
      privateInputs: [SelfProof, LdsDigestState, LDS_256, Bytes32],
      async method(
        proof: SelfProof<void, Out>,
        state: LdsDigestState,
        lds: LDS_256,
        dg1Digest: Bytes32,
      ) {
        proof.verify();
        proof.publicOutput.left.assertEquals(state.hash());
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
            left: Poseidon.hash(dg1Digest.bytes.map((uint) => uint.value)),
            right: Poseidon.hash(ldsDigest.bytes.map((u8) => u8.value)),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

// await LDS_Digest.compile();
// console.log(
//   mapObject(
//     await LDS_Digest.analyzeMethods(),
//     (m) => m.summary()["Total rows"],
//   ),
// );
