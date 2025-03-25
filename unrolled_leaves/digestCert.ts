import { Field, Poseidon, ZkProgram, SelfProof, Bytes, Provable } from "o1js";
import {
  DynamicSHA2,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";

export const CERT_BLOCKS_PER_ITERATION_512 = 6;
export class CertDigestState_512 extends Sha2IterationState(512) {
  toFields(): Field[] {
    return [
      Field(this.len),
      ...this.state.array.map((u32) => u32.value),
      this.commitment,
    ];
  }
}
export class CertDigestIteration_512 extends Sha2Iteration(
  512,
  CERT_BLOCKS_PER_ITERATION_512,
) {}
export class CertDigestIterationFinal_512 extends Sha2FinalIteration(
  512,
  CERT_BLOCKS_PER_ITERATION_512,
) {}

export const DigestCert_512 = ZkProgram({
  name: "digest-cert-512",
  publicOutput: Out,

  methods: {
    init_512: {
      privateInputs: [Field],
      async method(certPoseidonDigest: Field) {
        const state = new CertDigestState_512(CertDigestState_512.initial());
        return {
          publicOutput: new Out({
            left: certPoseidonDigest,
            right: Poseidon.hash([certPoseidonDigest, ...state.toFields()]),
            vkDigest: Field(0),
          }),
        };
      },
    },

    step_512: {
      privateInputs: [Field, CertDigestState_512, CertDigestIteration_512],
      async method(
        certPoseidonDigest: Field,
        state: CertDigestState_512,
        iter: CertDigestIteration_512,
      ) {
        const stateNext = new CertDigestState_512(
          DynamicSHA2.update(state, iter),
        );
        return {
          publicOutput: new Out({
            left: Poseidon.hash([certPoseidonDigest, ...state.toFields()]),
            right: Poseidon.hash([certPoseidonDigest, ...stateNext.toFields()]),
            vkDigest: Field(0),
          }),
        };
      },
    },

    laststep_512: {
      privateInputs: [Field, CertDigestState_512, CertDigestIterationFinal_512],
      async method(
        certPoseidonDigest: Field,
        state: CertDigestState_512,
        iter: CertDigestIterationFinal_512,
      ) {
        const stateNext = new CertDigestState_512(
          DynamicSHA2.finalizeOnly(state, iter),
        );
        return {
          publicOutput: new Out({
            left: Poseidon.hash([certPoseidonDigest, ...state.toFields()]),
            right: Poseidon.hash([certPoseidonDigest, ...stateNext.toFields()]),
            vkDigest: Field(0),
          }),
        };
      },
    },

    validate_512: {
      privateInputs: [Field, CertDigestState_512, CertDigestIterationFinal_512],
      async method(
        certPoseidonDigest: Field,
        state: CertDigestState_512,
        iter: CertDigestIterationFinal_512,
      ) {},
    },
  },
});
