import {
  Bytes,
  createEcdsa,
  createForeignCurve,
  Field,
  Poseidon,
  SelfProof,
  Struct,
  ZkProgram,
  Crypto,
  Provable,
} from "o1js";
import { DG1_TD3, LDS_256, SIGNED_ATTRS_256 } from "./constants.ts";
import {
  DynamicBytes,
  DynamicSHA2,
  SHA2,
  Sha2FinalIteration,
  Sha2Iteration,
  Sha2IterationState,
} from "@egemengol/mina-credentials/dynamic";
import { mapObject } from "../tests/common";
import {
  assertSubarray,
  bytes32ToScalar,
  parseECpubkey256Uncompressed,
} from "./utils";
import Contains, { State as ContainsState } from "./contains.ts";

export const DIGEST_SIZE = 32; // sha256
export const OFFSET_DG1_IN_LDS = 29; // fixed for sha256
export const OFFSET_LDS_IN_SIGNEDATTRS = 42; // fixed for sha256

export const LDS_DIGEST_BLOCKS_PER_ITERATION = 7; // can be less but more fails compilation
export class LdsDigestState extends Sha2IterationState(256) {}
export class LdsDigestIteration extends Sha2Iteration(
  256,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
) {}
export class LdsDigestIterationFinal extends Sha2FinalIteration(
  256,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
) {}

export const CERT_DIGEST_BLOCKS_PER_ITERATION = 7; // can be less but more fails compilation
export class CertDigestState extends Sha2IterationState(256) {}
export class CertDigestIteration extends Sha2Iteration(
  256,
  CERT_DIGEST_BLOCKS_PER_ITERATION,
) {}
export class CertDigestIterationFinal extends Sha2FinalIteration(
  256,
  CERT_DIGEST_BLOCKS_PER_ITERATION,
) {}

export class Cert extends DynamicBytes({ maxLength: 1500 }) {}
export class CertChunk extends DynamicBytes({ maxLength: 800 }) {}
export class PubkeySerialized extends Bytes(65) {}

export class Bytes32 extends Bytes(32) {}
export const Step = Field;

export class PublicKey_Secp256r1 extends createForeignCurve(
  Crypto.CurveParams.Secp256r1,
) {}
export class Signature_Secp256r1 extends createEcdsa(PublicKey_Secp256r1) {}

export const STEP_LDS_DIGEST = Step(1);
export const STEP_CONNECT_DG1_SIGNEDATTRS = Step(1);
export const STEP_CERT_DIGEST = Step(2);
export const STEP_CERT_CONTAINS_PUBKEY_STEP = Step(3);
export const STEP_CHECK_SIGNEDATTRS_SIGN = Step(4);
export const STEP_CHECK_CERT_SIGN = Step(5);
export const STEP_END = Step(6);

export class State extends Struct({
  step: Step,
  dg1: DG1_TD3,
  ldsDigest: LdsDigestState,
  signedAttrsDigest: Bytes32,
  certDigest: CertDigestState,
  certContains: ContainsState,
  pubkeyCertX: Provable.Array(Field, 3),
  pubkeyCertY: Provable.Array(Field, 3),
}) {}

const VALID_POINT: { x: [Field, Field, Field]; y: [Field, Field, Field] } =
  (() => {
    const x = PublicKey_Secp256r1.generator.x.value;
    const y = PublicKey_Secp256r1.generator.y.value;

    return { x: [x[0], x[1], x[2]], y: [y[0], y[1], y[2]] };
  })();

export const Full_256_256_256r1 = ZkProgram({
  name: "full-256-256-256r1",
  publicInput: State,
  publicOutput: State,

  methods: {
    // initial: {
    //   privateInputs: [],
    //   async method(inp: State) {
    //     return {
    //       publicOutput: new State({
    //         step: STEP_LDS_DIGEST,
    //         dg1: inp.dg1,
    //         ldsDigest: LdsDigestState.initial(),
    //         signedAttrsDigest: Bytes32.from([]),
    //         certDigest: CertDigestState.initial(),
    //         certContains: Contains.init(),
    //         pubkeyCertX: VALID_POINT.x,
    //         pubkeyCertY: VALID_POINT.y,
    //       }),
    //     };
    //   },
    // },
    // digestLdsStep: {
    //   privateInputs: [SelfProof, LdsDigestIteration],
    //   async method(
    //     inp: State,
    //     proof: SelfProof<State, State>,
    //     iteration: LdsDigestIteration,
    //   ) {
    //     // TODO: Provable.assertEqual(inp, proof.publicInput);
    //     inp.step.assertEquals(STEP_LDS_DIGEST);
    //     proof.verify();
    //     let state = proof.publicOutput;
    //     let ldsDigestNew = DynamicSHA2.update(state.ldsDigest, iteration);
    //     state.ldsDigest = ldsDigestNew;
    //     return { publicOutput: state };
    //   },
    // },
    // digestLdsFinalize: {
    //   privateInputs: [SelfProof, LdsDigestIterationFinal],
    //   async method(
    //     inp: State,
    //     proof: SelfProof<State, State>,
    //     finalIteration: LdsDigestIterationFinal,
    //   ) {
    //     // TODO: Provable.assertEqual(inp, proof.publicInput);
    //     inp.step.assertEquals(STEP_LDS_DIGEST);
    //     proof.verify();
    //     let state = proof.publicOutput;
    //     let ldsDigestNew = DynamicSHA2.finalizeOnly(
    //       state.ldsDigest,
    //       finalIteration,
    //     );
    //     state.ldsDigest = ldsDigestNew;
    //     state.step = STEP_CONNECT_DG1_SIGNEDATTRS;
    //     return { publicOutput: state };
    //   },
    // },
    // connectDg1ToSignedAttrs: {
    //   privateInputs: [SelfProof, LDS_256, SIGNED_ATTRS_256],
    //   async method(
    //     inp: State,
    //     proof: SelfProof<State, State>,
    //     lds: LDS_256,
    //     signedAttrs: SIGNED_ATTRS_256,
    //   ) {
    //     // TODO: Provable.assertEqual(inp, proof.publicInput);
    //     inp.step.assertEquals(STEP_CONNECT_DG1_SIGNEDATTRS);
    //     proof.verify();
    //     let state = proof.publicOutput;
    //     const dg1Digest = SHA2.hash(256, inp.dg1);
    //     lds.length.assertGreaterThan(OFFSET_DG1_IN_LDS + DIGEST_SIZE);
    //     assertSubarray(
    //       lds.array,
    //       dg1Digest.bytes,
    //       DIGEST_SIZE,
    //       OFFSET_DG1_IN_LDS,
    //       "dg1 in lds",
    //     );
    //     const ldsDigest = DynamicSHA2.validate(256, state.ldsDigest, lds);
    //     assertSubarray(
    //       signedAttrs.bytes,
    //       ldsDigest.bytes,
    //       DIGEST_SIZE,
    //       OFFSET_LDS_IN_SIGNEDATTRS,
    //       "lds in signedAttrs",
    //     );
    //     state.signedAttrsDigest = SHA2.hash(256, signedAttrs);
    //     state.step = STEP_CERT_DIGEST;
    //     return { publicOutput: state };
    //   },
    // },
    // digestCertStep: {
    //   privateInputs: [SelfProof, CertDigestIteration],
    //   async method(
    //     inp: State,
    //     proof: SelfProof<State, State>,
    //     iteration: CertDigestIteration,
    //   ) {
    //     // TODO: Provable.assertEqual(inp, proof.publicInput);
    //     inp.step.assertEquals(STEP_CERT_DIGEST);
    //     proof.verify();
    //     let state = proof.publicOutput;
    //     let certDigestNew = DynamicSHA2.update(state.certDigest, iteration);
    //     state.certDigest = certDigestNew;
    //     return { publicOutput: state };
    //   },
    // },
    digestCertFinalize: {
      privateInputs: [SelfProof, CertDigestIterationFinal],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        finalIteration: LdsDigestIterationFinal,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_CERT_DIGEST);
        proof.verify();
        let state = proof.publicOutput;
        let ldsDigestNew = DynamicSHA2.finalizeOnly(
          state.ldsDigest,
          finalIteration,
        );
        state.ldsDigest = ldsDigestNew;
        state.step = STEP_CERT_CONTAINS_PUBKEY_STEP;
        return { publicOutput: state };
      },
    },
    certContainsPubkeyStepRegular: {
      privateInputs: [SelfProof, CertChunk],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        chunk: CertChunk,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_CERT_CONTAINS_PUBKEY_STEP);
        proof.verify();
        let state = proof.publicOutput;
        const certContainsNew = Contains.processRegularChunk(
          state.certContains,
          chunk,
        );
        state.certContains = certContainsNew;
        return { publicOutput: state };
      },
    },
    certContainsPubkeyStepOverlapping: {
      privateInputs: [SelfProof, CertChunk, PubkeySerialized],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        chunk: CertChunk,
        pubkey: PubkeySerialized,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_CERT_CONTAINS_PUBKEY_STEP);
        proof.verify();
        let state = proof.publicOutput;
        const certContainsNew = Contains.processOverlappingChunk(
          state.certContains,
          chunk,
          pubkey,
        );
        state.certContains = certContainsNew;
        return { publicOutput: state };
      },
    },
    validatePubkeyInCertAndCertDigest: {
      privateInputs: [SelfProof, Cert, PubkeySerialized],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        cert: Cert,
        pubkey: PubkeySerialized,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_CERT_CONTAINS_PUBKEY_STEP);
        proof.verify();
        let state = proof.publicOutput;
        DynamicSHA2.validate(256, state.certDigest, cert);
        const commitmentHaystack = Contains.digest(
          Poseidon.initialState(),
          cert,
        );
        commitmentHaystack[0].assertEquals(
          state.certContains.commitmentHaystack[0],
        );
        commitmentHaystack[1].assertEquals(
          state.certContains.commitmentHaystack[1],
        );
        commitmentHaystack[2].assertEquals(
          state.certContains.commitmentHaystack[2],
        );
        const commitmentNeedle = Poseidon.hash(
          pubkey.bytes.map((b) => b.value),
        );
        state.certContains.commitmentNeedle.assertEquals(commitmentNeedle);
        const pubkeyParsed = parseECpubkey256Uncompressed(pubkey);
        state.pubkeyCertX = pubkeyParsed.x;
        state.pubkeyCertY = pubkeyParsed.y;
        state.step = STEP_CHECK_SIGNEDATTRS_SIGN;
        return { publicOutput: state };
      },
    },
    validateSignedAttrsSignature: {
      privateInputs: [SelfProof, Signature_Secp256r1],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        signature: Signature_Secp256r1,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_CHECK_SIGNEDATTRS_SIGN);
        proof.verify();
        const aff = new PublicKey_Secp256r1.Scalar.AlmostReduced(
          bytes32ToScalar(inp.signedAttrsDigest.bytes),
        );
        const pubkeyCert = new PublicKey_Secp256r1({
          // @ts-ignore
          x: inp.pubkeyCertX,
          // @ts-ignore
          y: inp.pubkeyCertY,
        });
        const isValid = signature.verifySignedHash(aff, pubkeyCert);
        isValid.assertTrue("signature validation failed for signedAttrs");
        let state = proof.publicOutput;
        state.step = STEP_CHECK_CERT_SIGN;
        return { publicOutput: state };
      },
    },
    validateCertSignature: {
      privateInputs: [SelfProof, Signature_Secp256r1],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        signature: Signature_Secp256r1,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_CHECK_CERT_SIGN);
        proof.verify();
        const certDigestBytes = Bytes32.from(
          inp.certDigest.state.array.flatMap((x) => x.toBytesBE()),
        );
        const aff = new PublicKey_Secp256r1.Scalar.AlmostReduced(
          bytes32ToScalar(certDigestBytes.bytes),
        );
        const pubkeyCert = new PublicKey_Secp256r1({
          // @ts-ignore
          x: inp.pubkeyCertX,
          // @ts-ignore
          y: inp.pubkeyCertY,
        });
        const isValid = signature.verifySignedHash(aff, pubkeyCert);
        isValid.assertTrue("signature validation failed for cert");
        let state = proof.publicOutput;
        state.step = STEP_END;
        return { publicOutput: state };
      },
    },
  },
});

console.log(
  mapObject(
    await Full_256_256_256r1.analyzeMethods(),
    (m) => m.summary()["Total rows"],
  ),
);
// await Full_256_256_256r1.compile();
