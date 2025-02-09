import {
  Bytes,
  createEcdsa,
  createForeignCurve,
  Field,
  Poseidon,
  Provable,
  SelfProof,
  Struct,
  ZkProgram,
  Crypto,
} from "o1js";
import { DG1_TD3, LDS_256, SIGNED_ATTRS_256 } from "./constants";
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
import Contains, { State as ContainsState } from "./contains";

export const DIGEST_SIZE = 32; // sha256
export const OFFSET_DG1_IN_LDS = 29; // fixed for sha256
export const OFFSET_LDS_IN_SIGNEDATTRS = 42; // fixed for sha256

const LDS_DIGEST_BLOCKS_PER_ITERATION = 10; // can be less but more fails compilation
class LdsDigestState extends Sha2IterationState(256) {}
class LdsDigestIteration extends Sha2Iteration(
  256,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
) {}
class LdsDigestIterationFinal extends Sha2FinalIteration(
  256,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
) {}

const CERT_DIGEST_BLOCKS_PER_ITERATION = 10; // can be less but more fails compilation
class CertDigestState extends Sha2IterationState(256) {}
class CertDigestIteration extends Sha2Iteration(
  256,
  CERT_DIGEST_BLOCKS_PER_ITERATION,
) {}
class CertDigestIterationFinal extends Sha2FinalIteration(
  256,
  CERT_DIGEST_BLOCKS_PER_ITERATION,
) {}

class Cert extends DynamicBytes({ maxLength: 1600 }) {}
class CertChunk extends DynamicBytes({ maxLength: 800 }) {}
class PubkeySerialized extends Bytes(65) {}

class Bytes32 extends Bytes(32) {}
const Step = Field;

export class PublicKey_Secp256r1 extends createForeignCurve(
  Crypto.CurveParams.Secp256r1,
) {}
export class Signature_Secp256r1 extends createEcdsa(PublicKey_Secp256r1) {}

const STEP_LDS_DIGEST = Step(1);
const STEP_CONNECT_DG1_SIGNEDATTRS = Step(1);
const STEP_CERT_DIGEST = Step(2);
const STEP_CERT_CONTAINS_PUBKEY_STEP = Step(3);
const STEP_CHECK_SIGNEDATTRS_SIGN = Step(4);
const STEP_CHECK_CERT_SIGN = Step(5);
const STEP_END = Step(6);

export class State extends Struct({
  step: Step,
  dg1: DG1_TD3,
  ldsDigest: LdsDigestState,
  signedAttrsDigest: Bytes32,
  certDigest: CertDigestState,
  certContains: ContainsState,
  pubkeyCert: PublicKey_Secp256r1,
}) {}

export const Full_256_256_256r1 = ZkProgram({
  name: "full-256-256-256r1",
  publicInput: State,
  publicOutput: State,

  methods: {
    initial: {
      privateInputs: [],
      async method(inp: State) {
        return {
          publicOutput: new State({
            step: STEP_LDS_DIGEST,
            dg1: inp.dg1,
            ldsDigest: LdsDigestState.initial(),
            signedAttrsDigest: Bytes32.from([]),
            certDigest: CertDigestState.initial(),
            certContains: Contains.init(),
            pubkeyCert: PublicKey_Secp256r1.generator,
          }),
        };
      },
    },

    digestLdsStep: {
      privateInputs: [SelfProof, LdsDigestIteration],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        iteration: LdsDigestIteration,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_LDS_DIGEST);
        proof.verify();
        let state = proof.publicOutput;
        let ldsDigestNew = DynamicSHA2.update(state.ldsDigest, iteration);
        state.ldsDigest = ldsDigestNew;
        return { publicOutput: state };
      },
    },

    digestLdsFinalize: {
      privateInputs: [SelfProof, LdsDigestIterationFinal],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        finalIteration: LdsDigestIterationFinal,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_LDS_DIGEST);
        proof.verify();
        let state = proof.publicOutput;
        let ldsDigestNew = DynamicSHA2.finalizeOnly(
          state.ldsDigest,
          finalIteration,
        );
        state.ldsDigest = ldsDigestNew;
        state.step = STEP_CONNECT_DG1_SIGNEDATTRS;
        return { publicOutput: state };
      },
    },

    connectDg1ToSignedAttrs: {
      privateInputs: [SelfProof, LDS_256, SIGNED_ATTRS_256],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        lds: LDS_256,
        signedAttrs: SIGNED_ATTRS_256,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_CONNECT_DG1_SIGNEDATTRS);
        proof.verify();
        let state = proof.publicOutput;

        const dg1Digest = SHA2.hash(256, inp.dg1);
        lds.length.assertGreaterThan(OFFSET_DG1_IN_LDS + DIGEST_SIZE);
        assertSubarray(
          lds.array,
          dg1Digest.bytes,
          DIGEST_SIZE,
          OFFSET_DG1_IN_LDS,
          "dg1 in lds",
        );

        const ldsDigest = DynamicSHA2.validate(256, state.ldsDigest, lds);
        assertSubarray(
          signedAttrs.bytes,
          ldsDigest.bytes,
          DIGEST_SIZE,
          OFFSET_LDS_IN_SIGNEDATTRS,
          "lds in signedAttrs",
        );

        state.signedAttrsDigest = SHA2.hash(256, signedAttrs);
        state.step = STEP_CERT_DIGEST;
        return { publicOutput: state };
      },
    },

    digestCertStep: {
      privateInputs: [SelfProof, CertDigestIteration],
      async method(
        inp: State,
        proof: SelfProof<State, State>,
        iteration: CertDigestIteration,
      ) {
        // TODO: Provable.assertEqual(inp, proof.publicInput);
        inp.step.assertEquals(STEP_CERT_DIGEST);
        proof.verify();
        let state = proof.publicOutput;
        let certDigestNew = DynamicSHA2.update(state.certDigest, iteration);
        state.certDigest = certDigestNew;
        return { publicOutput: state };
      },
    },

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

        state.pubkeyCert = new PublicKey_Secp256r1(pubkeyParsed);
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
        const isValid = signature.verifySignedHash(aff, inp.pubkeyCert);
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
        const isValid = signature.verifySignedHash(aff, inp.pubkeyCert);
        isValid.assertTrue("signature validation failed for cert");

        let state = proof.publicOutput;
        state.step = STEP_END;

        return { publicOutput: state };
      },
    },
  },
});

console.log(
  mapObject(await Full_256_256_256r1.analyzeMethods(), (m) => m.summary()),
);
// await Full_256_256_256r1.compile();
