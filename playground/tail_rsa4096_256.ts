import { Bool, Bytes, Field, Provable, Struct, UInt32, ZkProgram } from "o1js";
import {
  DynamicSHA2,
  Sha2IterationState,
  Sha2Iteration,
  Sha2FinalIteration,
  DynamicBytes,
} from "@egemengol/mina-credentials/dynamic";
import { mapObject } from "../tests/common";
import { SIGNED_ATTRS } from "../circuits/constants";

const BLOCKS_PER_ITERATION = 10; // can be less but more fails compilation
class DigestState extends Sha2IterationState(256) {}
class DigestIteration extends Sha2Iteration(256, BLOCKS_PER_ITERATION) {}
class DigestIterationFinal extends Sha2FinalIteration(
  256,
  BLOCKS_PER_ITERATION,
) {}

/**
 * Hash signedAttrs
 * Check if its
 */
export class TailState extends Struct({
  signedAttrs: SIGNED_ATTRS,
  tbsDigestState: DigestState,
  // tbsDigestFinalized: Bool,
  // signedAttrsDigestInTbsState: Field, // TODO
  // signedAttrsDigestInTBSFinalized: Bool,
  // local256r1PubkeyParsingState: Field, // TODO
  // local256r1PubkeyParsingFinalized: Bool,
  // localSignatureVerificationState: Field, // TODO
  // localSigntarueVerificationFinalized: Bool,
  // certSignatureVerificationState: Field, // TODO
  // certSignatureVerificationFinalized: Bool,
}) {}

function empty(signedAttrs: SIGNED_ATTRS): TailState {
  return new TailState({
    signedAttrs,
    tbsDigestState: DigestState.initial(),
    // tbsDigestFinalized: Bool.fromValue(false),
  });
}

function init(inp: TailState): TailState {
  inp.tbsDigestState = DigestState.initial();
  // inp.tbsDigestFinalized = Bool.fromValue(false);
  return inp;
}

function digestTbsStep(inp: TailState, iteration: DigestIteration): TailState {
  const newState = DynamicSHA2.update(inp.tbsDigestState, iteration);
  inp.tbsDigestState = newState;
  return inp;
}

function digestTbsFinalizeOnly(inp: TailState, iteration: DigestIterationFinal): TailState {
  const newState = DynamicSHA2.finalizeOnly(inp.tbsDigestState, iteration);
  inp.tbsDigestState = newState;
  return inp;
}

function



// export class Inner1 extends Struct({
//   f: Field,
// }) {}

// export class Inner2 extends Struct({
//   g: Field,
//   h: Field,
// }) {}

// export class Outer extends Struct({
//   i1: Inner1,
//   i2: Inner2,
// }) {}

// export const Zk = ZkProgram({
//   name: "zk",
//   publicInput: Outer,

//   methods: {
//     validateTail: {
//       privateInputs: [],

//       async method(inp: Outer) {
//         inp.i1.f.assertEquals(inp.i2.g);
//       },
//     },
//   },
// });

// async function main() {
//   const prog = await Zk.compile();
//   console.log(mapObject(await Zk.analyzeMethods(), (m) => m.summary()));
//   console.log("here");
// }

// await main();
