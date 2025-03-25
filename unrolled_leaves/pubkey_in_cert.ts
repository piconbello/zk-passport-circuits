import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { Out } from "../unrolled_meta/out";
import Contains from "../unrolled_meta/contains";
import { State as ContainsState } from "../unrolled_meta/contains";
import { DynamicBytes } from "@egemengol/mina-credentials";
import { Certificate } from "./constants";
// import { mapObject } from "../tests/common";

export class PubkeyInCertChunk extends DynamicBytes({ maxLength: 500 }) {}
export class PubkeyInCertNeedle extends DynamicBytes({ maxLength: 100 }) {}

export const PubkeyInCert = ZkProgram({
  name: "pubkey-in-cert",
  publicOutput: Out,

  methods: {
    processNonOverlappingChunk: {
      privateInputs: [Field, ContainsState, PubkeyInCertChunk],
      async method(
        pubkeyDigest: Field,
        leftState: ContainsState,
        chunk: PubkeyInCertChunk,
      ) {
        const rightState = Contains.processRegularChunk(leftState, chunk);
        return {
          publicOutput: new Out({
            left: Poseidon.hash([pubkeyDigest, ...leftState.toFields()]),
            right: Poseidon.hash([pubkeyDigest, ...rightState.toFields()]),
            vkDigest: Field(0),
          }),
        };
      },
    },
    processOverlappingChunk: {
      privateInputs: [
        Field,
        ContainsState,
        PubkeyInCertChunk,
        PubkeyInCertNeedle,
      ],
      async method(
        pubkeyDigest: Field,
        leftState: ContainsState,
        chunk: PubkeyInCertChunk,
        needle: PubkeyInCertNeedle,
      ) {
        const rightState = Contains.processOverlappingChunkDynamic(
          leftState,
          chunk,
          needle,
        );
        return {
          publicOutput: new Out({
            left: Poseidon.hash([pubkeyDigest, ...leftState.toFields()]),
            right: Poseidon.hash([pubkeyDigest, ...rightState.toFields()]),
            vkDigest: Field(0),
          }),
        };
      },
    },
    validateContains: {
      privateInputs: [Field, ContainsState, Certificate],
      async method(
        pubkeyDigest: Field,
        state: ContainsState,
        cert: Certificate,
      ) {
        state.processedNeedle.assertTrue();
        const certDigest = Contains.digest(Poseidon.initialState(), cert)[0];
        return {
          publicOutput: new Out({
            left: Poseidon.hash([pubkeyDigest, ...state.toFields()]),
            right: certDigest,
            vkDigest: Field(0),
          }),
        };
      },
    },
    ident: {
      privateInputs: [Field],
      async method(f: Field) {
        return {
          publicOutput: new Out({
            left: f,
            right: f,
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

// await PubkeyInCert.compile();
// console.log(mapObject(await PubkeyInCert.analyzeMethods(), (m) => m.summary()));
