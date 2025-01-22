import { expect, test, describe } from "bun:test";
import { Poseidon, SelfProof, ZkProgram } from "o1js";
import { DynamicBytes } from "@egemengol/mina-credentials";

import Contains, { State } from "../circuits/contains";
import { mapObject } from "./common";

class Haystack extends DynamicBytes({ maxLength: 300 }) {}
class Chunk extends DynamicBytes({ maxLength: 65 }) {}
class Needle extends DynamicBytes({ maxLength: 60 }) {}

const ContainsZkProg = ZkProgram({
  name: "contains",
  publicInput: State,
  publicOutput: State,

  methods: {
    init: {
      privateInputs: [],
      async method(state: State) {
        return {
          publicOutput: Contains.init(),
        };
      },
    },
    processRegular: {
      privateInputs: [SelfProof<State, State>, Chunk],
      async method(state: State, proof: SelfProof<State, State>, chunk: Chunk) {
        proof.verify();
        const newState = Contains.processRegularChunk(state, chunk);
        return {
          publicOutput: newState,
        };
      },
    },
    processOverlapping: {
      privateInputs: [SelfProof<State, State>, Chunk, Needle],
      async method(
        state: State,
        proof: SelfProof<State, State>,
        chunk: Chunk,
        needle: Needle,
      ) {
        proof.verify();
        const newState = Contains.processOverlappingChunk(state, chunk, needle);
        return {
          publicOutput: newState,
        };
      },
    },
    validate: {
      privateInputs: [SelfProof<State, State>, Haystack, Needle],
      async method(
        state: State,
        proof: SelfProof<State, State>,
        haystack: Haystack,
        needle: Needle,
      ) {
        proof.verify();
        state.commitmentNeedle.assertEquals(needle.hash());

        const commitmentHaystack = Contains.digest(
          Poseidon.initialState(),
          haystack,
        );
        commitmentHaystack[0].assertEquals(state.commitmentHaystack[0]);
        commitmentHaystack[1].assertEquals(state.commitmentHaystack[1]);
        commitmentHaystack[2].assertEquals(state.commitmentHaystack[2]);

        return {
          publicOutput: state,
        };
      },
    },
  },
});

console.log(
  mapObject(await ContainsZkProg.analyzeMethods(), (m) => m.summary()),
);

describe("Contains - ZkProg", async () => {
  test("compiles", async () => {
    await ContainsZkProg.compile();
  });

  test("should prove containment with correct proofs", async () => {
    // Setup test data
    const haystack = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const needle = new Uint8Array([3, 4, 5]);
    let state = Contains.init();

    // Generate chunks
    const { headingChunks, overlappingChunk, tailingChunks } =
      Contains.chunkifyHaystack(Chunk.maxLength, haystack, needle);

    // Initialize proof chain
    let proof = await ContainsZkProg.init(state);
    state = proof.proof.publicOutput;

    // Process heading chunks
    for (const chunk of headingChunks) {
      proof = await ContainsZkProg.processRegular(
        state,
        proof.proof,
        Chunk.fromBytes(chunk),
      );
      state = proof.proof.publicOutput;
    }

    // Process overlapping chunk with needle
    proof = await ContainsZkProg.processOverlapping(
      state,
      proof.proof,
      Chunk.fromBytes(overlappingChunk),
      Needle.fromBytes(needle),
    );
    state = proof.proof.publicOutput;

    // Process tailing chunks
    for (const chunk of tailingChunks) {
      proof = await ContainsZkProg.processRegular(
        state,
        proof.proof,
        Chunk.fromBytes(chunk),
      );
      state = proof.proof.publicOutput;
    }

    // Validate final state
    const finalProof = await ContainsZkProg.validate(
      state,
      proof.proof,
      Haystack.fromBytes(haystack),
      Needle.fromBytes(needle),
    );

    // Assertions
    expect(
      finalProof.proof.publicOutput.processedNeedle.toBoolean(),
    ).toBeTrue();
    expect(
      finalProof.proof.publicOutput.commitmentNeedle
        .equals(Needle.fromBytes(needle).hash())
        .toBoolean(),
    ).toBeTrue();
  });
});
