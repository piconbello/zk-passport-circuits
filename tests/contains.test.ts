import { expect, test, describe } from "bun:test";
import { DynamicBytes } from "@egemengol/mina-credentials";
import { Bool, Field, Poseidon } from "o1js";
import Contains from "../circuits/contains";

class Haystack extends DynamicBytes({ maxLength: 2300 }) {}
class Chunk extends DynamicBytes({ maxLength: 65 }) {}
class Needle extends DynamicBytes({ maxLength: 60 }) {}

describe("Contains Circuit - Core Functionality", () => {
  test("digest computation should be consistent when processing in chunks", () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

    // Process in two chunks
    const chunk1 = Needle.fromBytes(data.slice(0, 4));
    const chunk2 = Needle.fromBytes(data.slice(4));
    let state = Poseidon.initialState();
    state = Contains.digest(state, chunk1);
    state = Contains.digest(state, chunk2);

    // Process as single chunk
    const wholeChunk = Needle.fromBytes(data);
    const wholeState = Contains.digest(Poseidon.initialState(), wholeChunk);

    expect(state[0].equals(wholeState[0]).toBoolean()).toBeTrue();
    expect(state[1].equals(wholeState[1]).toBoolean()).toBeTrue();
    expect(state[2].equals(wholeState[2]).toBoolean()).toBeTrue();
  });

  test("initial state should have expected default values", () => {
    const state = Contains.init();
    expect(state.processedNeedle.toBoolean()).toBeFalse();
    expect(state.processedHaystack.toBoolean()).toBeFalse();
    expect(state.commitmentNeedle.equals(Field(0)).toBoolean()).toBeTrue();
  });
});

describe("Contains Circuit - Pattern Matching", () => {
  describe("Basic Pattern Locations", () => {
    test("should find needle at start of haystack", () => {
      const haystack = new Uint8Array([1, 2, 3, 4, 5]);
      const needle = new Uint8Array([1, 2]);
      let state = Contains.init();

      const { headingChunks, overlappingChunk } = Contains.chunkifyHaystack(
        Chunk.maxLength,
        haystack,
        needle,
      );

      expect(headingChunks).toHaveLength(0);

      state = Contains.processOverlappingChunkDynamic(
        state,
        Chunk.fromBytes(overlappingChunk),
        Needle.fromBytes(needle),
      );

      expect(state.processedNeedle.toBoolean()).toBeTrue();
    });

    test("should find needle at end of haystack", () => {
      const haystack = new Uint8Array([1, 2, 3, 4, 5]);
      const needle = new Uint8Array([4, 5]);
      let state = Contains.init();

      const { headingChunks, overlappingChunk, tailingChunks } =
        Contains.chunkifyHaystack(Chunk.maxLength, haystack, needle);

      headingChunks.forEach((chunk) => {
        state = Contains.processRegularChunk(state, Chunk.fromBytes(chunk));
      });

      state = Contains.processOverlappingChunkDynamic(
        state,
        Chunk.fromBytes(overlappingChunk),
        Needle.fromBytes(needle),
        Bool.fromValue(true),
      );

      expect(tailingChunks).toHaveLength(0);
      expect(state.processedNeedle.toBoolean()).toBeTrue();
      expect(state.processedHaystack.toBoolean()).toBeTrue();
    });

    test("should find needle in middle of haystack", () => {
      const haystack = new Uint8Array([1, 2, 3, 4, 5, 6]);
      const needle = new Uint8Array([3, 4]);
      let state = Contains.init();

      const { headingChunks, overlappingChunk, tailingChunks } =
        Contains.chunkifyHaystack(Chunk.maxLength, haystack, needle);

      headingChunks.forEach((chunk) => {
        state = Contains.processRegularChunk(state, Chunk.fromBytes(chunk));
      });

      state = Contains.processOverlappingChunkDynamic(
        state,
        Chunk.fromBytes(overlappingChunk),
        Needle.fromBytes(needle),
      );

      expect(state.processedNeedle.toBoolean()).toBeTrue();
    });
  });

  describe("Edge Cases", () => {
    test("should handle single-byte needle", () => {
      const haystack = new Uint8Array([1, 2, 3, 4, 5]);
      const needle = new Uint8Array([3]);
      let state = Contains.init();

      const { headingChunks, overlappingChunk } = Contains.chunkifyHaystack(
        Chunk.maxLength,
        haystack,
        needle,
      );

      headingChunks.forEach((chunk) => {
        state = Contains.processRegularChunk(state, Chunk.fromBytes(chunk));
      });

      state = Contains.processOverlappingChunkDynamic(
        state,
        Chunk.fromBytes(overlappingChunk),
        Needle.fromBytes(needle),
      );

      expect(state.processedNeedle.toBoolean()).toBeTrue();
    });

    test("should handle needle spanning multiple chunks", () => {
      const haystack = new Uint8Array(Array.from({ length: 100 }, (_, i) => i));
      const needle = new Uint8Array([63, 64, 65]);
      let state = Contains.init();

      const { headingChunks, overlappingChunk } = Contains.chunkifyHaystack(
        Chunk.maxLength,
        haystack,
        needle,
      );

      headingChunks.forEach((chunk) => {
        state = Contains.processRegularChunk(state, Chunk.fromBytes(chunk));
      });

      state = Contains.processOverlappingChunkDynamic(
        state,
        Chunk.fromBytes(overlappingChunk),
        Needle.fromBytes(needle),
      );

      expect(state.processedNeedle.toBoolean()).toBeTrue();
    });
  });

  describe("Error Cases", () => {
    test("should throw when needle not found", () => {
      const haystack = new Uint8Array([1, 2, 3]);
      const needle = new Uint8Array([4, 5]);

      expect(() => {
        Contains.chunkifyHaystack(Chunk.maxLength, haystack, needle);
      }).toThrow("Needle not found in haystack");
    });

    test("should throw with empty haystack", () => {
      const haystack = new Uint8Array([]);
      const needle = new Uint8Array([1]);

      expect(() => {
        Contains.chunkifyHaystack(Chunk.maxLength, haystack, needle);
      }).toThrow();
    });

    test("should throw when needle is larger than chunk size", () => {
      const haystack = new Uint8Array(Array(100).fill(1));
      const needle = new Uint8Array(Array(66).fill(1)); // Larger than Chunk.maxLength

      expect(() => {
        const { overlappingChunk } = Contains.chunkifyHaystack(
          Chunk.maxLength,
          haystack,
          needle,
        );
        Contains.processOverlappingChunkDynamic(
          Contains.init(),
          Chunk.fromBytes(overlappingChunk),
          Needle.fromBytes(needle),
        );
      }).toThrow();
    });
  });
});
