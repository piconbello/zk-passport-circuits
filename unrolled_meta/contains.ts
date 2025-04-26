import { DynamicBytes } from "@egemengol/mina-credentials";
import { Bool, Bytes, Field, Poseidon, Provable, Struct } from "o1js";
import { hashBytewisePoseidonState } from "../unrolled_leaves/utils";

export class State extends Struct({
  commitmentHaystack: [Field, Field, Field],
  commitmentNeedle: Field,
  processedNeedle: Bool,
}) {
  toObject() {
    return {
      commitmentHaystack: [
        this.commitmentHaystack[0].toBigInt(),
        this.commitmentHaystack[1].toBigInt(),
        this.commitmentHaystack[2].toBigInt(),
      ],
      commitmentNeedle: this.commitmentNeedle.toBigInt(),
      processedNeedle: this.processedNeedle.toBoolean(),
    };
  }
  toFields() {
    return [
      ...this.commitmentHaystack,
      this.commitmentNeedle,
      this.processedNeedle.toField(),
    ];
  }
}

function init(): State {
  return new State({
    commitmentNeedle: Field(0),
    commitmentHaystack: Poseidon.initialState(),
    processedNeedle: Bool.fromValue(false),
  });
}

function digest(
  state: [Field, Field, Field],
  chunk: DynamicBytes,
): [Field, Field, Field] {
  return hashBytewisePoseidonState(state, chunk);
}

function processRegularChunk(state: State, chunkHaystack: DynamicBytes): State {
  const newCommitmentHaystack = digest(
    // @ts-ignore
    state.commitmentHaystack,
    chunkHaystack,
  );
  return new State({
    commitmentNeedle: state.commitmentNeedle,
    commitmentHaystack: newCommitmentHaystack,
    processedNeedle: state.processedNeedle,
  });
}

function processOverlappingChunkDynamic(
  state: State,
  chunkHaystack: DynamicBytes,
  needle: DynamicBytes,
): State {
  if (needle.maxLength > chunkHaystack.maxLength) {
    throw new Error("needle cannot be bigger than chunk");
  }
  state.processedNeedle.assertFalse(
    "should not call this after processing needle once",
  );

  const newCommitmentHaystack = digest(
    // @ts-ignore
    state.commitmentHaystack,
    chunkHaystack,
  );

  // console.log("need", needle.toHex());
  const commitmentNeedle = needle.hash();
  // console.log("comm need", commitmentNeedle.toBigInt());

  chunkHaystack.length.assertGreaterThanOrEqual(needle.length);
  needle.forEach((byte, isPadding, i) => {
    Provable.if(
      isPadding,
      Bool.fromValue(true),
      byte.value.equals(chunkHaystack.array[i].value),
    ).assertTrue();
  });

  return new State({
    commitmentNeedle: commitmentNeedle,
    commitmentHaystack: newCommitmentHaystack,
    processedNeedle: Bool.fromValue(true),
  });
}

function processOverlappingChunk(
  state: State,
  chunkHaystack: DynamicBytes,
  needle: Bytes,
): State {
  if (needle.length > chunkHaystack.maxLength) {
    throw new Error("needle cannot be bigger than chunk");
  }
  state.processedNeedle.assertFalse(
    "should not call this after processing needle once",
  );

  const newCommitmentHaystack = digest(
    // @ts-ignore
    state.commitmentHaystack,
    chunkHaystack,
  );

  // console.log("need", needle.toHex());
  const commitmentNeedle = Poseidon.hash(needle.bytes.map((b) => b.value));
  // console.log("comm need", commitmentNeedle.toBigInt());

  chunkHaystack.length.assertGreaterThanOrEqual(needle.length);
  for (let i = 0; i < needle.length; i++) {
    needle.bytes[i].assertEquals(chunkHaystack.array[i]);
  }

  return new State({
    commitmentNeedle: commitmentNeedle,
    commitmentHaystack: newCommitmentHaystack,
    processedNeedle: Bool.fromValue(true),
  });
}

function findSubarray(haystack: Uint8Array, needle: Uint8Array) {
  if (needle.length === 0) return 0;
  if (needle.length > haystack.length) return -1;

  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return i;
  }
  return -1;
}

function chunkUint8Array(arr: Uint8Array, chunkSize: number): Uint8Array[] {
  return Array.from({ length: Math.ceil(arr.length / chunkSize) }, (_, i) =>
    arr.slice(i * chunkSize, (i + 1) * chunkSize),
  );
}

function chunkifyHaystack(
  chunkSize: number,
  haystack: Uint8Array,
  needle: Uint8Array,
) {
  const needleIndex = findSubarray(haystack, needle);

  if (needleIndex === -1) {
    throw new Error("Needle not found in haystack");
  }

  const headConcatenated = haystack.slice(0, needleIndex);
  const restConcatenated = haystack.slice(needleIndex);

  const headingChunks = chunkUint8Array(headConcatenated, chunkSize);
  const [overlappingChunk, ...tailingChunks] = chunkUint8Array(
    restConcatenated,
    chunkSize,
  );

  return {
    headingChunks,
    overlappingChunk,
    tailingChunks,
  };
}

const Contains = {
  init,
  processRegularChunk,
  processOverlappingChunkDynamic,
  processOverlappingChunk,
  chunkifyHaystack,
  digest,
};

export default Contains;
