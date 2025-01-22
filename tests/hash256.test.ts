import { expect, test, describe } from "bun:test";

import { sha256 } from "@noble/hashes/sha256";

import { Hash256, Hash256Proof, hashProvable256 } from "../circuits/hash256";
import { randomUint8Array } from "./common";
import { DynamicBytes, DynamicSHA2 } from "@egemengol/mina-credentials";
import type { Sha2IterationState } from "@egemengol/mina-credentials/dynamic";
import type { Bytes } from "o1js";

// console.log(mapObject(await Hash256.analyzeMethods(), (m) => m.summary()));

describe("hash 256", async () => {
  test("compiles", async () => {
    await Hash256.compile();
  });

  const payload = randomUint8Array(777);
  const payloadZk = DynamicBytes({ maxLength: 800 }).fromBytes(payload);
  const expectedDigest = sha256(payload);

  let hashProof: Hash256Proof;
  test("proves and validates hashProof for big", async () => {
    hashProof = await hashProvable256(payloadZk);
    expect(await Hash256.verify(hashProof)).toBeTrue();
  });

  test("validates the hash result for big in provable context", async () => {
    const state: Sha2IterationState = hashProof.publicOutput;
    const gotDigest: Bytes = DynamicSHA2.validate(256, state, payloadZk);
    expect(gotDigest.toBytes()).toEqual(expectedDigest);
  });

  test("Small Hash Test", async () => {
    const smallPayload = Uint8Array.from([1, 2, 3]);
    const smallPayloadZk = DynamicBytes({ maxLength: 64 }).fromBytes(
      smallPayload,
    );

    const hashProof = await hashProvable256(smallPayloadZk);

    // Validate the hash
    const digest = DynamicSHA2.validate(
      256,
      hashProof.publicOutput,
      smallPayloadZk,
    );
    expect(digest.toBytes()).toEqual(sha256(smallPayload));
  });
});
