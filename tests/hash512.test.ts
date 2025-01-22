import { expect, test, describe } from "bun:test";

import { sha512 } from "@noble/hashes/sha512";

import { Hash512, Hash512Proof, hashProvable512 } from "../circuits/hash512";
import { randomUint8Array } from "./common";
import { DynamicBytes, DynamicSHA2 } from "@egemengol/mina-credentials";
import type { Sha2IterationState } from "@egemengol/mina-credentials/dynamic";
import type { Bytes } from "o1js";

// console.log(mapObject(await Hash512.analyzeMethods(), (m) => m.summary()));

describe("hash 512", async () => {
  test("compiles", async () => {
    await Hash512.compile();
  });

  const payload = randomUint8Array(777);
  const payloadZk = DynamicBytes({ maxLength: 800 }).fromBytes(payload);
  const expectedDigest = sha512(payload);

  let hashProof: Hash512Proof;
  test("proves and validates hashProof", async () => {
    hashProof = await hashProvable512(payloadZk);
    expect(await Hash512.verify(hashProof)).toBeTrue();
  });

  test("validates the hash result in provable context", async () => {
    const state: Sha2IterationState = hashProof.publicOutput;
    const gotDigest: Bytes = DynamicSHA2.validate(512, state, payloadZk);
    expect(gotDigest.toBytes()).toEqual(expectedDigest);
  });
});
