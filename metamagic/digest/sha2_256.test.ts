import { expect, test, describe } from "bun:test";

import { sha256 } from "@noble/hashes/sha256";
import { merger, program, runner, verificationKey, vkHash } from './sha2_256';
import { verificationKey as mergerVerificationKey } from "./selfmerger";
import { Field, Bytes, verify } from "o1js";
import { randomUint8Array } from "../../tests/common";
import { getDigestCommitment } from "./shautils";

describe('sha2_256', async () => {
  test.skip("proves small string", async () => {
    const salt = Field.random();
    const payload = randomUint8Array(40);
    const expectedDigest = sha256(payload);
    const expectedDigestComm = getDigestCommitment(Bytes.from(expectedDigest), salt);
    const proofArray = await runner(salt, payload);
    // const mergedProof = await merger(proofArray);
    // const isVerified = await verify(mergedProof, mergerVerificationKey);
    // expect(isVerified).toBe(true);
    // expect(mergedProof.publicOutput).toEqual(expectedDigestComm);
    // expect(mergedProof.publicInput).toEqual(vkHash);
  });

  test("proves medium string", async () => {
    const salt = Field.random();
    const payload = randomUint8Array(120);
    const expectedDigest = sha256(payload);
    const expectedDigestComm = getDigestCommitment(Bytes.from(expectedDigest), salt);
    const proofArray = await runner(salt, payload);
    // const mergedProof = await merger(proofArray);
    // const isVerified = await verify(mergedProof, mergerVerificationKey);
    // expect(isVerified).toBe(true);
    // expect(mergedProof.publicOutput).toEqual(expectedDigestComm);
    // expect(mergedProof.publicInput).toEqual(vkHash);
  })

  // test("proves very big string", async () => {
  //   const salt = Field.random();
  //   const payload = randomUint8Array(4000);
  //   const expectedDigest = sha256(payload);
  //   const expectedDigestComm = getDigestCommitment(Bytes.from(expectedDigest), salt);
  //   const proofArray = await runner(salt, payload);
  //   const mergedProof = await merger(proofArray);
  //   const isVerified = await verify(mergedProof, mergerVerificationKey);
  //   expect(isVerified).toBe(true);
  //   expect(mergedProof.publicOutput).toEqual(expectedDigestComm);
  //   expect(mergedProof.publicInput).toEqual(vkHash);
  // })
});