import { expect, test, describe } from "bun:test";

import { sha256 } from "@noble/hashes/sha256";
import { program, runner, verificationKey } from './sha2_256';
import { Field, Bytes, verify } from "o1js";
import { randomUint8Array } from "../../tests/common";
import { getDigestCommitment } from "./shautils";

describe('sha2_256', async () => {
  test("proves small string", async () => {
    const salt = Field.random();
    const payload = randomUint8Array(40);
    const expectedDigest = sha256(payload);
    const expectedDigestComm = getDigestCommitment(Bytes.from(expectedDigest), salt);
    const proof = await runner(salt, payload);
    const isVerified = await verify(proof, verificationKey);
    expect(isVerified).toBe(true);
    expect(proof.publicOutput).toEqual(expectedDigestComm);
  });

  test("proves big string", async () => {
    const salt = Field.random();
    const payload = randomUint8Array(800);
    const expectedDigest = sha256(payload);
    const expectedDigestComm = getDigestCommitment(Bytes.from(expectedDigest), salt);
    const proof = await runner(salt, payload);
    const isVerified = await verify(proof, verificationKey);
    expect(isVerified).toBe(true);
    expect(proof.publicOutput).toEqual(expectedDigestComm);
  })

  test("proves very big string", async () => {
    const salt = Field.random();
    const payload = randomUint8Array(4000);
    const expectedDigest = sha256(payload);
    const expectedDigestComm = getDigestCommitment(Bytes.from(expectedDigest), salt);
    const proof = await runner(salt, payload);
    const isVerified = await verify(proof, verificationKey);
    expect(isVerified).toBe(true);
    expect(proof.publicOutput).toEqual(expectedDigestComm);
  })
});