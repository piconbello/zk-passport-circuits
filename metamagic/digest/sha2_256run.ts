import { sha256 } from "@noble/hashes/sha256";
import { merger, program, runner, verificationKey, vkHash } from './sha2_256';
import { verificationKey as mergerVerificationKey } from "./selfmerger";
import { Field, Bytes, verify } from "o1js";
import { randomUint8Array } from "../../tests/common";
import { getDigestCommitment } from "./shautils";


async function main() {
  const salt = Field.random();
  const payload = randomUint8Array(40);
  const expectedDigest = sha256(payload);
  const expectedDigestComm = getDigestCommitment(Bytes.from(expectedDigest), salt);
  const proofArray = await runner(salt, payload);
}

main();