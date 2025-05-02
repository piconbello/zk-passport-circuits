import { Field, Poseidon, Struct, ZkProgram } from "o1js";
import { Field3 } from "./constants";
import { StaticArray } from "@egemengol/mina-credentials";
import { MerkleWitnessStep } from "../unrolled_meta/merkle";
import { Out } from "../unrolled_meta/out";
import { RsaLimbs4096 } from "../unrolled_meta/rsa4096";

export const MERKLE_DEPTH = 1;

export class MasterlistInputEC256 extends Struct({
  pubkey_x: Field3,
  pubkey_y: Field3,
  path: StaticArray(MerkleWitnessStep, MERKLE_DEPTH),
}) {}

export class MasterlistInputRSA4096 extends Struct({
  modulus: RsaLimbs4096,
  exponent: Field,
  path: StaticArray(MerkleWitnessStep, MERKLE_DEPTH),
}) {}

export function masterlistContainsEC256(inp: MasterlistInputEC256) {
  const pubkeyDigest = Poseidon.hash([
    ...inp.pubkey_x.array,
    ...inp.pubkey_y.array,
  ]);
  let merkleNode = new Field(pubkeyDigest);
  for (let i = 0; i < inp.path.length; i++) {
    merkleNode = inp.path.array[i].calculateParentFor(merkleNode);
  }

  return new Out({
    left: pubkeyDigest,
    right: merkleNode,
    vkDigest: Field(0),
  });
}

export function masterlistContainsRSA4096(inp: MasterlistInputRSA4096) {
  const pubkeyDigest = Poseidon.hash([...inp.modulus, inp.exponent]);
  let merkleNode = new Field(pubkeyDigest);
  for (let i = 0; i < inp.path.length; i++) {
    merkleNode = inp.path.array[i].calculateParentFor(merkleNode);
  }

  return new Out({
    left: pubkeyDigest,
    right: merkleNode,
    vkDigest: Field(0),
  });
}

export const MasterlistContains = ZkProgram({
  name: "masterlist-contains",
  publicOutput: Out,

  methods: {
    contains_ec256: {
      privateInputs: [MasterlistInputEC256],
      async method(inp: MasterlistInputEC256) {
        return {
          publicOutput: masterlistContainsEC256(inp),
        };
      },
    },
    contains_rsa4096: {
      privateInputs: [MasterlistInputRSA4096],
      async method(inp: MasterlistInputRSA4096) {
        return {
          publicOutput: masterlistContainsRSA4096(inp),
        };
      },
    },
  },
});
