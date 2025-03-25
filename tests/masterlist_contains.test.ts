import { Bytes, Field, Poseidon } from "o1js";
import masterlist_mock from "../files/masterlist_mock.json" with { type: "json" };
import { parseECpubkey256Uncompressed } from "../unrolled_leaves/utils";
import { decodeBase64 } from "../src/parseBundle";
import { expect, test, describe } from "bun:test";
import { MerkleTree, MerkleWitnessStep } from "../unrolled_meta/merkle";
import {
  masterlistContainsEC256,
  masterlistContainsRSA4096,
  MasterlistInputEC256,
  MasterlistInputRSA4096,
  MERKLE_DEPTH,
} from "../unrolled_leaves/masterlist_contains";
import { Field3 } from "../unrolled_leaves/constants";
import { DynamicBytes, StaticArray } from "@egemengol/mina-credentials";
import { parseRSAfromPkcs1LongLongShort4096 } from "../unrolled_meta/rsa4096";

interface MasterlistPubkeyObjEC {
  encoded: string;
  type: "EC";
  curve: string;
}

interface MasterlistPubkeyObjRSA {
  encoded: string;
  type: "RSA";
  modulus: string;
}

function parseEC256Key(p: MasterlistPubkeyObjEC) {
  if (p.curve !== "prime256v1")
    throw new Error(`Unsupported curve: ${p.curve}`);
  const encoded = decodeBase64(p.encoded);
  if (encoded.length !== 65)
    throw new Error(`Invalid length: ${encoded.length}`);
  return parseECpubkey256Uncompressed(Bytes.from(encoded));
}

function parseRSA4096Key(p: MasterlistPubkeyObjRSA) {
  const encoded = decodeBase64(p.encoded);
  const modulus = decodeBase64(p.modulus);
  if (modulus.length !== 512) throw new Error("wrong rsa key length");
  return parseRSAfromPkcs1LongLongShort4096(
    DynamicBytes({ maxLength: 1000 }).fromBytes(encoded),
    Field(0),
  );
}

function getLeaves(): Field[] {
  // @ts-ignore
  return masterlist_mock.pairs.map((pair) => {
    if (pair.pubkey.type == "EC") {
      // @ts-ignore
      const parsed = parseEC256Key(pair.pubkey);
      return Poseidon.hash([...parsed.x, ...parsed.y]);
    } else if (pair.pubkey.type == "RSA") {
      // @ts-ignore
      const parsed = parseRSA4096Key(pair.pubkey);
      return Poseidon.hash([...parsed.modulusLimbs, parsed.exponentValue]);
    }
  });
}

describe("Masterlist Contains", () => {
  const leaves = getLeaves();
  const tree = new MerkleTree(leaves);

  test("basic ec", () => {
    const pubkey_i = masterlist_mock.pairs.findIndex(
      (p) => p.pubkey.type == "EC",
    );
    const witness = tree.getWitness(pubkey_i);
    const path = StaticArray(MerkleWitnessStep, MERKLE_DEPTH).from(witness);
    const pubkey_parsed = parseEC256Key(
      masterlist_mock.pairs[pubkey_i].pubkey as MasterlistPubkeyObjEC,
    );
    const inp = new MasterlistInputEC256({
      pubkey_x: Field3.from(pubkey_parsed.x),
      pubkey_y: Field3.from(pubkey_parsed.y),
      path,
    });
    const out = masterlistContainsEC256(inp);
    const pubkey_digest = Poseidon.hash([
      ...pubkey_parsed.x,
      ...pubkey_parsed.y,
    ]);
    expect(out.left.equals(pubkey_digest).toBoolean()).toBeTrue();
    expect(out.right.equals(tree.root).toBoolean()).toBeTrue();
  });

  test("basic rsa", () => {
    const pubkey_i = masterlist_mock.pairs.findIndex(
      (p) => p.pubkey.type == "RSA",
    );
    if (pubkey_i === -1) {
      throw new Error("No RSA keys found in masterlist mock");
    }

    const witness = tree.getWitness(pubkey_i);
    const path = StaticArray(MerkleWitnessStep, MERKLE_DEPTH).from(witness);
    const pubkey_parsed = parseRSA4096Key(
      masterlist_mock.pairs[pubkey_i].pubkey as MasterlistPubkeyObjRSA,
    );
    const inp = new MasterlistInputRSA4096({
      modulus: pubkey_parsed.modulusLimbs,
      exponent: pubkey_parsed.exponentValue,
      path: path,
    });
    const out = masterlistContainsRSA4096(inp);
    const pubkey_digest = Poseidon.hash([
      ...pubkey_parsed.modulusLimbs,
      pubkey_parsed.exponentValue,
    ]);
    expect(out.left.equals(pubkey_digest).toBoolean()).toBeTrue();
    expect(out.right.equals(tree.root).toBoolean()).toBeTrue();
    // Verify the leaf is in the tree
    const leaf = leaves[pubkey_i];
    expect(leaf.equals(pubkey_digest).toBoolean()).toBeTrue();
  });
});
