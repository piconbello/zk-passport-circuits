import { Bytes, Field, Poseidon } from "o1js";
import {
  type MasterCert,
  type PublicKeyEC,
  type RSAPublicKey,
} from "../pipelines/registry/bundle";
import { MerkleTree } from "../unrolled_meta/merkle";
import { createProvableBigint } from "../unrolled_meta/rsa/provableBigint";
import { b64ToBigint } from "../pipelines/registry/workerSchema";
import { parseECpubkey256Uncompressed } from "../unrolled_leaves/utils";
import { decodeBase64 } from "../src/parseBundle";

const ProvableBigint2048 = createProvableBigint(2048);
const ProvableBigint4096 = createProvableBigint(4096);

function calculateRsaKeyDigest(key: RSAPublicKey): Field {
  let modulusFields: Field[];
  switch (key.key_size_bits) {
    case 2048:
      modulusFields = ProvableBigint2048.fromBigint(
        b64ToBigint(key.modulus),
      ).fields;
      break;
    case 4096:
      modulusFields = ProvableBigint4096.fromBigint(
        b64ToBigint(key.modulus),
      ).fields;
      break;
    default:
      throw new Error(`Unsupported RSA key size: ${key.key_size_bits}`);
  }
  const exponentField = Field(b64ToBigint(key.exponent));
  return Poseidon.hash([...modulusFields, exponentField]);
}

export function calculateEcKeyDigestEc256(key: PublicKeyEC): Field {
  const encoded = Bytes.from(decodeBase64(key.encoded));
  const parsed = parseECpubkey256Uncompressed(encoded);
  return Poseidon.hash([...parsed.x, ...parsed.y]);
}

export function masterlistIntoLeaves(masterCerts: MasterCert[]): Field[] {
  const leaves: Field[] = masterCerts
    .map((cert) => {
      if (
        cert.pubkey.type === "RSA" &&
        (cert.pubkey.key_size_bits === 2048 ||
          cert.pubkey.key_size_bits === 4096)
      ) {
        return calculateRsaKeyDigest(cert.pubkey);
      } else if (cert.pubkey.type === "EC") {
        if (cert.pubkey.curve === "prime256v1")
          return calculateEcKeyDigestEc256(cert.pubkey);
        return null;
      } else {
        return null;
      }
    })
    .filter((leaf): leaf is Field => leaf !== null);

  if (leaves.length === 0) {
    throw new Error(
      "No supported master keys (RSA or EC) found to build the Merkle tree.",
    );
  }

  return leaves;
}

export function createMasterKeyMerkleTree(
  masterCerts: MasterCert[],
): MerkleTree {
  const rsaLeaves = masterlistIntoLeaves(masterCerts);
  console.log("Merkle tree with", rsaLeaves.length, "leaves");
  const tree = new MerkleTree(rsaLeaves);
  console.log("Merkle tree done");
  return tree;
}

// async function main() {
//   const masterlistText = await Bun.file("./files/masterlist_284.json").text();
//   const masterCerts = parseMasterlist(masterlistText);

//   const merkleTree = createMasterKeyMerkleTree(masterCerts);
//   console.log("Merkle Tree Root:", merkleTree.root.toString());
// }

// await main();
