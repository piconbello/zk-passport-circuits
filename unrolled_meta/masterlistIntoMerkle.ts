import { Field, Poseidon } from "o1js";
import {
  type MasterCert,
  type RSAPublicKey,
} from "../pipelines/registry/bundle";
import { MerkleTree } from "../unrolled_meta/merkle";
import { createProvableBigint } from "../unrolled_meta/rsa/provableBigint";
import { b64ToBigint } from "../pipelines/registry/workerSchema";

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

export function masterlistIntoLeaves(masterCerts: MasterCert[]): Field[] {
  const rsaLeaves: Field[] = masterCerts
    .filter(
      (cert): cert is MasterCert & { pubkey: RSAPublicKey } =>
        cert.pubkey.type === "RSA" &&
        (cert.pubkey.key_size_bits === 2048 ||
          cert.pubkey.key_size_bits === 4096), // Ensure supported sizes
    )
    .map((cert) => calculateRsaKeyDigest(cert.pubkey));

  if (rsaLeaves.length === 0) {
    throw new Error(
      "No supported RSA master keys found to build the Merkle tree.",
    );
  }

  return rsaLeaves;
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
