import { Field, Poseidon } from "o1js";
import {
  parseBundle,
  parseMasterlist,
  type RSAPublicKey,
  type SignatureRsaPkcs,
  type SignatureRsaPss,
} from "./bundle";
import { b64ToBigint, bigintToB64, type StepSerial } from "./workerSchema";
import { ProvableBigint4096 } from "../../unrolled_leaves/rsa/constants";
import { masterlistIntoLeaves } from "../../unrolled_meta/masterlistIntoMerkle";
import { calcMerkleHeightFor } from "../../unrolled_meta/merkle";
import { log } from "../../unrolled_meta/logger";

const MASTERLIST_LEAVES = await (async function() {
  log.start("masterlist parsing");
  const masterlistText = await Bun.file("./files/masterlist_284.json").text();
  const masterCerts = parseMasterlist(masterlistText);
  const leaves = masterlistIntoLeaves(masterCerts);
  log.finish("masterlist parsing");
  return leaves;
})();

export async function prepareStepInputsForExpiredBundle() {
  const t = await Bun.file("./files/bundle.emre.expired.json").text();
  // console.log("before parsing bundle");
  const bundle = parseBundle(t);
  // console.log("after parsing bundle");

  const pubkeyLocal = bundle.cert_local_pubkey as RSAPublicKey;
  const signatureDoc = bundle.document_signature as SignatureRsaPss;

  const pubkeyMaster = bundle.cert_master_pubkey as RSAPublicKey;
  const signatureCert = bundle.cert_local_signature as SignatureRsaPkcs;
  const pubkeyMasterDigest = Poseidon.hash([
    ...ProvableBigint4096.fromBigint(b64ToBigint(pubkeyMaster.modulus)).fields,
    Field(b64ToBigint(pubkeyMaster.exponent)),
  ]);

  const steps: StepSerial[] = [
    {
      step: "DG1",
      data: {
        digestAlgo: "sha256",
        variant: "TD3",
        dg1: bundle.dg1,
      },
    },
    {
      step: "LDS",
      data: {
        dg1: bundle.dg1,
        lds: bundle.lds,
        digestAlgo: "sha256",
      },
    },
    {
      step: "SIGNEDATTRS",
      data: {
        lds: bundle.lds,
        signedAttrs: bundle.signed_attrs,
        digestAlgo: "sha256",
      },
    },
    {
      step: "RSA_EXP_LOCAL",
      data: {
        keySize: 2048,
        signature: signatureDoc.signature,
        modulus: pubkeyLocal.modulus,
        exponent: pubkeyLocal.exponent,
        signedAttrs: bundle.signed_attrs,
      },
    },
    {
      step: "RSA_VERIFY_LOCAL_PSS",
      data: {
        digestSizeBytes: 32,
        exponent: pubkeyLocal.exponent,
        isModulusPrefixedWithZero: pubkeyLocal.is_modulus_prefixed_with_zero,
        keySize: 2048,
        modulus: pubkeyLocal.modulus,
        saltSizeBytes: 32,
        signature: signatureDoc.signature,
        signedAttrs: bundle.signed_attrs,
      },
    },
    {
      step: "PUBKEY_IN_CERT",
      data: {
        certLocalTbs: bundle.cert_local_tbs,
        pubkeyLocalEncoded: pubkeyLocal.encoded,
      },
    },
    {
      step: "DIGEST_CERT",
      data: {
        digestAlgo: "sha256",
        certLocalTbs: bundle.cert_local_tbs,
      },
    },
    {
      step: "RSA_EXP_MASTER",
      data: {
        keySize: 4096,
        modulus: pubkeyMaster.modulus,
        signature: signatureCert.signature,
        exponent: pubkeyMaster.exponent,
        message: bundle.cert_local_tbs,
      },
    },
    {
      step: "RSA_VERIFY_MASTER_PKCS",
      data: {
        keySize: 4096,
        digestSizeBytes: 32,
        exponent: pubkeyMaster.exponent,
        modulus: pubkeyMaster.modulus,
        signature: signatureCert.signature,
        message: bundle.cert_local_tbs,
      },
    },
    {
      step: "MASTERLIST_CONTAINS",
      data: {
        leaf: bigintToB64(pubkeyMasterDigest.toBigInt()),
        masterlistLeaves: MASTERLIST_LEAVES.map((f) =>
          bigintToB64(f.toBigInt()),
        ),
        maxTreeDepth: calcMerkleHeightFor(MASTERLIST_LEAVES.length) + 1,
      },
    },
  ];
  return steps;
}

// async function main() {
//   console.log(await prepareStepInputsForExpiredBundle());
// }
// await main();
