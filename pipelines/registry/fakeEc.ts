import {
  calculateEcKeyDigestEc256,
  masterlistIntoLeaves,
} from "../../unrolled_meta/masterlistIntoMerkle";
import {
  parseBundle,
  parseMasterlist,
  type PublicKeyEC,
  type SignatureEC,
} from "./bundle";
import { log } from "../../unrolled_meta/logger";
import { bigintToB64, type StepSerial } from "./workerSchema";
import { sha256 } from "@noble/hashes/sha256";
import { calcMerkleHeightFor } from "../../unrolled_meta/merkle";

const MASTERLIST_LEAVES = await (async function () {
  log.start("masterlist parsing");
  const masterlistText = await Bun.file("./files/masterlist_mock.json").text();
  const masterCerts = parseMasterlist(masterlistText);
  console.log(
    "pubkeys of mcs",
    masterCerts.map((mc) => mc.pubkey.encoded),
  );
  const leaves = masterlistIntoLeaves(masterCerts);
  log.finish("masterlist parsing");
  return leaves;
})();

export async function prepareStepInputsForFakeEcBundle() {
  const t = await Bun.file("./files/bundle.mock.ec.json").text();
  const bundle = parseBundle(t);

  const pubkeyLocal = bundle.cert_local_pubkey as PublicKeyEC;
  // console.log(pubkeyLocal);
  const signatureDoc = bundle.document_signature as SignatureEC;

  const pubkeyMaster = bundle.cert_master_pubkey as PublicKeyEC;
  console.log(pubkeyMaster.encoded);
  const signatureCert = bundle.cert_local_signature as SignatureEC;
  const pubkeyMasterDigest = calculateEcKeyDigestEc256(pubkeyMaster);

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
        digestAlgoHead: "sha256",
        digestAlgoTail: "sha256",
      },
    },
    {
      step: "SECPr1_LOCAL",
      data: {
        size: 256,
        signature: signatureDoc,
        pubkey: pubkeyLocal.encoded,
        signedAttrsDigest: Buffer.from(
          sha256(Buffer.from(bundle.signed_attrs, "base64")),
        ).toString("base64"),
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
      step: "SECPr1_MASTER",
      data: {
        size: 256,
        signature: signatureCert,
        pubkey: pubkeyMaster.encoded,
        certDigest: Buffer.from(
          sha256(Buffer.from(bundle.cert_local_tbs, "base64")),
        ).toString("base64"),
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
