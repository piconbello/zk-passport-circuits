import {
  parseBundleB64,
  type RSAPublicKey,
  type SignatureRsaPkcs,
  type SignatureRsaPss,
} from "../src/parseBundle";
import bundleJson from "../files/bundle.emre.expired.json";
import { generateCalls as generateCallsDG1 } from "../unrolled_leaves/dg1_td3_256";
import { generateCalls as generateCallsLDS } from "../unrolled_leaves/lds_256";
import { generateCall as generateCallSignedAttrs } from "../unrolled_leaves/signedAttrs_256_256";
import { generateCall as generateCallLocalExponentiate } from "../unrolled_leaves/rsa/exponentiation_2048";
import { generateCall as generateCallsLocalRsaVerify } from "../unrolled_leaves/rsa/validate_local_2048_pss";
import { generateCall as generateCallPubkeyInCert } from "../unrolled_leaves/pubkey_in_cert";
import { generateCalls as generateCallsDigestCert } from "../unrolled_leaves/digest_cert_256";
import { generateCall as generateCallMasterExponentiate } from "../unrolled_leaves/rsa/exponentiation_4096";
import { generateCall as generateCallsMasterRsaPkcsVerify } from "../unrolled_leaves/rsa/validate_master_4096_pkcs";
import type { PerProgram } from "../unrolled_meta/interface";
import { processFast } from "./processPipelineFast";
import { processPipeline } from "./processPipelineSlow";

function getPipeline() {
  const bundle = parseBundleB64(bundleJson as any);
  const pubkeyLocal = bundle.cert_local_pubkey as RSAPublicKey;
  const signatureDoc = bundle.document_signature as SignatureRsaPss;

  const pubkeyMaster = bundle.cert_master_pubkey as RSAPublicKey;
  const signatureCert = bundle.cert_local_signature as SignatureRsaPkcs;

  const callsPerProgram: PerProgram[] = [
    generateCallsDG1(bundle.dg1),
    ...generateCallsLDS(bundle.lds, bundle.dg1),
    generateCallSignedAttrs(bundle.signed_attrs, bundle.lds),
    generateCallLocalExponentiate(
      pubkeyLocal.modulus,
      signatureDoc.signature,
      pubkeyLocal.exponent,
      bundle.signed_attrs,
    ),
    generateCallsLocalRsaVerify(
      pubkeyLocal.is_modulus_prefixed_with_zero,
      32,
      32,
      pubkeyLocal.modulus,
      signatureDoc.signature,
      pubkeyLocal.exponent,
      bundle.signed_attrs,
    ),
    generateCallPubkeyInCert(bundle.cert_local_tbs, pubkeyLocal.encoded),
    ...generateCallsDigestCert(bundle.cert_local_tbs),
    generateCallMasterExponentiate(
      pubkeyMaster.modulus,
      signatureCert.signature,
      pubkeyMaster.exponent,
      bundle.cert_local_tbs,
    ),
    generateCallsMasterRsaPkcsVerify(
      32,
      pubkeyMaster.modulus,
      signatureCert.signature,
      pubkeyMaster.exponent,
      bundle.cert_local_tbs,
    ),
  ];
  return callsPerProgram;
}

const allOut = await processFast(getPipeline());
console.log("DONE");
