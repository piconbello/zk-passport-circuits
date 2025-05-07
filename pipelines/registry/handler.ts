import { b64ToBigint, type Step } from "./workerSchema.ts";
import { generateCalls as generateCallsDG1 } from "../../unrolled_leaves/dg1_td3_256";
import { generateCalls as generateCallsLDS } from "../../unrolled_leaves/lds_256";
import { generateCall as generateCallSignedAttrs } from "../../unrolled_leaves/signedAttrs_256_256";
import { generateCall as generateCallLocalExponentiate } from "../../unrolled_leaves/rsa/exponentiation_2048";
import { generateCall as generateCallsLocalRsaVerify } from "../../unrolled_leaves/rsa/validate_local_2048_pss";
import { generateCall as generateCallPubkeyInCert } from "../../unrolled_leaves/pubkey_in_cert";
import { generateCalls as generateCallsDigestCert } from "../../unrolled_leaves/digest_cert_256";
import { generateCall as generateCallMasterExponentiate } from "../../unrolled_leaves/rsa/exponentiation_4096";
import { generateCall as generateCallsMasterRsaPkcsVerify } from "../../unrolled_leaves/rsa/validate_master_4096_pkcs";
import { generateCall as generateCallMasterlistContains } from "../../unrolled_leaves/masterlistContains.ts";
import { generateCall as generateCallSecpr1Local256 } from "../../unrolled_leaves/secpr1_local_256_256.ts";
import { generateCall as generateCallSecpr1Master256 } from "../../unrolled_leaves/secpr1_master_256_256.ts";
import type { PerProgram } from "../../unrolled_meta/interface";
import { Field } from "o1js";
import { MerkleTree } from "../../unrolled_meta/merkle.ts";
import { arrToBigint } from "../../unrolled_meta/utils.ts";

export function stepHandler(stepObj: Step): PerProgram[] {
  // const stepObj = StepSchema.parse(stepSerial);
  switch (stepObj.step) {
    // todo variants as needed
    case "DG1":
      return [generateCallsDG1(stepObj.data.dg1)];
    case "LDS":
      return generateCallsLDS(stepObj.data.lds, stepObj.data.dg1);
    case "SIGNEDATTRS":
      return [
        generateCallSignedAttrs(stepObj.data.signedAttrs, stepObj.data.lds),
      ];
    case "RSA_EXP_LOCAL":
      return [
        generateCallLocalExponentiate(
          b64ToBigint(stepObj.data.modulus),
          stepObj.data.signature,
          b64ToBigint(stepObj.data.exponent),
          stepObj.data.signedAttrs,
        ),
      ];
    case "RSA_VERIFY_LOCAL_PSS":
      return [
        generateCallsLocalRsaVerify(
          stepObj.data.isModulusPrefixedWithZero,
          stepObj.data.digestSizeBytes,
          stepObj.data.saltSizeBytes,
          b64ToBigint(stepObj.data.modulus),
          stepObj.data.signature,
          b64ToBigint(stepObj.data.exponent),
          stepObj.data.signedAttrs,
        ),
      ];
    case "SECPr1_LOCAL":
      return [
        generateCallSecpr1Local256(
          stepObj.data.signedAttrsDigest,
          stepObj.data.pubkey,
          {
            r: arrToBigint(stepObj.data.signature.r),
            s: arrToBigint(stepObj.data.signature.s),
          },
        ),
      ];
    case "PUBKEY_IN_CERT":
      return [
        generateCallPubkeyInCert(
          stepObj.data.certLocalTbs,
          stepObj.data.pubkeyLocalEncoded,
        ),
      ];
    case "DIGEST_CERT":
      return generateCallsDigestCert(stepObj.data.certLocalTbs);
    case "RSA_EXP_MASTER":
      return [
        generateCallMasterExponentiate(
          b64ToBigint(stepObj.data.modulus),
          stepObj.data.signature,
          b64ToBigint(stepObj.data.exponent),
          stepObj.data.message,
        ),
      ];
    case "RSA_VERIFY_MASTER_PKCS":
      return [
        generateCallsMasterRsaPkcsVerify(
          stepObj.data.digestSizeBytes,
          b64ToBigint(stepObj.data.modulus),
          stepObj.data.signature,
          b64ToBigint(stepObj.data.exponent),
          stepObj.data.message,
        ),
      ];
    case "SECPr1_MASTER":
      return [
        generateCallSecpr1Master256(
          stepObj.data.certDigest,
          stepObj.data.pubkey,
          {
            r: arrToBigint(stepObj.data.signature.r),
            s: arrToBigint(stepObj.data.signature.s),
          },
        ),
      ];
    case "MASTERLIST_CONTAINS":
      const tree = new MerkleTree(
        stepObj.data.masterlistLeaves.map((bn) => Field.from(b64ToBigint(bn))),
      );
      return [
        generateCallMasterlistContains(
          Field.from(b64ToBigint(stepObj.data.leaf)),
          tree,
          tree.height + 1,
        ),
      ];
    default:
      // This should be unreachable if StepSchema and the switch statement are exhaustive
      const _exhaustiveCheck: never = stepObj;
      throw new Error(`Unhandled step: ${(_exhaustiveCheck as any)?.step}`);
  }
}
