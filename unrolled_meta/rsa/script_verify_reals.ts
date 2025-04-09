import { Field, Provable, Bytes, UInt8, assert } from "o1js";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { DynamicBytes } from "@egemengol/mina-credentials";

import {
  createProvableBigint,
  rsaVerify as rsaVerifyPkcs,
  ProvableBigintBase,
  EXP_BIT_COUNT,
  multiply,
} from "./provableBigint";
import { parseRSAfromPkcs1, rsaMessageFromDigest } from "./padding_pkcs";
import { pssVerify } from "./padding_pss";

import type {
  Bundle,
  SignatureRsaPss,
  SignatureRsaPkcs,
  RSAPublicKey,
} from "../../src/parseBundle";
import { parseBundle } from "../../src/parseBundle";

class DynByts extends DynamicBytes({ maxLength: 700 }) {}

// Helper Function: Get Noble hash function based on name
function getNobleHash(algoName: string): (msg: Uint8Array) => Uint8Array {
  const upperAlgo = algoName.toUpperCase();
  if (upperAlgo === "SHA256" || upperAlgo === "SHA-256") {
    return sha256;
  }
  if (upperAlgo === "SHA512" || upperAlgo === "SHA-512") {
    return sha512;
  }
  // Add other hashes like SHA1 if necessary, although less common/secure
  throw new Error(`Unsupported hash algorithm: ${algoName}`);
}

// Helper function to convert ProvableBigint back to UInt8 array (Big-Endian)
// This is needed to feed the result of modular exponentiation into pssVerify
async function provableBigintToUint8ArrayBE<T extends ProvableBigintBase>(
  instance: T,
  numBytes: number,
): Promise<UInt8[]> {
  const fieldArray = await Provable.witness(
    Provable.Array(UInt8, numBytes),
    () => {
      const val = instance.toBigint();
      const bytes = new Uint8Array(numBytes);
      for (let i = 0; i < numBytes; i++) {
        const shift = BigInt(8 * (numBytes - 1 - i));
        bytes[i] = Number((val >> shift) & 0xffn);
      }
      // Convert Uint8Array to simple array of UInt8 for witness return
      return Array.from(bytes).map((b) => UInt8.from(b));
    },
  );
  return fieldArray;
}

// --- Reusable Verification Function ---
async function verifyBundleSignatures(
  bundle: Bundle,
  bundleName: string,
): Promise<void> {
  console.log(`\n--- Verifying Bundle: ${bundleName} ---`);

  // --- 1. Verify Document Signature (Signed by Local Key) ---
  console.log("  Verifying Document Signature (Local Key)...");
  try {
    const localPubKey = bundle.cert_local_pubkey;
    const docSignature = bundle.document_signature;
    const signedAttrs = bundle.signed_attrs;

    if (localPubKey.type !== "RSA") {
      throw new Error(`Unsupported local public key type: ${localPubKey.type}`);
    }
    const rsaLocalPubKey = localPubKey as RSAPublicKey; // Type assertion

    const keySize = rsaLocalPubKey.key_size_bits;
    const ProvableBigintLocal = createProvableBigint(keySize);

    // Parse RSA Key components (Modulus N, Exponent e)
    const localKeyBytes = DynByts.fromBytes(
      Buffer.from(rsaLocalPubKey.encoded, "base64"), // Decode base64 encoded DER key
    );
    const { modulus: N_local_pb, exponentValue: e_local_field } =
      parseRSAfromPkcs1(ProvableBigintLocal, localKeyBytes, Field(0));

    if (docSignature.type === "RsaPss") {
      console.log("    Type: RSA-PSS");
      const rsaPssSig = docSignature as SignatureRsaPss; // Type assertion

      // a) Hash the signed attributes
      const hashFn = getNobleHash(rsaPssSig.message_hash_algorithm);
      const mHashBytes = hashFn(signedAttrs);
      const mHashO1js = Bytes.from(mHashBytes);

      // b) Perform modular exponentiation: EM_candidate = signature^e mod N
      const s_pb = ProvableBigintLocal.fromBigint(
        BigInt("0x" + Buffer.from(rsaPssSig.signature).toString("hex")), // Convert signature bytes to bigint
      );

      console.log("    Running PSS exponentiation and verification circuit...");
      await Provable.runAndCheck(async () => {
        // Calculate EM_candidate = s^e mod N
        let EM_candidate_pb = ProvableBigintLocal.fromBigint(1n);
        const bits = e_local_field.toBits(EXP_BIT_COUNT); // Use standard exponent bit count

        // Slightly optimized square-and-multiply
        let current_power = s_pb;
        for (let i = 0; i < EXP_BIT_COUNT; i++) {
          const multiplyFlag = bits[i];
          // Multiply step: EM_candidate *= current_power if bit is 1
          let multiplied = multiply(
            ProvableBigintLocal,
            EM_candidate_pb,
            current_power,
            N_local_pb,
          );
          EM_candidate_pb = Provable.if(
            multiplyFlag,
            ProvableBigintLocal,
            multiplied,
            EM_candidate_pb,
          );
          // Square step: current_power = current_power^2
          current_power = ProvableBigintLocal.modSquare(
            current_power,
            N_local_pb,
          );
        }

        // Check result limbs after exponentiation
        EM_candidate_pb.checkLimbs();

        // c) Convert EM_candidate_pb (limbs) back to UInt8 array (big-endian)
        const numBytes = keySize / 8;
        const EM_candidate_uint8 = await provableBigintToUint8ArrayBE(
          EM_candidate_pb,
          numBytes,
        );

        // d) Prepare parameters for pssVerify
        const digestSizeBytes = mHashBytes.length as 28 | 32 | 48 | 64; // Assert type based on hash function output length
        const saltSizeBytes = rsaPssSig.salt_size_bits / 8;
        assert(
          Number.isInteger(saltSizeBytes),
          "Salt size must be multiple of 8 bits",
        );
        // PSS often uses k-1 bits for the encoded message length, where k is modulus bit size
        const encodedMessageBits = BigInt(keySize - 1);

        // e) Call the PSS verification logic
        pssVerify(
          EM_candidate_uint8,
          encodedMessageBits,
          mHashO1js,
          digestSizeBytes,
          saltSizeBytes,
        );
      });
      console.log("    Document Signature (PSS) VERIFIED successfully.");
    } else if (docSignature.type === "RsaPkcs") {
      console.log("    Type: RSA-PKCS#1 v1.5");
      const rsaPkcsSig = docSignature as SignatureRsaPkcs; // Type assertion

      // a) Hash the signed attributes
      const hashFn = getNobleHash(rsaPkcsSig.message_hash_algorithm);
      const mHashBytes = hashFn(signedAttrs);
      const mHashO1js = Bytes.from(mHashBytes);

      // b) Prepare expected message using PKCS#1 v1.5 padding
      const expectedMessage_pb = rsaMessageFromDigest(
        ProvableBigintLocal,
        mHashO1js,
      );

      // c) Convert signature to ProvableBigint
      const signature_pb = ProvableBigintLocal.fromBigint(
        BigInt("0x" + Buffer.from(rsaPkcsSig.signature).toString("hex")), // Convert signature bytes to bigint
      );

      // d) Verify using the PKCS#1 v1.5 verification function
      console.log("    Running PKCS#1 v1.5 verification circuit...");
      await Provable.runAndCheck(async () => {
        rsaVerifyPkcs(
          ProvableBigintLocal,
          expectedMessage_pb, // Expected padded message
          signature_pb, // Signature s
          N_local_pb, // Modulus N
          e_local_field, // Exponent e
          EXP_BIT_COUNT,
        );
      });
      console.log("    Document Signature (PKCS) VERIFIED successfully.");
    } else {
      throw new Error(
        `Unsupported document signature type: ${(docSignature as any).type}`,
      );
    }
  } catch (error) {
    console.error(`    Document Signature FAILED:`, error);
  }

  // --- 2. Verify Local Certificate Signature (Signed by Master Key) ---
  console.log("  Verifying Local Certificate Signature (Master Key)...");
  try {
    const masterPubKey = bundle.cert_master_pubkey;
    const localCertSig = bundle.cert_local_signature;
    const localCertTBS = bundle.cert_local_tbs; // Data that was signed

    if (masterPubKey.type !== "RSA") {
      throw new Error(
        `Unsupported master public key type: ${masterPubKey.type}`,
      );
    }
    const rsaMasterPubKey = masterPubKey as RSAPublicKey; // Type assertion

    const keySize = rsaMasterPubKey.key_size_bits;
    const ProvableBigintMaster = createProvableBigint(keySize);

    // Parse Master RSA Key components
    const masterKeyBytes = DynByts.fromBytes(
      Buffer.from(rsaMasterPubKey.encoded, "base64"), // Decode base64 encoded DER key
    );
    const { modulus: N_master_pb, exponentValue: e_master_field } =
      parseRSAfromPkcs1(ProvableBigintMaster, masterKeyBytes, Field(0));

    // Certificates typically use PKCS#1 v1.5
    if (localCertSig.type === "RsaPkcs") {
      console.log("    Type: RSA-PKCS#1 v1.5");
      const rsaPkcsSig = localCertSig as SignatureRsaPkcs; // Type assertion

      // a) Hash the local certificate TBS data
      const hashFn = getNobleHash(bundle.cert_local_tbs_digest_algo); // Use the specified digest algo
      const tbsHashBytes = hashFn(localCertTBS);
      const hashHex = Buffer.from(tbsHashBytes).toString("hex");
      // console.log("    Hash Hex:", hashHex);
      const tbsHashO1js = Bytes.from(tbsHashBytes);
      // console.log("    Hash Length:", tbsHashO1js.bytes.length);

      // b) Prepare expected message using PKCS#1 v1.5 padding
      const expectedMessage_pb = rsaMessageFromDigest(
        ProvableBigintMaster,
        tbsHashO1js,
      );
      const expectedMessageBigInt = expectedMessage_pb.toBigint();
      const expectedMessageHex = expectedMessageBigInt
        .toString(16)
        .padStart(keySize / 4, "0"); // Pad to full length!
      // console.log(
      //   `    Expected Padded Msg Full Hex (${expectedMessageHex.length / 2} bytes): ${expectedMessageHex}`,
      // );

      // c) Convert signature to ProvableBigint
      const signature_pb = ProvableBigintMaster.fromBigint(
        BigInt("0x" + Buffer.from(rsaPkcsSig.signature).toString("hex")), // Convert signature bytes to bigint
      );

      // d) Verify using the PKCS#1 v1.5 verification function
      console.log("    Running PKCS#1 v1.5 verification circuit...");
      await Provable.runAndCheck(async () => {
        rsaVerifyPkcs(
          ProvableBigintMaster,
          expectedMessage_pb, // Expected padded TBS hash
          signature_pb, // Signature s
          N_master_pb, // Master Modulus N
          e_master_field, // Master Exponent e
          EXP_BIT_COUNT,
        );
      });
      console.log(
        "    Local Certificate Signature (PKCS) VERIFIED successfully.",
      );
    } else if (localCertSig.type === "RsaPss") {
      // Although less common for certs, handle PSS if encountered
      console.log("    Type: RSA-PSS");
      const rsaPssSig = localCertSig as SignatureRsaPss;

      // a) Hash the TBS data
      const hashFn = getNobleHash(bundle.cert_local_tbs_digest_algo);
      const tbsHashBytes = hashFn(localCertTBS);
      const tbsHashO1js = Bytes.from(tbsHashBytes);

      // b) Perform modular exponentiation: EM_candidate = signature^e mod N
      const s_pb = ProvableBigintMaster.fromBigint(
        BigInt("0x" + Buffer.from(rsaPssSig.signature).toString("hex")),
      );

      console.log("    Running PSS exponentiation and verification circuit...");
      await Provable.runAndCheck(async () => {
        // Calculate EM_candidate = s^e mod N (using master key N, e)
        let EM_candidate_pb = ProvableBigintMaster.fromBigint(1n);
        const bits = e_master_field.toBits(EXP_BIT_COUNT);
        let current_power = s_pb;

        for (let i = 0; i < EXP_BIT_COUNT; i++) {
          const multiplyFlag = bits[i];
          let multiplied = multiply(
            ProvableBigintMaster,
            EM_candidate_pb,
            current_power,
            N_master_pb,
          );
          EM_candidate_pb = Provable.if(
            multiplyFlag,
            ProvableBigintMaster,
            multiplied,
            EM_candidate_pb,
          );
          current_power = ProvableBigintMaster.modSquare(
            current_power,
            N_master_pb,
          );
        }

        EM_candidate_pb.checkLimbs();

        // c) Convert EM_candidate_pb back to UInt8 array
        const numBytes = keySize / 8;
        const EM_candidate_uint8 = await provableBigintToUint8ArrayBE(
          EM_candidate_pb,
          numBytes,
        );

        // d) Prepare PSS parameters
        const digestSizeBytes = tbsHashBytes.length as 28 | 32 | 48 | 64;
        const saltSizeBytes = rsaPssSig.salt_size_bits / 8;
        assert(
          Number.isInteger(saltSizeBytes),
          "Salt size must be multiple of 8 bits",
        );
        const encodedMessageBits = BigInt(keySize - 1);

        // e) Call pssVerify
        pssVerify(
          EM_candidate_uint8,
          encodedMessageBits,
          tbsHashO1js, // TBS Hash
          digestSizeBytes,
          saltSizeBytes,
        );
      });
      console.log(
        "    Local Certificate Signature (PSS) VERIFIED successfully.",
      );
    } else {
      throw new Error(
        `Unsupported local certificate signature type: ${(localCertSig as any).type}`,
      );
    }
  } catch (error) {
    console.error(`    Local Certificate Signature FAILED:`, error);
  }
}

// --- Main Execution ---
async function main() {
  try {
    console.log("Loading bundles...");
    // Load using Bun's file API
    const expiredStr = await Bun.file(
      "./files/bundle.emre.expired.json",
    ).text();
    const validStr = await Bun.file("./files/bundle.emre.valid.json").text();

    console.log("Parsing bundles...");
    const expiredBundle = parseBundle(expiredStr);
    const validBundle = parseBundle(validStr);

    // Verify the valid bundle first
    await verifyBundleSignatures(validBundle, "VALID");

    // Verify the expired bundle
    await verifyBundleSignatures(expiredBundle, "EXPIRED");

    console.log("\nVerification complete.");
  } catch (error) {
    console.error("\nScript failed:", error);
    process.exit(1);
  }
}

// Execute the main function
main().then(() => process.exit(0)); // Ensure clean exit on success
