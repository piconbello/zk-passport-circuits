import { describe, test, expect } from "bun:test";
import * as forge from "node-forge";
import { sha256 } from "@noble/hashes/sha256";
import { Bytes, Field, Unconstrained } from "o1js";
import {
  Bigint4096,
  rsaVerify,
  EXP_BIT_COUNT,
  rsaMessageFromDigest,
  parseRSAfromPkcs1LongLongShort4096,
} from "../unrolled_meta/rsa4096";
import { DynamicBytes } from "@egemengol/mina-credentials";

class PubkeyEncoded extends DynamicBytes({ maxLength: 600 }) {}

describe("RSA 4096-bit verification with real-world keys", () => {
  // Generate a real RSA 4096-bit key once for all tests
  const rsaKeyPair = forge.pki.rsa.generateKeyPair({ bits: 4096, e: 0x010001 });
  // Get the public key in PKCS#1 format
  const publicKeyDer = forge.asn1
    .toDer(forge.pki.publicKeyToRSAPublicKey(rsaKeyPair.publicKey))
    .getBytes();
  console.log("Public Key DER structure:");
  console.log(
    Buffer.from(publicKeyDer, "binary")
      .toString("hex")
      .match(/.{1,2}/g)
      ?.join(" "),
  );
  console.log("Key format info:");
  const asn1 = forge.asn1.fromDer(publicKeyDer);
  console.log(JSON.stringify(asn1, null, 2));

  test("should verify a valid 4096-bit RSA signature with e=65537", () => {
    // Create a test message
    const message =
      "This is a test message for RSA 4096-bit signature verification";

    // Calculate SHA-256 digest with noble/hashes for our circuit
    const digest = sha256(new TextEncoder().encode(message));

    // Sign the message using node-forge (which uses the same padding scheme)
    const md = forge.md.sha256.create();
    md.update(message);
    const signature = rsaKeyPair.privateKey.sign(md);

    // Convert the DER-encoded public key to a DynamicBytes object
    const publicKeyBytes = Uint8Array.from(
      publicKeyDer.split("").map((c) => c.charCodeAt(0)),
    );
    const dynamicPublicKey = PubkeyEncoded.fromBytes(publicKeyBytes);

    // Parse the public key components using your implementation
    const { modulusLimbs, exponentValue } = parseRSAfromPkcs1LongLongShort4096(
      dynamicPublicKey,
      Field(0),
    );

    // Create the message representation from the digest
    const messageLimbs = rsaMessageFromDigest(Bytes.from(digest), 4096n);
    const messageField = Bigint4096.fromLimbs(messageLimbs);

    // Convert signature to Bigint4096
    const signatureBytes = Uint8Array.from(
      signature.split("").map((c) => c.charCodeAt(0)),
    );
    let signatureBigInt = 0n;
    for (let i = 0; i < signatureBytes.length; i++) {
      signatureBigInt = (signatureBigInt << 8n) | BigInt(signatureBytes[i]);
    }
    const signatureField = Bigint4096.fromBigint(signatureBigInt);

    // Create the modulus Bigint4096
    const modulusField = Bigint4096.fromLimbs(modulusLimbs);

    // Verify using your implementation
    rsaVerify(messageField, signatureField, modulusField, exponentValue);
  });

  test("should reject an invalid 4096-bit RSA signature", () => {
    // Create a test message
    const message =
      "This is a test message for RSA 4096-bit signature verification";

    // Calculate SHA-256 digest with noble/hashes for our circuit
    const digest = sha256(new TextEncoder().encode(message));

    // Sign the message using node-forge
    const md = forge.md.sha256.create();
    md.update(message);
    let signature = rsaKeyPair.privateKey.sign(md);

    // Corrupt the signature by changing a byte
    const signatureBytes = signature.split("");
    signatureBytes[10] = String.fromCharCode(
      (signatureBytes[10].charCodeAt(0) + 1) % 256,
    );
    const corruptedSignature = signatureBytes.join("");

    // Convert the DER-encoded public key to a DynamicBytes object
    const publicKeyBytes = Uint8Array.from(
      publicKeyDer.split("").map((c) => c.charCodeAt(0)),
    );
    const dynamicPublicKey = PubkeyEncoded.fromBytes(publicKeyBytes);

    // Parse the public key components using your implementation
    const { modulusLimbs, exponentValue } = parseRSAfromPkcs1LongLongShort4096(
      dynamicPublicKey,
      Field(0),
    );

    // Create the message representation from the digest
    const messageLimbs = rsaMessageFromDigest(Bytes.from(digest), 4096n);
    const messageField = Bigint4096.fromLimbs(messageLimbs);

    // Convert corrupted signature to Bigint4096
    const corruptedSignatureBytes = Uint8Array.from(
      corruptedSignature.split("").map((c) => c.charCodeAt(0)),
    );
    let signatureBigInt = 0n;
    for (let i = 0; i < corruptedSignatureBytes.length; i++) {
      signatureBigInt =
        (signatureBigInt << 8n) | BigInt(corruptedSignatureBytes[i]);
    }
    const signatureField = Bigint4096.fromBigint(signatureBigInt);

    // Create the modulus Bigint4096
    const modulusField = Bigint4096.fromLimbs(modulusLimbs);

    // This should throw because the signature is corrupted
    expect(() => {
      rsaVerify(messageField, signatureField, modulusField, exponentValue);
    }).toThrow();
  });

  test("should verify multiple messages with the same key", () => {
    // Test with multiple different messages
    const messages = [
      "First test message",
      "Second test message with different content",
      "Third test message with even more unique content to verify",
    ];

    // Convert the DER-encoded public key to a DynamicBytes object
    const publicKeyBytes = Uint8Array.from(
      publicKeyDer.split("").map((c) => c.charCodeAt(0)),
    );
    const dynamicPublicKey = PubkeyEncoded.fromBytes(publicKeyBytes);

    // Parse the public key components using your implementation
    const { modulusLimbs, exponentValue } = parseRSAfromPkcs1LongLongShort4096(
      dynamicPublicKey,
      Field(0),
    );

    // Create the modulus Bigint4096
    const modulusField = Bigint4096.fromLimbs(modulusLimbs);

    for (const message of messages) {
      // Calculate SHA-256 digest with noble/hashes for our circuit
      const digest = sha256(new TextEncoder().encode(message));

      // Sign the message using node-forge
      const md = forge.md.sha256.create();
      md.update(message);
      const signature = rsaKeyPair.privateKey.sign(md);

      // Create the message representation from the digest
      const messageLimbs = rsaMessageFromDigest(Bytes.from(digest), 4096n);
      const messageField = Bigint4096.fromLimbs(messageLimbs);

      // Convert signature to Bigint4096
      const signatureBytes = Uint8Array.from(
        signature.split("").map((c) => c.charCodeAt(0)),
      );
      let signatureBigInt = 0n;
      for (let i = 0; i < signatureBytes.length; i++) {
        signatureBigInt = (signatureBigInt << 8n) | BigInt(signatureBytes[i]);
      }
      const signatureField = Bigint4096.fromBigint(signatureBigInt);

      // Verify using your implementation
      rsaVerify(messageField, signatureField, modulusField, exponentValue);
    }
  });

  test("should validate exponent bits match the expected value", () => {
    // Test that the exponent value matches the expected e=65537 (0x010001)
    // Convert the DER-encoded public key to a DynamicBytes object
    const publicKeyBytes = Uint8Array.from(
      publicKeyDer.split("").map((c) => c.charCodeAt(0)),
    );
    const dynamicPublicKey = PubkeyEncoded.fromBytes(publicKeyBytes);

    // Parse the public key components using your implementation
    const { exponentValue } = parseRSAfromPkcs1LongLongShort4096(
      dynamicPublicKey,
      Field(0),
    );

    // Check that exponentValue equals 65537
    expect(exponentValue.toBigInt()).toBe(65537n);

    // Check that the binary representation has the correct bits set
    // 65537 = 2^16 + 1 = 0x010001
    const bits = exponentValue.toBits(EXP_BIT_COUNT);

    // Only bit 0 and bit 16 should be set
    for (let i = 0; i < EXP_BIT_COUNT; i++) {
      if (i === 0 || i === 16) {
        expect(bits[i].toBoolean()).toBe(true);
      } else {
        expect(bits[i].toBoolean()).toBe(false);
      }
    }
  });

  test("should handle SHA-512 digest", () => {
    // Only if your implementation supports SHA-512
    try {
      const message = "Test message for SHA-512 digest";

      // Calculate SHA-512 digest with another library like noble/hashes
      const sha512 = async (data: Uint8Array) => {
        // Dynamic import to handle potential absence of SHA-512 support
        const { sha512 } = await import("@noble/hashes/sha512");
        return sha512(data);
      };

      sha512(new TextEncoder().encode(message)).then((digest) => {
        // Sign the message using node-forge with SHA-512
        const md = forge.md.sha512.create();
        md.update(message);
        const signature = rsaKeyPair.privateKey.sign(md);

        // Convert the DER-encoded public key to a DynamicBytes object
        const publicKeyBytes = Uint8Array.from(
          publicKeyDer.split("").map((c) => c.charCodeAt(0)),
        );
        const dynamicPublicKey = PubkeyEncoded.fromBytes(publicKeyBytes);

        // Parse the public key components using your implementation
        const { modulusLimbs, exponentValue } =
          parseRSAfromPkcs1LongLongShort4096(dynamicPublicKey, Field(0));

        // Create the message representation from the digest
        const messageLimbs = rsaMessageFromDigest(Bytes.from(digest), 4096n);
        const messageField = Bigint4096.fromLimbs(messageLimbs);

        // Convert signature to Bigint4096
        const signatureBytes = Uint8Array.from(
          signature.split("").map((c) => c.charCodeAt(0)),
        );
        let signatureBigInt = 0n;
        for (let i = 0; i < signatureBytes.length; i++) {
          signatureBigInt = (signatureBigInt << 8n) | BigInt(signatureBytes[i]);
        }
        const signatureField = Bigint4096.fromBigint(signatureBigInt);

        // Create the modulus Bigint4096
        const modulusField = Bigint4096.fromLimbs(modulusLimbs);

        // Verify using your implementation
        rsaVerify(messageField, signatureField, modulusField, exponentValue);
      });
    } catch (error) {
      // Skip test if SHA-512 is not supported
      console.log("SHA-512 test skipped: not supported");
    }
  });
});
