import { SHA2, type DynamicBytes } from "@egemengol/mina-credentials";
import { Field } from "o1js";
import data from "../files/pss.short.json" with { type: "json" };
import { Bytes, Gadgets, UInt8 } from "o1js";
import { assert } from "o1js";
import { sha256 } from "@noble/hashes/sha256";

type Length = 28 | 32 | 48 | 64;

function counterUint8s(counterValue: bigint) {
  if (counterValue < 0n || counterValue > 0xffffffffn) {
    throw new Error(
      `MGF1 counter value ${counterValue} is out of the valid 32-bit range (0 to ${0xffffffffn})`,
    );
  }
  const byte0 = (counterValue >> 24n) & 0xffn;
  const byte1 = (counterValue >> 16n) & 0xffn;
  const byte2 = (counterValue >> 8n) & 0xffn;
  const byte3 = counterValue & 0xffn;
  return [
    UInt8.from(byte0),
    UInt8.from(byte1),
    UInt8.from(byte2),
    UInt8.from(byte3),
  ];
}

function genMgf1Mask(
  seed: UInt8[],
  digestSizeBytes: Length,
  maskLen: number,
): UInt8[] {
  assert(maskLen > 0, `maskLen must be positive, got ${maskLen}`);
  assert(
    digestSizeBytes > 0,
    `digestSizeBytes must be positive, got ${digestSizeBytes}`,
  );
  let counter = 0n;
  const mask: UInt8[] = [];
  for (let i = 0; i < maskLen; i += digestSizeBytes) {
    const maskChunk: Bytes = SHA2.hash(
      // @ts-ignore math checks out
      digestSizeBytes * 8,
      seed.concat(counterUint8s(counter)),
    );
    counter += 1n;
    mask.push(...maskChunk.bytes);
  }
  return mask.slice(0, maskLen);
}

function xorUInt8Arrays(a: UInt8[], b: UInt8[]) {
  assert(
    a.length === b.length,
    `XOR arrays must have the same length. Got ${a.length} and ${b.length}`,
  );
  const res: UInt8[] = [];
  for (let i = 0; i < a.length; i++) {
    const f = Gadgets.xor(a[i].value, b[i].value, 8);
    res.push(UInt8.Unsafe.fromField(f));
  }
  return res;
}

function pssVerifySalt() {}

function pssVerify(
  encodedMessage: UInt8[],
  encodedMessageBits: bigint,
  messageDigest: Bytes,
  digestSizeBytes: Length,
  saltSizeBytes: number,
) {
  const em = encodedMessage;
  const mHash = messageDigest;
  const sLen = saltSizeBytes;

  // EM = maskedDB || H || 0xBC
  assert(
    em.length >= mHash.length + sLen + 2,
    "EM is too small for hash and salt",
  );
  em[em.length - 1].assertEquals(0xbc, "EM must end with 0xBC");

  const maskedDB = encodedMessage.slice(
    0,
    encodedMessage.length - digestSizeBytes - 1,
  );

  const h = encodedMessage.slice(
    encodedMessage.length - digestSizeBytes - 1,
    encodedMessage.length - 1,
  );

  const mgf1Mask = genMgf1Mask(h, digestSizeBytes, maskedDB.length);
  const db = xorUInt8Arrays(maskedDB, mgf1Mask);

  // Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB to zero
  const andMask = BigInt(0xff) >> (8n * BigInt(em.length) - encodedMessageBits);
  const firstField = Gadgets.and(db[0].value, Field.from(andMask), 8);
  db[0] = UInt8.Unsafe.fromField(firstField);

  for (let i = 0; i < em.length - digestSizeBytes - saltSizeBytes - 2; i++) {
    db[i].assertEquals(0, `inconsistent ${i}`);
  }
  db[em.length - digestSizeBytes - saltSizeBytes - 2].assertEquals(
    1,
    "inconsistent",
  );
  const salt = db.slice(em.length - digestSizeBytes - saltSizeBytes - 1);
  assert(salt.length === saltSizeBytes);

  const mPrime: UInt8[] = [];
  for (let i = 0; i < 8; i++) {
    mPrime.push(UInt8.from(0));
  }
  mPrime.push(...mHash.bytes);
  mPrime.push(...salt);
  const mPrimeHash: Bytes = SHA2.hash(
    // @ts-ignore
    (digestSizeBytes as number) * 8,
    mPrime,
  );
  assert(mPrimeHash.length === h.length);
  for (let i = 0; i < h.length; i++) {
    h[i].assertEquals(mPrimeHash.bytes[i]);
  }
  //done
}

// db for Short
// 8ccfa76220fc9c390ad05ebf213e33c0206ad9fa6b43d61f7f052ade02dff2a2de7fbdeef29b7dadcf010f0943a4a0c0deca1c0bb8fab9cc0f0a9498088e1cb49a91350961f67ee7428ccda94562cec6f369c9e4ba05b86231c0e6155c897eb909c9695294489c576017cb3eca3bb4226134844887f2b03270e98e660a1699f2880bd2e672259b203971adffa7eb8a471f8e49d317599fc9e613ea0fa653c0de020931e391ca2afb4a183c6edc1d32076007cc4ceb9c8c97860dcd4ea4760e22be09a2dbd167ae95638d471ee000ed8ea242311d8a1ff8106d83302008b6004c3f75c3fc0f7d1fe596d2fec88504b4a3cf99bfa74d20f76c31180a9c57ea6099299d712299e18ad6cdbe13e66f7aec957bb6c81b5b2e8de095bc78d1b04be1135638555dc0af346e6efc75980573d54d646656035682e764c9221349974cae7b5029bfede6a219aeebede9d33126d3718c300d1267fac18a8aef1351afd69cf7e11dbc043cf05fb9e23e13eb65a2a50a0a789b75c12533cbc9839660111aa030c7231cd9cc16587482158365814184cb8ece7c24f853c67ac417228fa6e7a8ec83867534118e3097a7bb9c6048e99e4c6fc39ca06f780c73f7a99d7b349035a0a9edaab69b9194932dab5953e7ba943ea5458422445bded2fe6cdf6f37b7c3

function main() {
  const dbShort = Buffer.from(
    "8ccfa76220fc9c390ad05ebf213e33c0206ad9fa6b43d61f7f052ade02dff2a2de7fbdeef29b7dadcf010f0943a4a0c0deca1c0bb8fab9cc0f0a9498088e1cb49a91350961f67ee7428ccda94562cec6f369c9e4ba05b86231c0e6155c897eb909c9695294489c576017cb3eca3bb4226134844887f2b03270e98e660a1699f2880bd2e672259b203971adffa7eb8a471f8e49d317599fc9e613ea0fa653c0de020931e391ca2afb4a183c6edc1d32076007cc4ceb9c8c97860dcd4ea4760e22be09a2dbd167ae95638d471ee000ed8ea242311d8a1ff8106d83302008b6004c3f75c3fc0f7d1fe596d2fec88504b4a3cf99bfa74d20f76c31180a9c57ea6099299d712299e18ad6cdbe13e66f7aec957bb6c81b5b2e8de095bc78d1b04be1135638555dc0af346e6efc75980573d54d646656035682e764c9221349974cae7b5029bfede6a219aeebede9d33126d3718c300d1267fac18a8aef1351afd69cf7e11dbc043cf05fb9e23e13eb65a2a50a0a789b75c12533cbc9839660111aa030c7231cd9cc16587482158365814184cb8ece7c24f853c67ac417228fa6e7a8ec83867534118e3097a7bb9c6048e99e4c6fc39ca06f780c73f7a99d7b349035a0a9edaab69b9194932dab5953e7ba943ea5458422445bded2fe6cdf6f37b7c3",
    "hex",
  );

  const emHex = data.encoded_message_hex;
  const digestSize = 32; // Assuming SHA-256
  const emLen = emHex.length / 2;
  const expected_h_hex = emHex.substring(
    (emLen - digestSize - 1) * 2,
    (emLen - 1) * 2,
  );

  const msg = Buffer.from(data.message, "ascii");
  const em = Buffer.from(data.encoded_message_hex, "hex");
  const emProvable = Array.from(em).map((u8) => UInt8.from(u8));

  pssVerify(emProvable, 4095n, Bytes.from(sha256(msg)), 32, 32);
}

main();
