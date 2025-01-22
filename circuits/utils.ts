import type { DynamicBytes } from "@egemengol/mina-credentials";
import { UInt8, Field, Bytes, UInt32 } from "o1js";
import type { Bytes65 } from "./constants";

export function assertSubarray(
  haystack: UInt8[],
  needle: UInt8[],
  sizeNeedle: number,
  offset: number,
  message?: string,
): void {
  for (let i = 0; i < sizeNeedle; i += 1) {
    haystack[offset + i].assertEquals(needle[i], message);
  }
}

export function parseECpubkey256Uncompressed(sec1: Bytes65) {
  if (sec1.length !== 65) {
    throw new Error("wrong size for ec pubkey parsing");
  }
  // First byte is header (should be 4 for uncompressed SEC1)
  const bytes = sec1.bytes;
  const head = bytes[0];
  head.assertEquals(UInt8.from(4));

  // Parse X coordinate (32 bytes split into 3 Fields)
  const x: [Field, Field, Field] = [Field(0), Field(0), Field(0)];
  // x[2] (highest limb): first 10 bytes
  for (let i = 1; i < 11; i++) {
    x[2] = x[2].mul(1n << 8n).add(bytes[i].value);
  }
  // x[1] (middle limb): next 11 bytes
  for (let i = 11; i < 22; i++) {
    x[1] = x[1].mul(1n << 8n).add(bytes[i].value);
  }
  // x[0] (lowest limb): last 11 bytes
  for (let i = 22; i < 33; i++) {
    x[0] = x[0].mul(1n << 8n).add(bytes[i].value);
  }

  // Parse Y coordinate (32 bytes split into 3 Fields)
  const y: [Field, Field, Field] = [Field(0), Field(0), Field(0)];
  // y[2] (highest limb): first 10 bytes
  for (let i = 33; i < 43; i++) {
    y[2] = y[2].mul(1n << 8n).add(bytes[i].value);
  }
  // y[1] (middle limb): next 11 bytes
  for (let i = 43; i < 54; i++) {
    y[1] = y[1].mul(1n << 8n).add(bytes[i].value);
  }
  // y[0] (lowest limb): last 11 bytes
  for (let i = 54; i < 65; i++) {
    y[0] = y[0].mul(1n << 8n).add(bytes[i].value);
  }

  return { x, y };
}

export function parseECpubkey256UncompressedDynamic(
  payload: DynamicBytes,
  offset: UInt32,
) {
  let length = 65;
  payload.assertIndexInRange(offset.add(length));

  // First byte is header (should be 4 for uncompressed SEC1)
  const head = payload.getOrUnconstrained(offset.value);
  head.assertEquals(UInt8.from(4));

  // Parse X coordinate (32 bytes split into 3 Fields)
  const x: [Field, Field, Field] = [Field(0), Field(0), Field(0)];
  // x[2] (highest limb): first 10 bytes
  for (let i = 1; i < 11; i++) {
    x[2] = x[2]
      .mul(1n << 8n)
      .add(payload.getOrUnconstrained(offset.add(i).value).value);
  }
  // x[1] (middle limb): next 11 bytes
  for (let i = 11; i < 22; i++) {
    x[1] = x[1]
      .mul(1n << 8n)
      .add(payload.getOrUnconstrained(offset.add(i).value).value);
  }
  // x[0] (lowest limb): last 11 bytes
  for (let i = 22; i < 33; i++) {
    x[0] = x[0]
      .mul(1n << 8n)
      .add(payload.getOrUnconstrained(offset.add(i).value).value);
  }

  // Parse Y coordinate (32 bytes split into 3 Fields)
  const y: [Field, Field, Field] = [Field(0), Field(0), Field(0)];
  // y[2] (highest limb): first 10 bytes
  for (let i = 33; i < 43; i++) {
    y[2] = y[2]
      .mul(1n << 8n)
      .add(payload.getOrUnconstrained(offset.add(i).value).value);
  }
  // y[1] (middle limb): next 11 bytes
  for (let i = 43; i < 54; i++) {
    y[1] = y[1]
      .mul(1n << 8n)
      .add(payload.getOrUnconstrained(offset.add(i).value).value);
  }
  // y[0] (lowest limb): last 11 bytes
  for (let i = 54; i < 65; i++) {
    y[0] = y[0]
      .mul(1n << 8n)
      .add(payload.getOrUnconstrained(offset.add(i).value).value);
  }

  return { x, y };
}

export function assertECpubkey256Uncompressed(
  sec1: Bytes65,
  x: [Field, Field, Field],
  y: [Field, Field, Field],
) {
  const parsed = parseECpubkey256Uncompressed(sec1);
  x[0].assertEquals(parsed.x[0]);
  x[1].assertEquals(parsed.x[1]);
  x[2].assertEquals(parsed.x[2]);
  y[0].assertEquals(parsed.y[0]);
  y[1].assertEquals(parsed.y[1]);
  y[2].assertEquals(parsed.y[2]);
}

export function assertSubarrayDynamic(
  haystack: DynamicBytes,
  needle: Bytes,
  offset: UInt32,
) {
  haystack.assertIndexInRange(offset.add(needle.length));

  for (let i = 0; i < needle.length; i += 1) {
    haystack
      .getOrUnconstrained(offset.value.add(i))
      .assertEquals(needle.bytes[i]);
  }
}
