import { UInt8, Field, Poseidon, Provable, ProvableType } from "o1js";
import type { Bytes65 } from "./constants";
import type { DynamicBytes } from "@egemengol/mina-credentials";

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

export function bytes32ToScalar(slice32: UInt8[]): [Field, Field, Field] {
  const x2 = bytesToLimbBE(slice32.slice(0, 10));
  const x1 = bytesToLimbBE(slice32.slice(10, 21));
  const x0 = bytesToLimbBE(slice32.slice(21, 32));

  return [x0, x1, x2];
}

export function bytesToLimbBE(bytes_: UInt8[]) {
  const bytes = bytes_.map((x) => x.value);
  const n = bytes.length;
  let limb = bytes[0];
  for (let i = 1; i < n; i++) {
    limb = limb.mul(1n << 8n).add(bytes[i]);
  }
  return limb.seal();
}

export function hashBytewisePoseidonState(
  state: [Field, Field, Field],
  db: DynamicBytes,
) {
  const [fullChunks, lastChunk] = db.chunk(2);
  fullChunks.forEach((pair, isDummy, _i) => {
    // @ts-ignore
    state = Provable.if(
      isDummy,
      Provable.Array(Field, 3),
      state,
      Poseidon.update(state, [pair.array[0].value, pair.array[1].value]),
    );
  });
  // @ts-ignore
  state = Provable.if(
    lastChunk.length.equals(2),
    Provable.Array(Field, 3),
    Poseidon.update(state, [
      lastChunk.array[0].value,
      lastChunk.array[1].value,
    ]),
    Poseidon.update(state, [lastChunk.array[0].value]),
  );

  return state;
}

export function hashBytewisePoseidon(db: DynamicBytes): Field {
  return hashBytewisePoseidonState(Poseidon.initialState(), db)[0];
}
