import { ZkProgram } from "o1js";
import { mapObject } from "../tests/common";
import type { ZkProgramMethods } from "./interface";
import { randomUUIDv7 } from "bun";
import { Out } from "./out";

export function once<T>(fn: () => Promise<T>): () => Promise<T> {
  let result: T | undefined;
  let executed = false;
  let promise: Promise<T> | null = null;

  return async (): Promise<T> => {
    if (promise) return promise;
    if (executed) return result as T;

    promise = fn().then((value) => {
      result = value;
      executed = true;
      promise = null;
      return value;
    });

    return promise;
  };
}

export function serializedLengthOf(bn: bigint): number {
  let dec = BigInt(bn);
  let len = 0;
  while (dec !== 0n) {
    len += 1;
    dec = dec >> 8n;
  }
  return len;
}

export async function analyzeMethods(zkpMethods: ZkProgramMethods) {
  const zkp = ZkProgram({
    name: randomUUIDv7("base64"),
    publicOutput: Out,
    methods: zkpMethods,
  });
  return mapObject(
    await zkp.analyzeMethods(),
    (m) => m.summary()["Total rows"],
  );
}

export function arrToBigint(arr: Uint8Array): bigint {
  let hex = Buffer.from(arr).toString("hex");
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  return hex ? BigInt("0x" + hex) : 0n;
}

export function bigintToArr(bn: bigint): Uint8Array {
  let hex = bn.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  return Buffer.from(hex, "hex");
}
