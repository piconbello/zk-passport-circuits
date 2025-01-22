import type { UInt8, ZkProgram } from "o1js";

export function randomUint8Array(length: number) {
  const arr = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    arr[i] = Math.floor(Math.random() * 256);
  }
  return arr;
}

export function mapObject<
  T extends Record<string, any>,
  S extends Record<keyof T, any>,
>(obj: T, fn: <K extends keyof T>(value: T[K], key: K) => S[K]): S {
  let result = {} as S;
  for (let key in obj) {
    result[key] = fn(obj[key], key);
  }
  return result;
}
