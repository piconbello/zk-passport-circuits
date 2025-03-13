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
