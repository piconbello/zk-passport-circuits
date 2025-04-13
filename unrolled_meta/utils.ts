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
