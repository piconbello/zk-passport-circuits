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
