import type { Out } from "./out";
import type { ProvableType } from "o1js";
type Tuple<T> = [T, ...T[]] | [];

export interface ZkProgramMethod<
  T extends Tuple<ProvableType> = Tuple<ProvableType>,
> {
  privateInputs: T;
  method(...args: any[]): Promise<{ publicOutput: Out }>;
}

export interface ZkProgramMethods {
  [methodName: string]: ZkProgramMethod;
}

export interface PerProgram {
  id?: string;
  methods: ZkProgramMethods;
  calls: Call[];
}

export function identifyPerProgram(pp: PerProgram): string {
  if (pp.id) {
    return pp.id;
  } else {
    const methodNames = Object.keys(pp.methods);
    return `[${methodNames.join(", ")}]`;
  }
}

export interface Call {
  methodName: string;
  args: any[];
}
