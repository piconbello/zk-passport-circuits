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
  methods: ZkProgramMethods;
  calls: Call[];
}

export interface Call {
  methodName: string;
  args: any[];
}
