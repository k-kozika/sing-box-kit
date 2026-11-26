export type Fields = Record<string, unknown>;

export type ReadonlyJson<T> = T extends object
  ? { readonly [K in keyof T]: ReadonlyJson<T[K]> }
  : T;

type UnionKeys<T> = T extends unknown ? keyof T : never;

export type StrictUnion<T, All = T> = T extends unknown
  ? T & { readonly [K in Exclude<UnionKeys<All>, keyof T>]?: never }
  : never;

export type CamelCase<S extends string> = S extends `${infer Head}-${infer Tail}`
  ? `${Head}${Capitalize<CamelCase<Tail>>}`
  : S;
