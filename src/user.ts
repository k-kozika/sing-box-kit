import { fieldsFrom, preserveIdentity, snapshot } from "./resource";
import { fail } from "./schema";
import type { StrictUnion } from "./type-utils";

declare const userBrand: unique symbol;
export interface User {
  readonly name: string;
  readonly [userBrand]: true;
}

type Password = { readonly password: string };

export interface UserCredentials {
  readonly anytls?: Password;
  readonly http?: Password;
  readonly hysteria?: StrictUnion<
    { readonly auth: string | readonly number[] } | { readonly auth_str: string }
  >;
  readonly hysteria2?: Password;
  readonly mixed?: Password;
  readonly naive?: Password;
  readonly shadowsocks?: Password;
  readonly shadowtls?: Password;
  readonly snell?: { readonly userkey: string };
  readonly socks?: Password;
  readonly trojan?: Password;
  readonly tuic?: Password & { readonly uuid: string };
  readonly vless?: { readonly uuid: string; readonly flow?: string };
  readonly vmess?: { readonly uuid: string; readonly alter_id?: number };
}

const passwordFields = ["password"] as const;
const credentialFields = {
  anytls: passwordFields,
  http: passwordFields,
  hysteria: ["auth", "auth_str"],
  hysteria2: passwordFields,
  mixed: passwordFields,
  naive: passwordFields,
  shadowsocks: passwordFields,
  shadowtls: passwordFields,
  snell: ["userkey"],
  socks: passwordFields,
  trojan: passwordFields,
  tuic: ["password", "uuid"],
  vless: ["uuid", "flow"],
  vmess: ["uuid", "alter_id"],
} as const satisfies {
  [K in keyof UserCredentials]-?: readonly (keyof NonNullable<UserCredentials[K]> & string)[];
};

const users = new WeakMap<object, UserCredentials>();

export function user(input: { name: string; credentials?: UserCredentials }): User {
  const { name, credentials } = fieldsFrom(input, "user", ["name", "credentials"], ["name"]);
  if (typeof name !== "string") fail("user.name", "expected a string");
  const entries = fieldsFrom(
    credentials === undefined ? {} : credentials,
    "user.credentials",
    Object.keys(credentialFields),
  );
  for (const key of Object.keys(credentialFields) as (keyof UserCredentials)[]) {
    if (!Object.hasOwn(entries, key)) continue;
    const path = `user.credentials.${key}`;
    const allowed = credentialFields[key];
    const required =
      key === "hysteria" ? [] : allowed.filter((field) => field !== "flow" && field !== "alter_id");
    const entry = fieldsFrom(entries[key], path, allowed, required);
    if (key === "hysteria" && Object.keys(entry).length !== 1)
      fail(path, "expected either auth or auth_str");
    for (const [field, value] of Object.entries(entry)) {
      if (field === "alter_id") {
        if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
          fail(`${path}.${field}`, "expected a non-negative integer");
      } else if (field === "auth" && Array.isArray(value)) {
        if (Array.from(value).some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255))
          fail(`${path}.${field}`, "expected an array of bytes");
      } else if (typeof value !== "string") {
        fail(`${path}.${field}`, "expected a string");
      }
    }
    entries[key] = entry;
  }
  const value = preserveIdentity({ name });
  users.set(value, snapshot(entries, "user.credentials"));
  return value as User;
}

export function isUser(value: unknown): value is User {
  return value !== null && typeof value === "object" && users.has(value);
}

export function requireUserCredentials<K extends keyof UserCredentials>(
  value: User,
  kind: K,
  path: string,
): NonNullable<UserCredentials[K]> {
  return users.get(value)?.[kind] ?? fail(path, `missing ${kind} credentials`);
}
