import { fieldsFrom, preserveIdentity } from "./resource";
import { fail } from "./schema";

declare const userBrand: unique symbol;
export interface User {
  readonly name: string;
  readonly [userBrand]: true;
}

const users = new WeakSet<object>();

export function user(input: { name: string }): User {
  const { name } = fieldsFrom(input, "user", ["name"], ["name"]);
  if (typeof name !== "string") fail("user.name", "expected a string");
  const value = preserveIdentity({ name });
  users.add(value);
  return value as User;
}

export function isUser(value: unknown): value is User {
  return value !== null && typeof value === "object" && users.has(value);
}
