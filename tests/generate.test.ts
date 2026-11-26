import { expect, test } from "bun:test";
import { rejects } from "node:assert/strict";
import { createECDH, createHmac, createPrivateKey, X509Certificate } from "node:crypto";
import { createSecureContext } from "node:tls";
import {
  ECHKeyPair,
  Random,
  RandomBase64,
  RandomBase64Url,
  RandomHex,
  Reality,
  TailcatKeyPair,
  TLSKeyPair,
  UUID,
  VapidKeyPair,
  Wireguard,
  X25519KeyPair,
  x25519PublicKey,
} from "../index";

test("generates UUID v4 and random bytes in each encoding", () => {
  expect(UUID()).toMatch(/^[a-f\d]{8}-[a-f\d]{4}-4[a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/);
  expect(Random(17)).toBeInstanceOf(Uint8Array);
  expect(Random(17)).toHaveLength(17);
  expect(RandomHex(17)).toMatch(/^[a-f\d]{34}$/);
  expect(RandomBase64(17)).toMatch(/^[A-Za-z\d+/]{23}=$/);
  expect(RandomBase64Url(17)).toMatch(/^[A-Za-z\d_-]{23}$/);
  expect(Random(0)).toHaveLength(0);
  const large = Random(65_536 + 32);
  expect(large).toHaveLength(65_536 + 32);
  expect(large.subarray(65_536).some((byte) => byte !== 0)).toBe(true);
  expect(() => Random(-1)).toThrow(RangeError);
  expect(() => Random(1.5)).toThrow(RangeError);
});

test("derives X25519 public keys and encodes WireGuard and Reality pairs", async () => {
  const scalar = Buffer.from(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    "hex",
  );
  expect(Buffer.from(await x25519PublicKey(scalar)).toString("hex")).toBe(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  );
  await rejects(x25519PublicKey(new Uint8Array(31)), RangeError);
  const raw = await X25519KeyPair();
  expect(raw.privateKey[0]! & 7).toBe(0);
  expect(raw.privateKey[31]! & 192).toBe(64);
  expect(raw.publicKey).toEqual(await x25519PublicKey(raw.privateKey));

  const wireguard = await Wireguard();
  expect(wireguard.privateKey).toMatch(/^[A-Za-z\d+/]{43}=$/);
  expect(wireguard.publicKey).toBe(
    Buffer.from(await x25519PublicKey(Buffer.from(wireguard.privateKey, "base64"))).toString(
      "base64",
    ),
  );
  const reality = await Reality();
  expect(reality.privateKey).toMatch(/^[A-Za-z\d_-]{43}$/);
  expect(reality.publicKey).toBe(
    Buffer.from(await x25519PublicKey(Buffer.from(reality.privateKey, "base64url"))).toString(
      "base64url",
    ),
  );
});

test("generates a VAPID P-256 scalar and uncompressed public point", async () => {
  const pair = await VapidKeyPair();
  const scalar = Buffer.from(pair.privateKey, "base64url");
  expect(scalar).toHaveLength(32);
  const key = createECDH("prime256v1");
  key.setPrivateKey(scalar);
  expect(pair.publicKey).toBe(key.getPublicKey().toString("base64url"));
});

test("generates Tailcat keys and a public-key-derived ULA address", async () => {
  const pair = await TailcatKeyPair();
  const publicKey = Buffer.from(pair.publicKey, "base64");
  expect(publicKey.equals(await x25519PublicKey(Buffer.from(pair.privateKey, "base64")))).toBe(
    true,
  );
  const discoPrivateKey = createHmac("sha256", Buffer.from(pair.privateKey, "base64"))
    .update("github.com/tailscale/tailcat disco key v1")
    .digest();
  expect(pair.discoKey).toBe(
    Buffer.from(await x25519PublicKey(discoPrivateKey)).toString("base64"),
  );
  expect(Buffer.from(pair.preSharedKey, "base64")).toHaveLength(32);
  const address = `fd7a:115c:a1e0:${publicKey.subarray(0, 10).toString("hex").match(/.{4}/g)!.join(":")}`;
  expect(pair.address).toBe(new URL(`http://[${address}]`).hostname.slice(1, -1));
});

test("generates matching ECH config and key PEM blocks", async () => {
  const pair = await ECHKeyPair("public.example");
  const configs = Buffer.from(pair.config.split("\n").slice(1, -2).join(""), "base64");
  const keys = Buffer.from(pair.key.split("\n").slice(1, -2).join(""), "base64");
  expect(pair.config).toStartWith("-----BEGIN ECH CONFIGS-----");
  expect(pair.key).toStartWith("-----BEGIN ECH KEYS-----");
  expect(configs.readUInt16BE(0)).toBe(configs.length - 2);
  expect(configs.readUInt16BE(2)).toBe(0xfe0d);
  expect(configs.readUInt16BE(4)).toBe(configs.length - 6);
  expect(configs.readUInt16BE(7)).toBe(0x0020);
  expect(keys.readUInt16BE(0)).toBe(32);
  expect(configs.subarray(11, 43).equals(await x25519PublicKey(keys.subarray(2, 34)))).toBe(true);
  expect(keys.subarray(34)).toEqual(configs);
  expect(configs.subarray(59, -2).toString()).toBe("public.example");
  await rejects(ECHKeyPair("a".repeat(256)), RangeError);
});

test("generates a self-signed TLS certificate with a matching private key and SAN", async () => {
  const { privateKey, certificate } = await TLSKeyPair("example.com");
  const parsed = new X509Certificate(certificate);
  expect(parsed.checkHost("example.com", { subject: "never" })).toBe("example.com");
  expect(parsed.checkPrivateKey(createPrivateKey(privateKey))).toBe(true);
  expect(parsed.verify(parsed.publicKey)).toBe(true);
  expect(parsed.ca).toBe(false);
  expect(() => createSecureContext({ key: privateKey, cert: certificate })).not.toThrow();

  await rejects(TLSKeyPair("example.com", 0), RangeError);
});

test.each(["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"])(
  "encodes %s as a TLS IP subject alternative name",
  async (ip) => {
    const { certificate } = await TLSKeyPair(ip);
    const parsed = new X509Certificate(certificate);
    expect(parsed.checkIP(ip)).toBe(ip);
  },
);

test("rejects a scoped IPv6 address for a TLS certificate", async () => {
  await rejects(TLSKeyPair("fe80::1%eth0"), TypeError);
});
