import assert from "node:assert/strict";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { test } from "node:test";

// CI runs this file beside the installed tarball. Use the source entry for type checking.
const packageName = "sing-box-kit";
const {
  compile,
  endpoint,
  generate,
  outbound,
  service,
  validateConfig,
}: typeof import("../index") = await import(packageName);

void test("compiles and validates configurations from the installed package", () => {
  const direct = outbound.direct({ tag: "direct" });
  assert.deepEqual(compile({ outbounds: [direct] }), {
    outbounds: [{ type: "direct", tag: "direct" }],
  });

  const tailscale = endpoint.tailscale({ tag: "tail", advertise_exit_node: true });
  const usbip = service.usbipServer({ provider: "dynamic" }).listen({ port: 0 });
  const config = compile({ endpoints: [tailscale], services: [usbip] });
  assert.equal(validateConfig(config), config);
  assert.deepEqual(config, {
    endpoints: [{ type: "tailscale", tag: "tail", advertise_exit_node: true }],
    services: [{ type: "usbip-server", provider: "dynamic", listen_port: 0 }],
  });
});

void test("generates a self-signed TLS certificate from the installed package", async () => {
  const { privateKey, certificate } = await generate.tlsKeyPair("example.com");
  const parsed = new X509Certificate(certificate);
  assert.equal(parsed.checkHost("example.com", { subject: "never" }), "example.com");
  assert.ok(parsed.checkPrivateKey(createPrivateKey(privateKey)));
  assert.ok(parsed.verify(parsed.publicKey));
});

void test("generates ECH PEM blocks from the installed package", async () => {
  const ech = await generate.echKeyPair("example.com");
  assert.match(ech.config, /^-----BEGIN ECH CONFIGS-----/);
  assert.match(ech.key, /^-----BEGIN ECH KEYS-----/);
});
