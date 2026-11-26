import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { pem } from "./crypto";

function der(tag: number, ...parts: Uint8Array[]): Buffer {
  const body = Buffer.concat(parts);
  if (body.length < 128) return Buffer.concat([Buffer.from([tag, body.length]), body]);

  const size = Buffer.alloc(4);
  size.writeUInt32BE(body.length);
  const length = size.subarray(size.findIndex((byte) => byte !== 0));
  return Buffer.concat([Buffer.from([tag, 0x80 | length.length]), length, body]);
}

function sequence(...parts: Uint8Array[]): Buffer {
  return der(0x30, ...parts);
}

function time(date: Date): Buffer {
  const year = date.getUTCFullYear();
  const utc = year >= 1950 && year < 2050;
  const value = date
    .toISOString()
    .slice(utc ? 2 : 0, 19)
    .replace(/[-:T]/g, "");
  return der(utc ? 0x17 : 0x18, Buffer.from(`${value}Z`));
}

function ipAddress(name: string, version: number): Buffer {
  if (version === 4) return Buffer.from(name.split(".").map(Number));

  const canonical = new URL(`http://[${name}]`).hostname.slice(1, -1);
  const [prefix, suffix] = canonical.split("::");
  const leading = prefix ? prefix.split(":") : [];
  const trailing = suffix ? suffix.split(":") : [];
  const groups = [
    ...leading,
    ...Array<string>(8 - leading.length - trailing.length).fill("0"),
    ...trailing,
  ];
  const bytes = Buffer.alloc(16);
  groups.forEach((group, index) => bytes.writeUInt16BE(Number.parseInt(group, 16), index * 2));
  return bytes;
}

export function serverCertificate(serverName: string, months: number) {
  if (!Number.isSafeInteger(months) || months < 1) {
    throw new RangeError("TLS validity must be a positive integer number of months");
  }

  const now = new Date();
  const expires = new Date(now);
  expires.setUTCMonth(expires.getUTCMonth() + months);
  if (!Number.isFinite(expires.getTime()) || expires.getUTCFullYear() > 9999) {
    throw new RangeError("TLS expiry is outside the supported date range");
  }

  if (/[\s\\/@?#%]/.test(serverName)) {
    throw new TypeError("TLS server name must be a DNS name or IP address");
  }
  const version = isIP(serverName);
  const dnsName = version ? "" : domainToASCII(serverName);
  if (!version && (!dnsName || !/^(?:\*\.)?[a-z\d_-]+(?:\.[a-z\d_-]+)*\.?$/i.test(dnsName))) {
    throw new TypeError("TLS server name must be a DNS name or IP address");
  }

  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const sha256WithRsa = Buffer.from("300d06092a864886f70d01010b0500", "hex");
  const name = sequence(
    der(
      0x31,
      sequence(Buffer.from("0603550403", "hex"), der(0x0c, Buffer.from(dnsName || serverName))),
    ),
  );
  const subjectAltName = der(
    version ? 0x87 : 0x82,
    version ? ipAddress(serverName, version) : Buffer.from(dnsName),
  );
  const extensions = der(
    0xa3,
    sequence(
      // Key usage (digitalSignature, keyEncipherment) and extended key usage (serverAuth).
      Buffer.from("300e0603551d0f0101ff0404030205a0", "hex"),
      Buffer.from("30130603551d25040c300a06082b06010505070301", "hex"),
      Buffer.from("30090603551d1304023000", "hex"),
      sequence(Buffer.from("0603551d11", "hex"), der(0x04, sequence(subjectAltName))),
    ),
  );

  const serial = randomBytes(16);
  serial[0] = serial[0]! & 0x7f;
  const first = serial.findIndex((byte) => byte !== 0);
  const serialNumber = first === -1 ? Buffer.from([1]) : serial.subarray(first);
  const positiveSerial =
    serialNumber[0]! < 128 ? serialNumber : Buffer.concat([Buffer.from([0]), serialNumber]);
  const signed = sequence(
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, positiveSerial),
    sha256WithRsa,
    name,
    sequence(time(new Date(now.getTime() - 3_600_000)), time(expires)),
    name,
    publicKey.export({ format: "der", type: "spki" }),
    extensions,
  );
  const signature = sign("sha256", signed, privateKey);
  return {
    privateKey: pem("PRIVATE KEY", privateKey.export({ format: "der", type: "pkcs8" })),
    certificate: pem(
      "CERTIFICATE",
      sequence(signed, sha256WithRsa, der(0x03, Buffer.from([0]), signature)),
    ),
  };
}
