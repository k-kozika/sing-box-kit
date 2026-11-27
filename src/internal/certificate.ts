import "reflect-metadata";
import { pem } from "@peculiar/utils/pem";
import {
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
} from "@peculiar/x509";
import { isIP } from "../ip";

export async function serverCertificate(serverName: string, months: number) {
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
  const dnsName =
    version || serverName.includes(":") ? undefined : URL.parse(`http://${serverName}/`)?.hostname;
  if (!version && (!dnsName || !/^(?:\*\.)?[a-z\d_-]+(?:\.[a-z\d_-]+)*\.?$/i.test(dnsName))) {
    throw new TypeError("TLS server name must be a DNS name or IP address");
  }

  const crypto = globalThis.crypto;
  const algorithm = {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  };
  const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);

  const name = dnsName || serverName;
  // Normalize IPv4-mapped IPv6 to hexadecimal groups for the SAN encoder.
  const san = version === 6 ? new URL(`http://[${serverName}]`).hostname.slice(1, -1) : name;
  const certificate = await X509CertificateGenerator.createSelfSigned(
    {
      name: [{ CN: [name] }],
      notBefore: new Date(now.getTime() - 3_600_000),
      notAfter: expires,
      signingAlgorithm: algorithm,
      keys,
      extensions: [
        new KeyUsagesExtension(
          KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment,
          true,
        ),
        new ExtendedKeyUsageExtension([ExtendedKeyUsage.serverAuth]),
        new BasicConstraintsExtension(false),
        new SubjectAlternativeNameExtension([{ type: version ? "ip" : "dns", value: san }]),
      ],
    },
    crypto,
  );

  return {
    privateKey: pem.encode("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", keys.privateKey)),
    certificate: pem.encode("CERTIFICATE", certificate.rawData),
  };
}
