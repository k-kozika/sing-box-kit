import "reflect-metadata";
import { PemConverter } from "@peculiar/x509";

export {
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
} from "@peculiar/x509";

export function encodePem(data: ArrayBuffer | Uint8Array<ArrayBuffer>, label: string): string {
  return `${PemConverter.encode(data, label).trimEnd()}\n`;
}
