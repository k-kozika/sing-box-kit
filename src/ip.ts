const ipv4Octet = /^(?:0|[1-9][0-9]{0,2})$/;
const ipv6Group = /^[0-9a-f]{1,4}$/i;
const ipv6Zone = /^[0-9a-z.:-]+$/i;
const cidrPrefix = /^[0-9]+$/;

export function isIPv4(input: string): boolean {
  const octets = input.split(".", 5);
  return (
    octets.length === 4 && octets.every((octet) => ipv4Octet.test(octet) && Number(octet) <= 255)
  );
}

export function isIPv6(input: string): boolean {
  const [address = "", zone, extraZone] = input.split("%", 3);
  if (
    !address.includes(":") ||
    extraZone !== undefined ||
    (zone !== undefined && !ipv6Zone.test(zone))
  ) {
    return false;
  }

  const [head = "", tail, extra] = address.split("::", 3);
  if (extra !== undefined) return false;

  const groups = head ? head.split(":", 9) : [];
  if (tail) groups.push(...tail.split(":", 9));

  let groupCount = groups.length;
  const last = groups.at(-1);
  if (last?.includes(".")) {
    if (tail === "" || !isIPv4(last)) return false;
    groups.pop();
    // An embedded IPv4 address occupies two 16-bit groups.
    groupCount++;
  }

  return (
    (tail === undefined ? groupCount === 8 : groupCount < 8) &&
    groups.every((group) => ipv6Group.test(group))
  );
}

export function isIP(input: string): 0 | 4 | 6 {
  if (isIPv4(input)) return 4;
  if (isIPv6(input)) return 6;
  return 0;
}

export function isCIDR(input: string): boolean {
  const [address = "", prefix, extra] = input.split("/", 3);
  if (
    prefix === undefined ||
    extra !== undefined ||
    address.includes("%") ||
    !cidrPrefix.test(prefix)
  ) {
    return false;
  }

  const version = isIP(address);
  return version !== 0 && Number(prefix) <= (version === 4 ? 32 : 128);
}
