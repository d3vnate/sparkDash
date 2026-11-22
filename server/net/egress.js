/**
 * Default-deny egress for sparkDash.
 *
 * The dashboard collects from, and runs commands on, machines it does not
 * control. Treat every collected value and every command result as untrusted:
 * nothing may leave the local network (loopback, LAN, link-local, Tailscale /
 * CGNAT) unless the operator explicitly sets SPARKDASH_ALLOW_WAN_EGRESS=1.
 *
 * The container entrypoint enforces the same policy with iptables (see
 * scripts/egress-lockdown.sh). This module is the in-process guard so a direct
 * `npm start`, a development run, or a compose file without the firewall still
 * fails closed for features that would reach the public Internet.
 */
import dns from "node:dns/promises";
import net from "node:net";

export const EGRESS_BLOCKED_MESSAGE =
  "Blocked: destination is outside the local network. Set SPARKDASH_ALLOW_WAN_EGRESS=1 only when the operator explicitly allows Internet egress.";

export class EgressBlockedError extends Error {
  constructor(message = EGRESS_BLOCKED_MESSAGE) {
    super(message);
    this.name = "EgressBlockedError";
    this.status = 403;
  }
}

/** True only when the operator opted in explicitly. Anything else is denied. */
export function wanEgressAllowed(env = process.env) {
  return ["1", "true"].includes(String(env?.SPARKDASH_ALLOW_WAN_EGRESS || "").toLowerCase());
}

function normalizeHost(host) {
  return String(host || "")
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
}

/** Dotted quad for the IPv4-mapped IPv6 forms Node may hand back from DNS. */
function mappedIpv4(host) {
  const dotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(host);
  if (dotted && net.isIP(dotted[1]) === 4) return dotted[1];
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (!hex) return null;
  const hi = Number.parseInt(hex[1], 16);
  const lo = Number.parseInt(hex[2], 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

/**
 * True for addresses that stay inside the operator's own network:
 * loopback, RFC 1918, link-local, CGNAT / Tailscale, IPv6 ULA and link-local.
 * Multicast, unspecified and all global unicast addresses are denied.
 */
export function isLocalAddress(address) {
  const host = normalizeHost(address);
  const family = net.isIP(host);
  if (family === 4) {
    const [a, b] = host.split(".").map(Number);
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (family === 6) {
    if (host === "::1") return true;
    const mapped = mappedIpv4(host);
    if (mapped) return isLocalAddress(mapped);
    const first = Number.parseInt(host.split(":", 1)[0] || "0", 16);
    if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 (ULA)
    if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 (link-local)
    return false;
  }
  return false;
}

/**
 * Refuse a host unless every address it resolves to is local. Hostnames are
 * resolved through the supplied lookup so tests can pin the answers.
 * @param {string} host
 * @param {{ lookup?: Function, env?: NodeJS.ProcessEnv }} [opts]
 * @returns {Promise<void>}
 */
export async function assertLocalEgress(host, { lookup = dns.lookup, env = process.env } = {}) {
  if (wanEgressAllowed(env)) return;
  const target = normalizeHost(host);
  if (!target) throw new EgressBlockedError();
  if (target === "localhost" || target.endsWith(".localhost")) return;
  if (net.isIP(target)) {
    if (!isLocalAddress(target)) throw new EgressBlockedError();
    return;
  }
  let addresses;
  try {
    addresses = await lookup(target, { all: true, verbatim: true });
  } catch {
    throw new EgressBlockedError(
      "Blocked: the destination could not be resolved inside the local network."
    );
  }
  if (!Array.isArray(addresses) || addresses.length === 0) throw new EgressBlockedError();
  if (addresses.some((entry) => !isLocalAddress(entry?.address))) throw new EgressBlockedError();
}

/**
 * fetch() with the default-deny egress policy applied to the URL's host.
 * @param {string|URL|Request} input
 * @param {RequestInit} [init]
 * @param {{ lookup?: Function, env?: NodeJS.ProcessEnv }} [opts]
 */
export async function guardedFetch(input, init, opts = {}) {
  const url =
    typeof input === "string"
      ? new URL(input)
      : input instanceof URL
        ? input
        : new URL(input.url);
  await assertLocalEgress(url.hostname, opts);
  return fetch(input, init);
}
