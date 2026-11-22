import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  EGRESS_BLOCKED_MESSAGE,
  assertLocalEgress,
  isLocalAddress,
  wanEgressAllowed,
} from "../net/egress.js";

const lookup = (answers) => async () => answers.map((address) => ({ address }));

test("local addresses cover loopback, RFC 1918, link-local, Tailscale and IPv6 ULA", () => {
  for (const address of [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.1.105",
    "169.254.1.1",
    "100.64.0.1",
    "100.127.255.254",
    "::1",
    "fd00::1",
    "fe80::1",
    "::ffff:192.168.1.5",
  ]) {
    assert.equal(isLocalAddress(address), true, address);
  }
});

test("public, multicast and unspecified addresses are not local", () => {
  for (const address of [
    "1.1.1.1",
    "8.8.8.8",
    "172.15.0.1",
    "172.32.0.1",
    "100.63.255.255",
    "100.128.0.1",
    "224.0.0.1",
    "0.0.0.0",
    "2606:4700:4700::1111",
    "::",
  ]) {
    assert.equal(isLocalAddress(address), false, address);
  }
});

test("WAN egress is off unless the operator sets the opt-in", () => {
  assert.equal(wanEgressAllowed({}), false);
  assert.equal(wanEgressAllowed({ SPARKDASH_ALLOW_WAN_EGRESS: "0" }), false);
  assert.equal(wanEgressAllowed({ SPARKDASH_ALLOW_WAN_EGRESS: "1" }), true);
  assert.equal(wanEgressAllowed({ SPARKDASH_ALLOW_WAN_EGRESS: "true" }), true);
});

test("assertLocalEgress allows local literals and hostnames that resolve locally", async () => {
  await assertLocalEgress("192.168.1.105", { env: {} });
  await assertLocalEgress("100.69.136.98", { env: {} });
  await assertLocalEgress("host.docker.internal", { env: {}, lookup: lookup(["192.168.65.254"]) });
  await assertLocalEgress("localhost", { env: {} });
});

test("assertLocalEgress refuses public literals and hostnames that resolve public", async () => {
  await assert.rejects(
    () => assertLocalEgress("1.1.1.1", { env: {} }),
    (err) => err.message === EGRESS_BLOCKED_MESSAGE && err.status === 403
  );
  await assert.rejects(
    () => assertLocalEgress("raw.githubusercontent.com", { env: {}, lookup: lookup(["185.199.108.133"]) }),
    (err) => err.message === EGRESS_BLOCKED_MESSAGE
  );
  await assert.rejects(
    () =>
      assertLocalEgress("mixed.example", {
        env: {},
        lookup: lookup(["192.168.1.5", "93.184.216.34"]),
      }),
    (err) => err.message === EGRESS_BLOCKED_MESSAGE
  );
});

test("an unresolvable destination fails closed", async () => {
  await assert.rejects(
    () =>
      assertLocalEgress("unknown.example", {
        env: {},
        lookup: async () => {
          throw new Error("ENOTFOUND");
        },
      }),
    (err) => err.name === "EgressBlockedError"
  );
});

test("the explicit opt-in bypasses the local-only check", async () => {
  await assertLocalEgress("raw.githubusercontent.com", {
    env: { SPARKDASH_ALLOW_WAN_EGRESS: "1" },
  });
});
