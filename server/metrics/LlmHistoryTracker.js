import { llmKey } from "./historyTiers.js";

const finite = (v) => typeof v === "number" && Number.isFinite(v);

/** A baseline older than this is stale: the next delta would span a gap, not one sample. */
const MAX_GAP_MS = 60_000;

/** Difference between two cumulative counters; null on the first sample or a counter reset. */
function delta(current, previous) {
  if (!finite(current) || current < 0) return { delta: null, next: previous };
  if (!finite(previous)) return { delta: null, next: current };
  if (current < previous) return { delta: null, next: current };
  return { delta: current - previous, next: current };
}

/**
 * Per-unit, per-port LLM history tracker. The live gauges are recorded as-is;
 * the cumulative histogram sums/counts and engine counters are differenced into
 * per-sample deltas. The sampler then stores those deltas in the existing
 * 1m/15m rings, where `avg * n` recovers the bucket total.
 *
 * First sample / counter reset / a gap longer than MAX_GAP_MS: the baseline is
 * seeded and the delta series is omitted, so a restart or an offline stretch
 * does not look like one interval's worth of requests.
 */
export function createLlmHistoryTracker() {
  /** @type {Map<string, Map<number, { prev: Record<string, number|null>, at: number }>>} */
  const units = new Map();

  return {
    /** Forget a unit's baselines (e.g. after a restart or when sampling is disabled). */
    reset(unitId) {
      if (typeof unitId === "string") units.delete(unitId);
    },

    /**
     * @param {any} snapshot  SparkMonitor snapshot
     * @param {number} atMs
     * @param {(domain: string) => boolean} isFresh
     * @returns {Record<string, number>}
     */
    record(snapshot, atMs, isFresh = () => true) {
      if (!snapshot || snapshot.online !== true || !isFresh("llm")) return {};
      const unitId = snapshot.id;
      if (typeof unitId !== "string" || unitId === "") return {};
      const entries = Array.isArray(snapshot.metrics?.llm) ? snapshot.metrics.llm : [];
      const configured = Array.isArray(snapshot.llmPorts) ? snapshot.llmPorts : [];
      let ports = units.get(unitId);
      if (!ports) {
        ports = new Map();
        units.set(unitId, ports);
      }
      const out = {};

      entries.forEach((entry, index) => {
        const port = Number.isInteger(entry?.port) ? entry.port : configured[index];
        if (
          !Number.isInteger(port) ||
          !configured.includes(port) ||
          entry?.available !== true ||
          entry?.measurementValid === false
        ) {
          return;
        }
        let state = ports.get(port);
        if (!state) {
          state = { prev: {}, at: atMs };
          ports.set(port, state);
        }
        // A long gap means the counters moved while nothing was sampled: seed,
        // don't report the whole gap as one interval.
        const gap = !finite(state.at) || atMs - state.at > MAX_GAP_MS;
        state.at = atMs;

        const set = (name, value) => {
          if (finite(value)) out[llmKey(port, name)] = value;
        };

        // Live gauges.
        set("perStreamTps", entry.perStreamTps);
        const running = entry.slots?.running ?? entry.requestsRunning;
        const waiting = entry.slots?.waiting ?? entry.requestsWaiting;
        set("requestsRunning", running);
        set("requestsWaiting", waiting);
        if (Number.isFinite(waiting)) {
          set("queued", waiting > 0 ? 1 : 0);
        }
        if (Number.isFinite(running) && Number.isFinite(waiting)) {
          set("idle", running === 0 && waiting === 0 ? 1 : 0);
        }
        set("slotsTotal", entry.slots?.total ?? entry.slotsTotal);
        // A backend that does not flag decode still reports a rate when it is
        // generating; use that rather than recording a false idle.
        const generating =
          entry.decodeActive === true ||
          (Number.isFinite(entry.generationTps) && entry.generationTps > 0);
        set("prefillActive", entry.prefillActive === true ? 1 : 0);
        set("decodeActive", generating ? 1 : 0);
        set("cacheHitRate", entry.prefixCacheHitRate);
        set("mtpAcceptance", entry.mtpAcceptanceRate);
        set("prefillProgress", entry.prefillProgressTokens);
        set("generationProgress", entry.generationProgressTokens);
        if (finite(entry.deviceMemoryBytes)) {
          set("deviceMemory", entry.deviceMemoryBytes / 1024 ** 3);
        }

        // Aggregate decode divided by the sum of the per-stream rates. 1.0 means
        // the engine is decoding all running streams at their measured rate.
        const runningCount = Number(running);
        const gen = Number(entry.generationTps);
        const per = Number(entry.perStreamTps);
        if (
          Number.isFinite(runningCount) &&
          runningCount > 0 &&
          Number.isFinite(gen) &&
          gen >= 0 &&
          Number.isFinite(per) &&
          per > 0
        ) {
          set("decodeEfficiency", Math.min(1, gen / (runningCount * per)));
        }

        // Cumulative counters → per-sample deltas.
        const counters = [
          ["prefillSeconds", entry.prefillSecondsTotal],
          ["prefillCount", entry.prefillCountTotal],
          ["decodeSeconds", entry.decodeSecondsTotal],
          ["decodeCount", entry.decodeCountTotal],
          ["ttftTime", entry.ttftSecondsTotal],
          ["ttftCount", entry.ttftCountTotal],
          ["latencyTime", entry.latencySecondsTotal],
          ["latencyCount", entry.latencyCountTotal],
          ["tpotTime", entry.tpotSecondsTotal],
          ["tpotCount", entry.tpotCountTotal],
          ["preemptions", entry.preemptionsTotal],
          ["promptTokens", entry.totalPromptTokens],
          ["cachedTokens", entry.totalCachedTokens],
          ["genTokens", entry.totalOutputTokens],
          ["decodeRounds", entry.decodeRoundsTotal],
        ];
        for (const [name, current] of counters) {
          if (gap) {
            state.prev[name] = finite(current) && current >= 0 ? current : null;
            continue;
          }
          const { delta: d, next } = delta(current, state.prev[name]);
          state.prev[name] = next;
          if (d != null) set(name, d);
        }

        // Request-time breakdown from the same sample's deltas. The TTFT
        // histogram includes queue wait + prefill; subtract prefill for the
        // queue component. The shares are over queue + prefill + decode.
        const prefill = out[llmKey(port, "prefillSeconds")];
        const decode = out[llmKey(port, "decodeSeconds")];
        const ttft = out[llmKey(port, "ttftTime")];
        if (finite(prefill) && finite(ttft)) {
          const queue = Math.max(0, ttft - prefill);
          set("queueWait", queue);
          const total = prefill + (finite(decode) ? decode : 0) + queue;
          if (total > 0) set("prefillShare", Math.min(1, Math.max(0, prefill / total)));
        }
        const latency = out[llmKey(port, "latencyTime")];
        if (finite(latency) && finite(ttft) && finite(decode)) {
          set("overheadSeconds", Math.max(0, latency - ttft - decode));
        }
      });

      return out;
    },
  };
}
