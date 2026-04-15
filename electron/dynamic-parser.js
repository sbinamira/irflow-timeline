/**
 * dynamic-parser.js — Config-driven log file parser for IRFlow Timeline
 *
 * Reads parser config JSON files (via config-loader.js) and implements generic
 * streaming parsers for the four supported format types:
 *
 *   kvp   — space-separated key=value pairs  (e.g. FortiGate syslog)
 *   csv   — delimited text, optional syslog prefix stripping and header variants
 *           (e.g. PAN-OS traffic/threat logs)
 *   cef   — Common Event Format  (e.g. Check Point Log Exporter)
 *   json  — JSON array or NDJSON  (e.g. Check Point Management API export)
 *
 * How to add a new format:
 *   1. Create a JSON config file in electron/parser-configs/ (see existing files).
 *   2. If its format.type is one of the four above, it will "just work".
 *   3. If you need a brand-new format type, add a sub-parser function below and
 *      wire it into parseWithConfig().
 */

"use strict";

const fs = require("fs");
const { dbg } = require("./logger");
const { loadConfigs } = require("./config-loader");

// ── Shared utilities ──────────────────────────────────────────────────

/** Regex for generic key=value extraction (reused across KVP and CEF parsers) */
const KVP_RE = /(\w[\w.-]*)=("(?:[^"\\]|\\.)*"|[^\s]+)/g;

/** Strip outer quotes and unescape common sequences from a KVP value. */
function stripKvpQuotes(v) {
  if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') {
    return v.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }
  return v;
}

/** Return the index of the n-th occurrence of character ch in str, or -1. */
function nthIndex(str, ch, n) {
  let count = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] === ch && ++count === n) return i;
  }
  return -1;
}

/** Default syslog priority+header prefix pattern: <14>Apr  1 12:00:00 hostname  */
const DEFAULT_SYSLOG_PREFIX_RE = /^<\d+>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+\S+\s+/;

function stripSyslogPrefix(line, patternStr) {
  const re = patternStr ? new RegExp(patternStr) : DEFAULT_SYSLOG_PREFIX_RE;
  return line.replace(re, "");
}

/**
 * Read the first n non-empty lines of a file without buffering the whole thing.
 * Used both by detectFormat() and by the JSON parser.
 */
function peekLines(filePath, n = 5) {
  return new Promise((resolve, reject) => {
    const lines = [];
    const stream = fs.createReadStream(filePath, { encoding: "utf8", highWaterMark: 4096 });
    let buf = "";
    stream.on("data", chunk => {
      buf += chunk;
      const parts = buf.split("\n");
      buf = parts.pop();
      for (const part of parts) {
        const line = part.trim();
        if (line) {
          lines.push(line);
          if (lines.length >= n) { stream.destroy(); return; }
        }
      }
    });
    stream.on("close", () => resolve(lines));
    stream.on("error", reject);
  });
}

/**
 * Stream a file line-by-line, calling onLine(line, lineByteLength) for each line.
 */
function streamLines(filePath, onLine) {
  return new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filePath, { encoding: "utf8", highWaterMark: 256 * 1024 });
    let buf = "";
    stream.on("data", chunk => {
      buf += chunk;
      const parts = buf.split("\n");
      buf = parts.pop();
      for (const part of parts) {
        onLine(part.replace(/\r$/, ""), Buffer.byteLength(part + "\n", "utf8"));
      }
    });
    stream.on("end", () => {
      if (buf) onLine(buf.replace(/\r$/, ""), Buffer.byteLength(buf, "utf8"));
      resolve();
    });
    stream.on("error", reject);
  });
}

/**
 * Split a delimited line, handling RFC 4180 quoting for comma-delimited files.
 * For non-comma delimiters, a simple split is used (enough for most log formats).
 */
function parseDelimited(line, delimiter) {
  if (delimiter !== ",") return line.split(delimiter);
  const fields = [];
  let inQ = false, field = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') { field += '"'; i++; }
        else inQ = false;
      } else field += c;
    } else {
      if (c === '"') inQ = true;
      else if (c === delimiter) { fields.push(field); field = ""; }
      else field += c;
    }
  }
  fields.push(field);
  return fields;
}

// ── Detection engine ──────────────────────────────────────────────────

/**
 * Test one detection rule against a set of sample lines.
 * Returns true if the rule matches any (or the specified) line.
 */
function testRule(rule, sampleLines) {
  switch (rule.type) {
    case "line_contains":
      return sampleLines.some(l => l.includes(rule.value));

    // Match any of the provided values (convenience for quoted/unquoted variants)
    case "line_contains_any":
      return Array.isArray(rule.values) &&
        sampleLines.some(l => rule.values.some(v => l.includes(v)));

    // Match a KVP key=value regardless of whether the value is quoted:
    // "kvp_key=traffic" matches both  key=traffic  and  key="traffic"
    case "line_contains_kvp_value": {
      const bare   = `${rule.key}=${rule.value}`;
      const quoted = `${rule.key}="${rule.value}"`;
      return sampleLines.some(l => l.includes(bare) || l.includes(quoted));
    }

    case "line_startswith":
      return sampleLines.some(l => l.startsWith(rule.value));

    case "line_regex": {
      try {
        const re = new RegExp(rule.pattern, rule.flags || "i");
        return sampleLines.some(l => re.test(l));
      } catch { return false; }
    }

    case "csv_field_equals": {
      // Strip syslog prefix before splitting, so field index is correct
      for (const line of sampleLines) {
        const stripped = stripSyslogPrefix(line);
        const fields = parseDelimited(stripped, ",");
        const idx = rule.index;
        if (idx < fields.length) {
          const v = fields[idx].trim().replace(/^"|"$/g, "");
          const match = rule.caseSensitive
            ? v === rule.value
            : v.toLowerCase() === String(rule.value).toLowerCase();
          if (match) return true;
        }
      }
      return false;
    }

    case "json_field_exists": {
      for (const line of sampleLines) {
        try {
          const obj = JSON.parse(line.trim());
          if (obj && typeof obj === "object" && rule.field in obj) return true;
        } catch {}
      }
      return false;
    }

    case "json_field_value": {
      for (const line of sampleLines) {
        try {
          const obj = JSON.parse(line.trim());
          if (obj && obj[rule.field] !== undefined) {
            const v = String(obj[rule.field]);
            const match = rule.caseSensitive
              ? v === rule.value
              : v.toLowerCase() === String(rule.value).toLowerCase();
            if (match) return true;
          }
        } catch {}
      }
      return false;
    }

    default:
      dbg("DYNPARSER", `Unknown rule type: ${rule.type}`);
      return false;
  }
}

/**
 * Scan a file against all loaded configs and return the best match.
 *
 * @param {string} filePath
 * @returns {Promise<{ config: object, confidence: number } | null>}
 */
async function detectFormat(filePath) {
  const configs = loadConfigs();
  if (!configs.length) return null;

  const maxLines = Math.max(...configs.map(c => c.detection?.sampleLines || 5), 5);
  let sampleLines;
  try { sampleLines = await peekLines(filePath, maxLines); }
  catch { return null; }
  if (!sampleLines.length) return null;

  const candidates = [];

  for (const cfg of configs) {
    const det      = cfg.detection || {};
    const required = det.required || [];
    const optional = det.optional || [];
    const lines    = sampleLines.slice(0, det.sampleLines || 5);

    // All required rules must pass
    if (!required.every(rule => testRule(rule, lines))) continue;

    // Score: base 0.7 for all-required pass; optional matches add up to 0.3
    const optMatched = optional.filter(rule => testRule(rule, lines)).length;
    const confidence = required.length === 0
      ? 0.3
      : 0.7 + (optional.length > 0 ? (optMatched / optional.length) * 0.3 : 0.3);

    candidates.push({ config: cfg, confidence });
    dbg("DYNPARSER", `Candidate: ${cfg.id}  conf=${confidence.toFixed(2)}`);
  }

  if (!candidates.length) return null;
  candidates.sort((a, b) => b.confidence - a.confidence);
  const best = candidates[0];
  dbg("DYNPARSER", `Best match: ${best.config.id}  conf=${best.confidence.toFixed(2)}`);
  return best;
}

// ── Sub-parsers ───────────────────────────────────────────────────────

/**
 * KVP parser — two-pass streaming.
 * Pass 1: discover all key names in order of first appearance.
 * Pass 2: insert row arrays into the database.
 */
async function parseKvp(filePath, cfg, tabId, db, onProgress) {
  const totalBytes  = safeSize(filePath);
  const syslogPat   = cfg.format.stripSyslogPrefix ? cfg.format.syslogPrefixPattern : null;
  // Support custom key separators; default to "="
  const sep         = cfg.format.kvSeparator || "=";
  const kvPattern   = sep === "="
    ? KVP_RE
    : new RegExp(`(\\w[\\w.-]*)${sep}("(?:[^"\\\\]|\\\\.)*"|[^\\s]+)`, "g");

  // ── Pass 1: key discovery ─────────────────────────────────────────
  const keyOrder = new Map();
  await streamLines(filePath, line => {
    const cleaned = syslogPat || cfg.format.stripSyslogPrefix
      ? stripSyslogPrefix(line, syslogPat)
      : line;
    if (!cleaned.trim()) return;
    kvPattern.lastIndex = 0;
    let m;
    while ((m = kvPattern.exec(cleaned)) !== null) {
      if (!keyOrder.has(m[1])) keyOrder.set(m[1], keyOrder.size);
    }
  });

  const headers = Array.from(keyOrder.keys());
  if (!headers.length) throw new Error(`No key=value pairs found in ${cfg.name} file`);
  db.createTab(tabId, headers);

  // ── Pass 2: row insertion ─────────────────────────────────────────
  const BATCH = 5000;
  let batch = [], rowCount = 0, bytesProcessed = 0, lastTick = 0;

  await streamLines(filePath, (line, lineBytes) => {
    const cleaned = syslogPat || cfg.format.stripSyslogPrefix
      ? stripSyslogPrefix(line, syslogPat)
      : line;
    if (!cleaned.trim()) return;

    const values = new Array(headers.length).fill("");
    kvPattern.lastIndex = 0;
    let m;
    while ((m = kvPattern.exec(cleaned)) !== null) {
      const idx = keyOrder.get(m[1]);
      if (idx !== undefined) values[idx] = stripKvpQuotes(m[2]);
    }

    batch.push(values);
    rowCount++;
    bytesProcessed += lineBytes;

    if (batch.length >= BATCH) {
      db.insertBatchArrays(tabId, batch);
      batch = [];
      const now = Date.now();
      if (now - lastTick >= 200) { lastTick = now; if (onProgress) onProgress(rowCount, bytesProcessed, totalBytes); }
    }
  });

  if (batch.length) db.insertBatchArrays(tabId, batch);
  if (onProgress) onProgress(rowCount, totalBytes, totalBytes);
  const result = db.finalizeImport(tabId);
  return { headers, rowCount: result.rowCount, tsColumns: result.tsColumns, numericColumns: result.numericColumns, sourceFormat: cfg.id };
}

/**
 * CSV parser — single pass.
 * Supports: explicit header row, injected static headers, syslog prefix stripping,
 * and type-field-based header variants (e.g. PAN-OS TRAFFIC vs THREAT columns).
 */
async function parseCsv(filePath, cfg, tabId, db, onProgress) {
  const totalBytes = safeSize(filePath);
  const fmt        = cfg.format;
  const delimiter  = fmt.delimiter || ",";
  const syslogRe   = fmt.stripSyslogPrefix
    ? (fmt.syslogPrefixPattern ? new RegExp(fmt.syslogPrefixPattern) : DEFAULT_SYSLOG_PREFIX_RE)
    : null;

  let headers = null;
  const BATCH = 10000;
  let batch = [], rowCount = 0, bytesProcessed = 0, lastTick = 0;

  await streamLines(filePath, (line, lineBytes) => {
    const raw     = syslogRe ? line.replace(syslogRe, "") : line;
    const trimmed = raw.trim();
    if (!trimmed) return;

    const fields = parseDelimited(trimmed, delimiter);

    if (!headers) {
      if (fmt.hasHeader === false) {
        // Header is injected from config (no header row in file)
        if (fmt.headerVariants && fmt.typeColumnIndex != null) {
          const typeVal = (fields[fmt.typeColumnIndex] || "").trim().toUpperCase();
          headers = fmt.headerVariants[typeVal] || fmt.headerColumns || fields.map((_, i) => `field_${i + 1}`);
        } else {
          headers = fmt.headerColumns || fields.map((_, i) => `field_${i + 1}`);
        }
        db.createTab(tabId, headers);
        // This line is also data — fall through to insert it
      } else {
        // First line is the header row
        headers = fields.map(h => h.trim());
        db.createTab(tabId, headers);
        bytesProcessed += lineBytes;
        return;
      }
    }

    const values = new Array(headers.length).fill("");
    for (let i = 0; i < headers.length && i < fields.length; i++) values[i] = fields[i];
    batch.push(values);
    rowCount++;
    bytesProcessed += lineBytes;

    if (batch.length >= BATCH) {
      db.insertBatchArrays(tabId, batch);
      batch = [];
      const now = Date.now();
      if (now - lastTick >= 200) { lastTick = now; if (onProgress) onProgress(rowCount, bytesProcessed, totalBytes); }
    }
  });

  if (batch.length) db.insertBatchArrays(tabId, batch);
  if (onProgress) onProgress(rowCount, totalBytes, totalBytes);
  const result = db.finalizeImport(tabId);
  return { headers: headers || [], rowCount: result.rowCount, tsColumns: result.tsColumns, numericColumns: result.numericColumns, sourceFormat: cfg.id };
}

/**
 * CEF parser — two-pass streaming.
 * Static pipe-delimited header fields + dynamic KVP extension block.
 */
async function parseCef(filePath, cfg, tabId, db, onProgress) {
  const totalBytes   = safeSize(filePath);
  const staticFields = cfg.format.cefStaticFields ||
    ["CEF_Version", "Device_Vendor", "Device_Product", "Device_Version", "Signature_ID", "Name", "Severity"];
  const staticCount  = staticFields.length;

  // ── Pass 1: discover extension keys ──────────────────────────────
  const extKeyOrder = new Map();
  await streamLines(filePath, line => {
    const trimmed = line.trim();
    if (!trimmed) return;
    const pipeIdx = nthIndex(trimmed, "|", staticCount);
    const ext = pipeIdx >= 0 ? trimmed.slice(pipeIdx + 1) : "";
    KVP_RE.lastIndex = 0;
    let m;
    while ((m = KVP_RE.exec(ext)) !== null) {
      if (!extKeyOrder.has(m[1])) extKeyOrder.set(m[1], extKeyOrder.size);
    }
  });

  const headers = [...staticFields, ...extKeyOrder.keys()];
  db.createTab(tabId, headers);

  // ── Pass 2: insert rows ───────────────────────────────────────────
  const BATCH = 5000;
  let batch = [], rowCount = 0, bytesProcessed = 0, lastTick = 0;

  await streamLines(filePath, (line, lineBytes) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const pipeIdx    = nthIndex(trimmed, "|", staticCount);
    const headerPart = pipeIdx >= 0 ? trimmed.slice(0, pipeIdx) : trimmed;
    const ext        = pipeIdx >= 0 ? trimmed.slice(pipeIdx + 1) : "";
    const values     = new Array(headers.length).fill("");

    const staticVals = headerPart.split("|");
    for (let i = 0; i < staticCount && i < staticVals.length; i++) values[i] = staticVals[i];

    KVP_RE.lastIndex = 0;
    let m;
    while ((m = KVP_RE.exec(ext)) !== null) {
      const idx = extKeyOrder.get(m[1]);
      if (idx !== undefined) values[staticCount + idx] = stripKvpQuotes(m[2]);
    }

    batch.push(values);
    rowCount++;
    bytesProcessed += lineBytes;

    if (batch.length >= BATCH) {
      db.insertBatchArrays(tabId, batch);
      batch = [];
      const now = Date.now();
      if (now - lastTick >= 200) { lastTick = now; if (onProgress) onProgress(rowCount, bytesProcessed, totalBytes); }
    }
  });

  if (batch.length) db.insertBatchArrays(tabId, batch);
  if (onProgress) onProgress(rowCount, totalBytes, totalBytes);
  const result = db.finalizeImport(tabId);
  return { headers, rowCount: result.rowCount, tsColumns: result.tsColumns, numericColumns: result.numericColumns, sourceFormat: cfg.id };
}

/**
 * JSON / NDJSON parser.
 * Streams NDJSON line-by-line; loads JSON arrays entirely (with a 100 MB size guard
 * that caps at 10 000 objects to avoid OOM on huge files).
 */
async function parseJson(filePath, cfg, tabId, db, onProgress) {
  const totalBytes = safeSize(filePath);
  const isLarge    = totalBytes > 100 * 1024 * 1024;
  const mode       = cfg.format.jsonMode || "auto";

  const firstLine  = (await peekLines(filePath, 1))[0] || "";
  const isArray    = firstLine.trimStart().startsWith("[");

  let objects = [];

  if (mode === "ndjson" || (mode === "auto" && !isArray)) {
    // Stream NDJSON line by line (memory-efficient for large files)
    await new Promise((resolve, reject) => {
      const stream = fs.createReadStream(filePath, { encoding: "utf8", highWaterMark: 256 * 1024 });
      let buf = "";
      stream.on("data", chunk => {
        buf += chunk;
        const parts = buf.split("\n");
        buf = parts.pop();
        for (const part of parts) {
          const line = part.trim();
          if (line) { try { objects.push(JSON.parse(line)); } catch {} }
        }
      });
      stream.on("end", () => {
        if (buf.trim()) { try { objects.push(JSON.parse(buf.trim())); } catch {} }
        resolve();
      });
      stream.on("error", reject);
    });
  } else {
    // JSON array — read whole file (with size guard)
    const raw = fs.readFileSync(filePath, "utf8");
    let parsed;
    try { parsed = JSON.parse(raw); } catch { throw new Error(`Invalid JSON in ${cfg.name} file`); }
    if (!Array.isArray(parsed)) throw new Error(`Expected a JSON array in ${cfg.name} file`);
    objects = isLarge ? parsed.slice(0, 10000) : parsed;
  }

  if (!objects.length) throw new Error(`No parseable JSON objects found in ${cfg.name} file`);

  // Discover all top-level keys in first-seen order
  const keyOrder = new Map();
  for (const obj of objects) {
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      for (const k of Object.keys(obj)) {
        if (!keyOrder.has(k)) keyOrder.set(k, keyOrder.size);
      }
    }
  }

  const headers   = Array.from(keyOrder.keys());
  const colCount  = headers.length;
  db.createTab(tabId, headers);

  const BATCH = 5000;
  let batch = [], rowCount = 0, lastTick = 0;
  const bytesPerObj = totalBytes / Math.max(1, objects.length);

  for (const obj of objects) {
    const values = new Array(colCount).fill("");
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      for (const [k, v] of Object.entries(obj)) {
        const idx = keyOrder.get(k);
        if (idx !== undefined) values[idx] = v == null ? "" : String(v);
      }
    }
    batch.push(values);
    rowCount++;

    if (batch.length >= BATCH) {
      db.insertBatchArrays(tabId, batch);
      batch = [];
      const now = Date.now();
      if (now - lastTick >= 200) {
        lastTick = now;
        if (onProgress) onProgress(rowCount, Math.round(rowCount * bytesPerObj), totalBytes);
      }
    }
  }

  if (batch.length) db.insertBatchArrays(tabId, batch);
  if (onProgress) onProgress(rowCount, totalBytes, totalBytes);
  const result = db.finalizeImport(tabId);
  return { headers, rowCount: result.rowCount, tsColumns: result.tsColumns, numericColumns: result.numericColumns, sourceFormat: cfg.id };
}

// ── Helpers ───────────────────────────────────────────────────────────

function safeSize(filePath) {
  try { return fs.statSync(filePath).size; } catch { return 0; }
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Parse a file using a pre-resolved config object.
 * Returns the same shape as the built-in parsers: { headers, rowCount, tsColumns, numericColumns, sourceFormat }.
 */
async function parseWithConfig(filePath, cfg, tabId, db, onProgress) {
  dbg("DYNPARSER", `parseWithConfig: ${cfg.id} (${cfg.format.type}) → ${filePath}`);
  switch (cfg.format.type) {
    case "kvp":  return parseKvp(filePath, cfg, tabId, db, onProgress);
    case "csv":  return parseCsv(filePath, cfg, tabId, db, onProgress);
    case "cef":  return parseCef(filePath, cfg, tabId, db, onProgress);
    case "json": return parseJson(filePath, cfg, tabId, db, onProgress);
    default:
      throw new Error(`Unsupported format type in config "${cfg.id}": ${cfg.format.type}`);
  }
}

module.exports = { detectFormat, parseWithConfig, peekLines };
