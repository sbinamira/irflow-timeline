/**
 * schema-fingerprints.js — Config-driven schema detection for IRFlow Timeline
 *
 * Uses loaded parser configs (config-loader.js) to:
 *   1. Provide a confidence-coloured schema badge in the stat bar.
 *   2. Pre-populate the Schema Builder with column labels from the matched config.
 *
 * Fast path: if the dynamic parser already set sourceFormat = a config id,
 * we return confidence 1.0 without re-scanning headers.
 *
 * Fallback: compare file headers against each config's declared columns
 * (using the "required" flag on each column entry to weight the score).
 */

"use strict";

const { loadConfigs } = require("./config-loader");

const NO_MATCH = {
  schemaId: null,
  label: "Unknown",
  vendor: null,
  tool: null,
  confidence: 0,
  matchedRequired: [],
  matchedOptional: [],
  unmatchedRequired: [],
  columns: [],
};

/**
 * Detect the schema of an already-parsed file.
 *
 * @param {string[]}  headers       Column header names from the parsed file.
 * @param {object[]}  sampleRows    First N rows of data (reserved for future row-based checks).
 * @param {string|null} sourceFormat  Config id set by the dynamic parser (fast path).
 * @returns {object}  Schema result with schemaId, label, vendor, tool, confidence, columns.
 */
function detectSchema(headers, sampleRows, sourceFormat) {
  const configs = loadConfigs();

  // ── Fast path: parser already resolved the config id ─────────────
  if (sourceFormat) {
    const cfg = configs.find(c => c.id === sourceFormat);
    if (cfg) {
      return {
        schemaId:         cfg.id,
        label:            cfg.name,
        vendor:           cfg.vendor || null,
        tool:             cfg.tool   || null,
        confidence:       1.0,
        matchedRequired:  [],
        matchedOptional:  [],
        unmatchedRequired:[],
        columns:          cfg.columns || [],
      };
    }
  }

  // ── Header-based fallback ─────────────────────────────────────────
  if (!headers || !headers.length) return NO_MATCH;

  const hLower = headers.map(h => h.toLowerCase());
  const candidates = [];

  for (const cfg of configs) {
    const cols = cfg.columns;
    if (!cols || !cols.length) continue;

    // Columns marked required:true (or that carry a semantic type) are weighted heavier
    const required = cols.filter(c => c.required !== false && c.semantic).map(c => c.key.toLowerCase());
    const optional = cols.filter(c => !c.semantic || c.required === false).map(c => c.key.toLowerCase());

    if (!required.length) continue;

    const matchedRequired = required.filter(k => hLower.includes(k));
    if (matchedRequired.length < required.length * 0.7) continue; // need ≥70 % required match

    const matchedOptional = optional.filter(k => hLower.includes(k));
    const confidence =
      (matchedRequired.length / required.length) * 0.7 +
      (optional.length > 0 ? (matchedOptional.length / optional.length) * 0.3 : 0.3);

    candidates.push({ cfg, matchedRequired, matchedOptional, confidence });
  }

  if (!candidates.length) return NO_MATCH;
  candidates.sort((a, b) => b.confidence - a.confidence);

  const { cfg, matchedRequired, matchedOptional, confidence } = candidates[0];
  return {
    schemaId:         cfg.id,
    label:            cfg.name,
    vendor:           cfg.vendor || null,
    tool:             cfg.tool   || null,
    confidence:       Math.min(1, confidence),
    matchedRequired,
    matchedOptional,
    unmatchedRequired: [],
    columns:          cfg.columns || [],
  };
}

module.exports = { detectSchema };
