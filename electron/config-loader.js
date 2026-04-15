/**
 * config-loader.js — Loads user-defined parser configs for IRFlow Timeline
 *
 * JSON config files are read from two locations (merged, user configs win on id conflict):
 *   1. {app}/electron/parser-configs/   — bundled example configs (shipped with the app)
 *   2. {userData}/parser-configs/       — user-created / user-edited configs
 *
 * Config format: see electron/parser-configs/*.json for examples.
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const { dbg } = require("./logger");

let _cachedConfigs = null;
let _configDirs    = [];

/**
 * Set the directories to scan.  Call once from main.js before any parsing starts.
 * @param {string} bundledDir  Path to the bundled parser-configs folder (read-only in prod).
 * @param {string} userDir     Path to the user's writable parser-configs folder.
 */
function initConfigDirs(bundledDir, userDir) {
  _configDirs   = [bundledDir, userDir].filter(Boolean);
  _cachedConfigs = null; // invalidate cache
  dbg("CONFIG", `Config dirs: ${_configDirs.join(", ")}`);
}

/** Return the list of directories currently configured. */
function getConfigDirs() { return [..._configDirs]; }

/**
 * Load all valid parser configs.  Results are cached; call clearCache() to force a reload.
 * @returns {object[]}  Array of validated config objects (sorted by id).
 */
function loadConfigs() {
  if (_cachedConfigs) return _cachedConfigs;

  const byId = new Map();

  for (const dir of _configDirs) {
    if (!fs.existsSync(dir)) continue;
    let files;
    try { files = fs.readdirSync(dir).filter(f => f.endsWith(".json")); }
    catch (e) { dbg("CONFIG", `Cannot read dir ${dir}: ${e.message}`); continue; }

    for (const file of files) {
      const fullPath = path.join(dir, file);
      try {
        const cfg = JSON.parse(fs.readFileSync(fullPath, "utf8"));
        if (!_validate(cfg)) {
          dbg("CONFIG", `Skipping invalid config (missing required fields): ${file}`);
          continue;
        }
        // Later dirs override earlier ones for the same id (user configs beat bundled)
        byId.set(cfg.id, { ...cfg, _source: fullPath });
        dbg("CONFIG", `Loaded: ${cfg.id}  (${cfg.name})  from ${file}`);
      } catch (e) {
        dbg("CONFIG", `Failed to parse ${file}: ${e.message}`);
      }
    }
  }

  _cachedConfigs = Array.from(byId.values()).sort((a, b) => a.id.localeCompare(b.id));
  dbg("CONFIG", `Total configs loaded: ${_cachedConfigs.length}`);
  return _cachedConfigs;
}

/** Invalidate the config cache so the next loadConfigs() re-reads from disk. */
function clearCache() { _cachedConfigs = null; }

// ── Validation ────────────────────────────────────────────────────────

const VALID_FORMAT_TYPES = ["kvp", "csv", "cef", "json"];

function _validate(cfg) {
  if (!cfg || typeof cfg !== "object")                 return false;
  if (!cfg.id   || typeof cfg.id   !== "string")       return false;
  if (!cfg.name || typeof cfg.name !== "string")       return false;
  if (!cfg.detection || !Array.isArray(cfg.detection.required)) return false;
  if (!cfg.format || !cfg.format.type)                 return false;
  if (!VALID_FORMAT_TYPES.includes(cfg.format.type))   return false;
  return true;
}

module.exports = { initConfigDirs, getConfigDirs, loadConfigs, clearCache };
