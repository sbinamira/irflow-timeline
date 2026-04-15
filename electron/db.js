/**
 * db.js — SQLite-backed data engine for IRFlow Timeline
 *
 * Architecture:
 *   1. Streaming import: CSV/XLSX rows are inserted in batches via transactions
 *   2. FTS5 full-text search index for global search
 *   3. SQL-based filtering, sorting, pagination (only visible rows in memory)
 *   4. Column metadata, stats, and type detection stored alongside data
 *   5. Temp database files auto-cleaned on close
 *
 * This enables handling 30-50GB+ files because:
 *   - Rows stream from disk → SQLite (never all in JS heap)
 *   - Queries use LIMIT/OFFSET (only ~10k rows in memory at once)
 *   - FTS5 handles full-text search natively
 *   - SQLite B-tree indexes handle sorting without in-memory sort
 */

const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

// ── Debug trace logger (shared singleton — see logger.js) ─────────
const { dbg } = require("./logger");

class TimelineDB {
  constructor() {
    this.databases = new Map(); // tabId -> { db, dbPath, headers, rowCount, tsColumns }
    // Periodic WAL checkpoint — prevent unbounded WAL growth on long sessions
    this._walInterval = setInterval(() => {
      for (const [, meta] of this.databases) {
        try { if (meta.db?.open) meta.db.pragma("wal_checkpoint(PASSIVE)"); } catch {}
      }
    }, 5 * 60 * 1000); // every 5 minutes
  }

  _isHayabusaDataset(metaOrHeaders) {
    const headers = Array.isArray(metaOrHeaders) ? metaOrHeaders : metaOrHeaders?.headers;
    if (!Array.isArray(headers) || headers.length === 0) return false;
    const has = (re) => headers.some((h) => re.test(h));
    return has(/^RuleTitle$/i) && has(/^Details$/i) && has(/^EventID$/i) && has(/^Channel$/i);
  }

  _isChainsawDataset(metaOrHeaders) {
    const headers = Array.isArray(metaOrHeaders) ? metaOrHeaders : metaOrHeaders?.headers;
    if (!Array.isArray(headers) || headers.length === 0) return false;
    const has = (re) => headers.some((h) => re.test(h));
    return has(/^system_time$/i) && has(/^id$/i)
      && (has(/^detection_rules$/i) || has(/^computer_name$/i) || has(/^workstation_name$/i));
  }

  _isChainsawProcessDataset(metaOrHeaders) {
    const headers = Array.isArray(metaOrHeaders) ? metaOrHeaders : metaOrHeaders?.headers;
    if (!this._isChainsawDataset(headers)) return false;
    const has = (re) => headers.some((h) => re.test(h));
    return has(/^process_name$/i)
      || has(/^Event\.EventData\.Image$/i)
      || has(/^command_line$/i)
      || has(/^Event\.EventData\.CommandLine$/i);
  }

  _isChainsawLogonDataset(metaOrHeaders) {
    const headers = Array.isArray(metaOrHeaders) ? metaOrHeaders : metaOrHeaders?.headers;
    if (!this._isChainsawDataset(headers)) return false;
    const has = (re) => headers.some((h) => re.test(h));
    return has(/^target_username$/i)
      && has(/^logon_type$/i)
      && (has(/^source_ip$/i) || has(/^workstation_name$/i));
  }

  _cleanWrappedField(value, options = {}) {
    const { lineJoiner = "" } = options;
    if (value == null) return "";
    let s = String(value).replace(/\u0000/g, "");
    s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    s = s.replace(/\n+/g, lineJoiner);
    s = s.trim();
    while (s.length >= 2 && (
      (s.startsWith('"') && s.endsWith('"'))
      || (s.startsWith("'") && s.endsWith("'"))
    )) {
      s = s.slice(1, -1).trim();
    }
    return s;
  }

  _normalizeCompactKey(key) {
    return String(key || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
  }

  _parseCompactKeyValues(...texts) {
    const map = new Map();
    for (const text of texts) {
      if (!text) continue;
      const parts = String(text).split(/\s*[¦\r\n]+\s*/);
      for (const rawPart of parts) {
        const part = rawPart.trim();
        if (!part) continue;
        const idx = part.indexOf(":");
        if (idx <= 0) continue;
        const key = part.slice(0, idx).trim();
        const value = part.slice(idx + 1).trim();
        if (!key || !value) continue;
        const norm = this._normalizeCompactKey(key);
        if (!norm || map.has(norm)) continue;
        map.set(norm, value);
      }
    }
    return map;
  }

  _compactGet(map, ...aliases) {
    if (!(map instanceof Map) || map.size === 0) return "";
    for (const alias of aliases) {
      const norm = this._normalizeCompactKey(alias);
      if (!norm) continue;
      const value = map.get(norm);
      if (value != null) {
        const trimmed = String(value).trim();
        if (trimmed !== "" && trimmed !== "-") return trimmed;
      }
    }
    return "";
  }

  _extractFirstInteger(value) {
    if (value == null) return "";
    const s = String(value).trim();
    if (!s) return "";
    if (/^0x[0-9a-f]+$/i.test(s)) return String(parseInt(s, 16));
    const m = s.match(/0x[0-9a-f]+|\d+/i);
    if (!m) return "";
    if (/^0x/i.test(m[0])) return String(parseInt(m[0], 16));
    return m[0];
  }

  _compactGetInt(map, ...aliases) {
    for (const alias of aliases) {
      const value = this._compactGet(map, alias);
      const parsed = this._extractFirstInteger(value);
      if (parsed) return parsed;
    }
    return "";
  }

  _normalizeEvtxChannel(channel) {
    const raw = String(channel || "").trim().toLowerCase();
    if (!raw) return "";
    if (raw === "sec" || raw.includes("security")) return "security";
    if (raw === "sys" || raw.includes("system")) return "system";
    if (raw.includes("sysmon")) return "sysmon";
    if (raw === "tasksch" || raw.includes("taskscheduler") || raw.includes("task scheduler")) return "taskscheduler";
    if (raw === "pwsh" || raw.includes("powershell")) return "powershell";
    if (raw === "wmi" || raw.includes("wmi-activity")) return "wmi-activity";
    if (raw.includes("localsessionmanager")) return "localsessionmanager";
    if (raw.includes("remoteconnectionmanager")) return "remoteconnectionmanager";
    return raw;
  }

  _resolveEventChannel(row) {
    const explicit = row?.channel || row?.provider || row?._channel;
    const normalized = this._normalizeEvtxChannel(explicit);
    if (normalized) return normalized;

    const eventId = this._extractFirstInteger(row?.eventId || row?.id);
    if (!eventId) return "";

    const hasLmShape = !!(row?.source || row?.workstation || row?.user || row?.logonType);
    if (eventId === "1149") return "remoteconnectionmanager";
    if (hasLmShape && ["21", "22", "23", "24", "25", "39", "40"].includes(eventId)) return "localsessionmanager";
    if (["1", "6", "7", "11", "12", "13", "14", "19", "20", "21", "25"].includes(eventId)) return "sysmon";
    if (["7040", "7045", "7035", "7036"].includes(eventId)) return "system";
    if (["106", "118", "119", "129", "140", "141", "200"].includes(eventId)) return "taskscheduler";
    if (eventId === "4104") return "powershell";
    if (["4624", "4625", "4634", "4647", "4648", "4657", "4672", "4697", "4698", "4699", "4702", "4720", "4724", "4728", "4732", "4738", "4756", "4769", "4778", "4779", "5136", "5137", "5140", "5141", "5145"].includes(eventId)) return "security";
    return "";
  }

  _evtxChannelMatches(channel, wantedChannels = []) {
    if (!wantedChannels || wantedChannels.length === 0) return true;
    const raw = String(channel || "").toLowerCase();
    const norm = this._normalizeEvtxChannel(channel);
    return wantedChannels.some((wanted) => {
      const needle = String(wanted || "").trim().toLowerCase();
      if (!needle) return false;
      if (raw.includes(needle) || norm.includes(needle)) return true;
      if (needle === "security" && norm === "security") return true;
      if (needle === "system" && norm === "system") return true;
      if (needle === "sysmon" && norm === "sysmon") return true;
      if (needle === "taskscheduler" && norm === "taskscheduler") return true;
      if (needle === "powershell" && norm === "powershell") return true;
      if (needle === "wmi-activity" && norm === "wmi-activity") return true;
      return false;
    });
  }

  _buildCompactAliasBlob(map) {
    if (!(map instanceof Map) || map.size === 0) return "";
    const parts = [];
    const add = (label, ...aliases) => {
      const value = this._compactGet(map, ...aliases);
      if (value) parts.push(`${label}: ${value}`);
    };

    add("ProcessId", "PID", "ProcessId", "NewProcessId");
    add("ParentProcessId", "ParentPID", "ParentProcessId", "CreatorProcessId");
    add("ProcessGuid", "PGUID", "ProcessGuid", "ProcessGUID");
    add("ParentProcessGuid", "ParentPGUID", "ParentProcessGuid", "ParentProcessGUID");
    add("Image", "Proc", "Image", "NewProcessName", "ProcessName");
    add("ParentImage", "ParentImage", "ParentProcessName");
    add("CommandLine", "Cmdline", "CommandLine", "ProcessCommandLine");
    add("TargetUserName", "TgtUser", "TargetUserName", "User");
    add("SubjectUserName", "SubjectUserName", "SrcUser", "User");
    add("TargetDomainName", "TargetDomainName", "Domain");
    add("LogonType", "LogonType", "Type");
    add("IpAddress", "SrcIP", "IpAddress", "SourceNetworkAddress", "ClientAddress");
    add("WorkstationName", "SrcComp", "WorkstationName", "ClientName", "SrcHost");
    add("RemoteHost", "TgtSvr", "TgtHost");
    add("ShareName", "ShareName", "Share");
    add("RelativeTargetName", "RelativeTargetName", "RelTarget");
    add("ServiceName", "Svc", "ServiceName", "param1");
    add("Account", "Acct", "AccountName", "ServiceAccount");
    add("StartType", "StartType", "OldStartType", "NewStartType");
    add("ImagePath", "Path", "ImagePath", "ServiceFileName");
    add("Task", "Task", "TaskName", "Name");
    add("Command", "Command", "Action", "Actions");
    add("TargetObject", "RegKey", "TargetObject", "TgtObj", "ObjectName");
    add("Details", "Details");
    add("ScriptBlockText", "ScriptBlock", "ScriptBlockText");
    add("Path", "Path");
    add("SessionName", "SessionName");
    add("SubStatus", "SubStatus");
    add("MessageNumber", "MessageNumber");
    add("MessageTotal", "MessageTotal");
    add("ScriptBlockId", "ScriptBlockId");
    add("HostApplication", "HostApplication");
    add("TaskContent", "TaskContent", "Content");
    add("Consumer", "Consumer");
    add("Filter", "Filter");
    add("Query", "Query");
    add("Operation", "Operation");
    add("Namespace", "Namespace");
    add("ObjectDN", "ObjectDN");
    add("ObjectClass", "ObjectClass");

    return parts.join(" | ");
  }

  _buildChainsawAliasBlob(row) {
    const parts = [];
    const add = (label, value, options = {}) => {
      const cleaned = this._cleanWrappedField(value, options);
      if (cleaned) parts.push(`${label}: ${cleaned}`);
    };

    add("RuleTitle", row.ruleTitle || row.detectionRule, { lineJoiner: " | " });
    add("Computer", row.computer || row.hostname);
    add("Image", row.image);
    add("CommandLine", row.cmdLine);
    add("TargetFilename", row.targetFilename);
    add("TargetObject", row.targetObject);
    add("Details", row.details);
    add("IpAddress", row.source);
    add("WorkstationName", row.workstation);
    add("TargetUserName", row.user);
    add("LogonType", row.logonType);

    return parts.join(" | ");
  }

  _buildEvtxHaystack(row) {
    const baseParts = [
      row.payload, row.payload2, row.payload3, row.payload4, row.payload5, row.payload6,
      row.mapDesc, row.execInfo, row.details, row.extra, row.ruleTitle, row.detectionRule,
    ].filter(Boolean);
    const compactMap = this._parseCompactKeyValues(row.details, row.extra);
    const aliasBlob = this._buildCompactAliasBlob(compactMap);
    if (aliasBlob) baseParts.push(aliasBlob);
    const chainsawAliasBlob = this._buildChainsawAliasBlob(row);
    if (chainsawAliasBlob) baseParts.push(chainsawAliasBlob);
    return baseParts.join(" | ");
  }

  /**
   * Create a new database for a tab and prepare the schema
   */
  createTab(tabId, headers) {
    dbg("DB", `createTab start`, { tabId, headerCount: headers?.length });
    const dbPath = path.join(
      os.tmpdir(),
      `tle_${tabId}_${crypto.randomBytes(4).toString("hex")}.db`
    );

    const db = new Database(dbPath);
    dbg("DB", `Database opened`, { dbPath });

    try {
    // Register REGEXP function for regex search mode
    let _reCache = null, _rePattern = null;
    db.function("regexp", { deterministic: true }, (pattern, value) => {
      if (pattern == null || value == null) return 0;
      try {
        if (pattern !== _rePattern) { _reCache = new RegExp(pattern, "i"); _rePattern = pattern; }
        return _reCache.test(value) ? 1 : 0;
      } catch { return 0; }
    });

    // Register FUZZY_MATCH function for fuzzy/approximate search
    // Uses n-gram similarity: breaks search term into overlapping character chunks
    // and checks what fraction appear in the text. Fast O(n) per cell.
    db.function("fuzzy_match", { deterministic: true }, (text, term) => {
      if (text == null || term == null) return 0;
      const t = String(text).toLowerCase();
      const s = String(term).toLowerCase();
      if (t.includes(s)) return 1; // exact substring = always match
      if (s.length < 2) return 0;  // single char: exact only
      // Use bigrams for short terms (2-4 chars), trigrams for longer
      const n = s.length < 5 ? 2 : 3;
      const grams = [];
      for (let i = 0; i <= s.length - n; i++) grams.push(s.substring(i, i + n));
      if (grams.length === 0) return 0;
      let hits = 0;
      for (const g of grams) { if (t.includes(g)) hits++; }
      // Adaptive threshold: stricter for short terms, looser for long
      const threshold = s.length < 5 ? 0.7 : 0.6;
      return (hits / grams.length) >= threshold ? 1 : 0;
    });

    // Register extract_date function for histogram — normalizes any timestamp format to yyyy-MM-dd
    const MONTH_MAP = { jan: "01", feb: "02", mar: "03", apr: "04", may: "05", jun: "06", jul: "07", aug: "08", sep: "09", oct: "10", nov: "11", dec: "12" };
    db.function("extract_date", { deterministic: true }, (val) => {
      if (val == null) return null;
      const s = String(val).trim();
      // Fast path: ISO format (avoids regex — called millions of times)
      if (s.length >= 10 && s.charCodeAt(4) === 45 && s.charCodeAt(7) === 45 && s.charCodeAt(0) >= 48 && s.charCodeAt(0) <= 57) return s.substring(0, 10);
      // US date: 02/05/2026 or 02-05-2026
      let m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
      if (m) return `${m[3]}-${m[1].padStart(2,"0")}-${m[2].padStart(2,"0")}`;
      // Month name: "Feb 5th 2026", "February 5, 2026", "5 Feb 2026", etc.
      m = s.match(/^([A-Za-z]+)\s+(\d{1,2})\w*[\s,]+(\d{4})/);
      if (m) { const mo = MONTH_MAP[m[1].substring(0,3).toLowerCase()]; if (mo) return `${m[3]}-${mo}-${m[2].padStart(2,"0")}`; }
      // "5 Feb 2026" or "05-Feb-2026"
      m = s.match(/^(\d{1,2})[\s\-]([A-Za-z]+)[\s\-](\d{4})/);
      if (m) { const mo = MONTH_MAP[m[2].substring(0,3).toLowerCase()]; if (mo) return `${m[3]}-${mo}-${m[1].padStart(2,"0")}`; }
      // Unix timestamp (seconds since epoch, 10 digits)
      if (/^\d{10}(\.\d+)?$/.test(s)) { const d = new Date(parseFloat(s) * 1000); if (!isNaN(d)) return d.toISOString().substring(0, 10); }
      // Unix timestamp (milliseconds, 13 digits)
      if (/^\d{13}$/.test(s)) { const d = new Date(parseInt(s)); if (!isNaN(d)) return d.toISOString().substring(0, 10); }
      // Excel serial date (e.g. 45566 = 2024-10-05, 37685.41 = 2003-03-10)
      if (/^\d{1,5}(\.\d+)?$/.test(s)) {
        const serial = parseFloat(s);
        if (serial >= 1 && serial <= 73050) {
          const d = new Date(Math.round((serial - 25569) * 86400000));
          if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100) return d.toISOString().substring(0, 10);
        }
      }
      // Fallback: try JS Date parse
      const d = new Date(s);
      if (!isNaN(d) && d.getFullYear() > 1970 && d.getFullYear() < 2100) return d.toISOString().substring(0, 10);
      return null;
    });

    // Register extract_datetime_minute — normalizes any timestamp to yyyy-MM-dd HH:mm
    db.function("extract_datetime_minute", { deterministic: true }, (val) => {
      if (val == null) return null;
      const s = String(val).trim();
      // Fast path: ISO format (avoids regex — called millions of times)
      // Check for "YYYY-MM-DD HH:MM" or "YYYY-MM-DDTHH:MM" pattern by char codes
      if (s.length >= 16 && s.charCodeAt(4) === 45 && s.charCodeAt(7) === 45 && s.charCodeAt(0) >= 48 && s.charCodeAt(0) <= 57) {
        const sep = s.charCodeAt(10); // space (32) or T (84)
        if ((sep === 32 || sep === 84) && s.charCodeAt(13) === 58) return `${s.substring(0, 10)} ${s.substring(11, 16)}`;
      }
      // Non-ISO fallback with regex
      let m = s.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
      if (m) return `${m[1]} ${m[2]}`;
      // US date with time: 02/05/2026 14:30:00 or 02-05-2026 2:30 PM
      m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?/i);
      if (m) {
        let hh = parseInt(m[4], 10);
        if (m[7]) { const ap = m[7].toUpperCase(); if (ap === "PM" && hh < 12) hh += 12; if (ap === "AM" && hh === 12) hh = 0; }
        return `${m[3]}-${m[1].padStart(2,"0")}-${m[2].padStart(2,"0")} ${String(hh).padStart(2,"0")}:${m[5]}`;
      }
      // Month name with time: "Mar 4th 2026 12:59:15", "February 5, 2026 09:30", etc.
      m = s.match(/^([A-Za-z]+)\s+(\d{1,2})\w*[\s,]+(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?/i);
      if (m) {
        const mo = MONTH_MAP[m[1].substring(0,3).toLowerCase()];
        if (mo) {
          let hh = parseInt(m[4], 10);
          if (m[7]) { const ap = m[7].toUpperCase(); if (ap === "PM" && hh < 12) hh += 12; if (ap === "AM" && hh === 12) hh = 0; }
          return `${m[3]}-${mo}-${m[2].padStart(2,"0")} ${String(hh).padStart(2,"0")}:${m[5]}`;
        }
      }
      // "5 Feb 2026 14:30:00" or "05-Feb-2026 14:30"
      m = s.match(/^(\d{1,2})[\s\-]([A-Za-z]+)[\s\-](\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?/i);
      if (m) {
        const mo = MONTH_MAP[m[2].substring(0,3).toLowerCase()];
        if (mo) {
          let hh = parseInt(m[4], 10);
          if (m[7]) { const ap = m[7].toUpperCase(); if (ap === "PM" && hh < 12) hh += 12; if (ap === "AM" && hh === 12) hh = 0; }
          return `${m[3]}-${mo}-${m[1].padStart(2,"0")} ${String(hh).padStart(2,"0")}:${m[5]}`;
        }
      }
      // Month name without time — date only, default to 00:00
      m = s.match(/^([A-Za-z]+)\s+(\d{1,2})\w*[\s,]+(\d{4})/);
      if (m) { const mo = MONTH_MAP[m[1].substring(0,3).toLowerCase()]; if (mo) return `${m[3]}-${mo}-${m[2].padStart(2,"0")} 00:00`; }
      m = s.match(/^(\d{1,2})[\s\-]([A-Za-z]+)[\s\-](\d{4})/);
      if (m) { const mo = MONTH_MAP[m[2].substring(0,3).toLowerCase()]; if (mo) return `${m[3]}-${mo}-${m[1].padStart(2,"0")} 00:00`; }
      // Excel serial date (e.g. 45566.833 = 2024-10-05 20:00)
      if (/^\d{1,5}(\.\d+)?$/.test(s)) {
        const serial = parseFloat(s);
        if (serial >= 1 && serial <= 73050) {
          const d = new Date((serial - 25569) * 86400000);
          if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100) {
            const iso = d.toISOString();
            return `${iso.substring(0, 10)} ${iso.substring(11, 16)}`;
          }
        }
      }
      // Fallback: try JS Date parse
      const d = new Date(s);
      if (!isNaN(d) && d.getFullYear() > 1970 && d.getFullYear() < 2100) {
        const iso = d.toISOString();
        return `${iso.substring(0, 10)} ${iso.substring(11, 16)}`;
      }
      return null;
    });

    // Register sort_datetime — normalizes any timestamp format to sortable ISO string (yyyy-MM-dd HH:mm:ss.fff)
    // Used in ORDER BY for timestamp columns to ensure correct chronological sort regardless of input format
    db.function("sort_datetime", { deterministic: true }, (val) => {
      if (val == null || val === "") return null;
      const s = String(val).trim();
      // Fast path: ISO format (most common in forensic data) — already sortable
      if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s)) return s.replace("T", " ");
      // ISO date-only: 2026-02-05
      if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s + " 00:00:00";
      // US date: M/D/YYYY or MM/DD/YYYY with optional time
      let m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\s*(.*)/);
      if (m) {
        const rest = m[4] ? " " + m[4].replace(/\s*[AP]M$/i, (ap) => {
          // Convert 12h to 24h
          const parts = m[4].replace(/\s*[AP]M$/i, "").trim().split(":");
          if (parts.length >= 2) {
            let h = parseInt(parts[0]);
            if (/PM$/i.test(ap) && h !== 12) h += 12;
            if (/AM$/i.test(ap) && h === 12) h = 0;
            return ""; // will be handled below
          }
          return "";
        }) : " 00:00:00";
        // Re-parse with AM/PM handling
        let timePart = m[4] || "00:00:00";
        const ampm = timePart.match(/\s*([AP]M)\s*$/i);
        timePart = timePart.replace(/\s*[AP]M\s*$/i, "").trim();
        if (ampm && timePart) {
          const tp = timePart.split(":");
          let h = parseInt(tp[0]) || 0;
          if (/PM/i.test(ampm[1]) && h !== 12) h += 12;
          if (/AM/i.test(ampm[1]) && h === 12) h = 0;
          tp[0] = String(h).padStart(2, "0");
          timePart = tp.join(":");
        }
        return `${m[3]}-${m[1].padStart(2,"0")}-${m[2].padStart(2,"0")} ${timePart || "00:00:00"}`;
      }
      // Unix timestamp (seconds, 10 digits)
      if (/^\d{10}(\.\d+)?$/.test(s)) {
        const d = new Date(parseFloat(s) * 1000);
        if (!isNaN(d)) return d.toISOString().replace("T", " ").replace("Z", "");
      }
      // Unix timestamp (milliseconds, 13 digits)
      if (/^\d{13}$/.test(s)) {
        const d = new Date(parseInt(s));
        if (!isNaN(d)) return d.toISOString().replace("T", " ").replace("Z", "");
      }
      // Excel serial date
      if (/^\d{1,5}(\.\d+)?$/.test(s)) {
        const serial = parseFloat(s);
        if (serial >= 1 && serial <= 73050) {
          const d = new Date(Math.round((serial - 25569) * 86400000));
          if (!isNaN(d.getTime()) && d.getFullYear() >= 1900 && d.getFullYear() <= 2100)
            return d.toISOString().replace("T", " ").replace("Z", "");
        }
      }
      // Fallback: JS Date parse
      const d = new Date(s);
      if (!isNaN(d) && d.getFullYear() > 1970 && d.getFullYear() < 2100)
        return d.toISOString().replace("T", " ").replace("Z", "");
      // Unparseable — return original so it still sorts somehow
      return s;
    });

    // page_size MUST be set before any tables are created
    // 64KB pages: fewer B-tree nodes, faster bulk writes & index creation
    db.pragma("page_size = 65536");

    // Scale pragmas based on file size — reduce memory for very large files to prevent OOM
    const fileSize = this._fileSizeHint || 0;
    const isLargeFile = fileSize > 5 * 1024 * 1024 * 1024; // >5GB
    this._fileSizeHint = 0; // consume the hint

    // Performance pragmas for bulk import (maximise write throughput)
    db.pragma("journal_mode = OFF"); // no journal — fastest writes (temp DB, crash = re-import)
    db.pragma("synchronous = OFF");
    db.pragma(`cache_size = ${isLargeFile ? -262144 : -1048576}`); // 256MB or 1GB write cache
    db.pragma(`temp_store = ${isLargeFile ? "FILE" : "MEMORY"}`); // disk temp for large files
    db.pragma("mmap_size = 0"); // disable mmap during import (write-only)
    db.pragma("locking_mode = EXCLUSIVE"); // single-user, avoid lock overhead
    db.pragma("threads = 4"); // parallel sort for internal operations

    // Sanitize headers for SQL column names
    const safeCols = headers.map((h, i) => ({
      original: h,
      safe: `c${i}`,
    }));

    // Create main data table
    const colDefs = safeCols.map((c) => `${c.safe} TEXT`).join(", ");
    db.exec(`CREATE TABLE data (rowid INTEGER PRIMARY KEY, ${colDefs})`);

    // FTS5 table created lazily on first search (avoid DDL overhead during import)

    // Create bookmarks table
    db.exec(`CREATE TABLE bookmarks (rowid INTEGER PRIMARY KEY)`);

    // Create tags table
    db.exec(`CREATE TABLE tags (rowid INTEGER, tag TEXT, PRIMARY KEY(rowid, tag))`);
    db.exec(`CREATE INDEX idx_tags_tag ON tags(tag, rowid)`);
    db.exec(`CREATE INDEX idx_tags_rowid ON tags(rowid)`);

    // Create color rules table
    db.exec(
      `CREATE TABLE color_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        col_name TEXT, condition TEXT, value TEXT,
        bg_color TEXT, fg_color TEXT
      )`
    );

    // Detect timestamp columns based on header names
    const tsColumns = new Set();
    headers.forEach((h) => {
      if (
        /(time|date|timestamp|created|modified|accessed|when|start|end|written)/i.test(h)
      ) {
        tsColumns.add(h);
      }
    });

    // Prepare bulk insert statement
    const colList = safeCols.map((c) => c.safe).join(", ");
    const placeholders = safeCols.map(() => "?").join(", ");
    const insertStmt = db.prepare(
      `INSERT INTO data (${colList}) VALUES (${placeholders})`
    );

    // Prepare multi-row INSERT for faster bulk loading
    // SQLite limit is 32766 host parameters — use full capacity (no artificial 1000 cap)
    const multiRowCount = Math.max(1, Math.floor(32766 / safeCols.length));
    let multiInsertStmt = null;
    if (multiRowCount > 1) {
      const singleRow = `(${placeholders})`;
      const multiValues = Array(multiRowCount).fill(singleRow).join(",");
      multiInsertStmt = db.prepare(
        `INSERT INTO data (${colList}) VALUES ${multiValues}`
      );
    }

    // Pre-allocate flat params array (reused across all insertBatchArrays calls)
    const insertFlat = multiRowCount > 1 ? new Array(multiRowCount * safeCols.length) : null;

    // Pre-cache bookmark/tag prepared statements (avoids re-prepare per operation)
    const bmCheckStmt = db.prepare("SELECT rowid FROM bookmarks WHERE rowid = ?");
    const bmInsertStmt = db.prepare("INSERT OR IGNORE INTO bookmarks (rowid) VALUES (?)");
    const bmDeleteStmt = db.prepare("DELETE FROM bookmarks WHERE rowid = ?");
    const bmCountStmt = db.prepare("SELECT COUNT(*) as cnt FROM bookmarks");
    const tagInsertStmt = db.prepare("INSERT OR IGNORE INTO tags (rowid, tag) VALUES (?, ?)");
    const tagDeleteStmt = db.prepare("DELETE FROM tags WHERE rowid = ? AND tag = ?");

    const meta = {
      tabId,
      db,
      dbPath,
      headers,
      safeCols,
      tsColumns,
      rowCount: 0,
      ftsReady: false,
      isLargeFile,
      insertStmt,
      multiInsertStmt,
      multiRowCount,
      insertFlat,
      bmCheckStmt, bmInsertStmt, bmDeleteStmt, bmCountStmt,
      tagInsertStmt, tagDeleteStmt,
      colMap: Object.fromEntries(safeCols.map((c) => [c.original, c.safe])),
      reverseColMap: Object.fromEntries(safeCols.map((c) => [c.safe, c.original])),
    };

    this.databases.set(tabId, meta);
    dbg("DB", `createTab OK`, { tabId, colCount: headers.length, tsColumns: [...tsColumns] });
    return { tabId, headers, tsColumns: [...tsColumns] };
    } catch (err) {
      dbg("DB", `createTab FAILED`, { tabId, error: err.message, stack: err.stack });
      // Clean up on failure — prevent leaked DB connections and orphaned temp files
      try { db.close(); } catch (_) {}
      try { fs.unlinkSync(dbPath); } catch (_) {}
      throw err;
    }
  }

  /**
   * Insert a batch of rows as arrays (fast path — used by parser)
   * Each row is a pre-built array of values in column order.
   * No object allocation or property lookup per row.
   */
  insertBatchArrays(tabId, rows) {
    const meta = this.databases.get(tabId);
    if (!meta) throw new Error(`Tab ${tabId} not found`);

    const singleStmt = meta.insertStmt;
    const multiStmt = meta.multiInsertStmt;
    const multiN = meta.multiRowCount;
    const colCount = meta.headers.length;
    const flat = meta.insertFlat; // pre-allocated in createTab, reused across all calls

    const tx = meta.db.transaction(() => {
      let i = 0;

      if (multiStmt && multiN > 1 && flat) {
        while (i + multiN <= rows.length) {
          for (let r = 0; r < multiN; r++) {
            const row = rows[i + r];
            const off = r * colCount;
            for (let c = 0; c < colCount; c++) {
              flat[off + c] = row[c];
            }
          }
          multiStmt.run(flat);
          i += multiN;
        }
      }

      // Remainder with single-row inserts
      while (i < rows.length) {
        singleStmt.run(rows[i]);
        i++;
      }
    });
    tx();

    meta.rowCount += rows.length;
    return meta.rowCount;
  }

  /**
   * Insert a batch of rows as objects (legacy — used by session restore)
   */
  insertBatch(tabId, rows) {
    const meta = this.databases.get(tabId);
    if (!meta) throw new Error(`Tab ${tabId} not found`);

    const stmt = meta.insertStmt;
    const hdrs = meta.headers;
    const tx = meta.db.transaction(() => {
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const values = new Array(hdrs.length);
        for (let c = 0; c < hdrs.length; c++) {
          values[c] = row[hdrs[c]] ?? "";
        }
        stmt.run(values);
      }
    });
    tx();

    meta.rowCount += rows.length;
    return meta.rowCount;
  }

  /**
   * Finalize import: detect column types, switch to query mode.
   * Indexes, FTS, and ANALYZE are all deferred to async background builds
   * so the UI becomes interactive immediately after import completes.
   */
  finalizeImport(tabId) {
    dbg("DB", `finalizeImport start`, { tabId });
    const meta = this.databases.get(tabId);
    if (!meta) { dbg("DB", `finalizeImport: no meta for tab`); return; }

    const db = meta.db;

    // FTS index is built lazily on first search — skip here for fast import.
    meta.ftsReady = false;

    // Sort indexes are built asynchronously after import — skip here.
    meta.indexedCols = new Set();
    meta.indexesReady = false;
    meta.indexesBuilding = false;

    // Detect numeric columns (fast — only samples 100 rows)
    const sampleRows = db
      .prepare(
        `SELECT ${meta.safeCols.map((c) => c.safe).join(", ")} FROM data LIMIT 100`
      )
      .all();

    meta.numericColumns = new Set();
    meta.safeCols.forEach((col) => {
      // Skip columns already detected as timestamps — parseFloat("2026-01-17 01:26:27")
      // returns 2026 (the year), falsely classifying timestamps as numeric.
      if (meta.tsColumns.has(col.original)) return;
      const values = sampleRows
        .map((r) => r[col.safe])
        .filter((v) => v && v.trim());
      if (values.length > 0) {
        // Use Number() instead of parseFloat() — Number() requires the ENTIRE string
        // to be a valid number, preventing false positives like "2026-01-17" → 2026
        const numCount = values.filter((v) => v.trim() !== "" && !isNaN(Number(v.trim()))).length;
        if (numCount / values.length > 0.8) {
          meta.numericColumns.add(col.original);
        }
      }
    });

    // Minimal pragmas so initial queries work while background builds run.
    // buildIndexesAsync/buildFtsAsync set their own aggressive pragmas and
    // restore full query mode (WAL + mmap + 256MB cache) when they finish.
    db.pragma("journal_mode = WAL"); // need WAL for concurrent reads during build
    db.pragma("synchronous = NORMAL");
    db.pragma("cache_size = -262144"); // 256MB cache for queries

    // Skip ANALYZE here — run after async index build completes

    return {
      rowCount: meta.rowCount,
      headers: meta.headers,
      tsColumns: [...meta.tsColumns],
      numericColumns: [...meta.numericColumns],
    };
  }

  /**
   * Build column sort index on demand (called on first sort of that column).
   * Deferred from import to keep file open near-instant.
   */
  _ensureIndex(tabId, colName) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    const safeCol = meta.colMap[colName];
    if (!safeCol || meta.indexedCols.has(safeCol)) return;
    try {
      // Temporarily tune pragmas for fast index build (same as buildIndexesAsync)
      meta.db.pragma("synchronous = OFF");
      meta.db.pragma("threads = 8");
      meta.db.pragma("mmap_size = 0");
      const isLarge = meta.rowCount > 5000000;
      meta.db.pragma(`cache_size = ${isLarge ? -262144 : -1048576}`);

      const collation = (meta.numericColumns && meta.numericColumns.has(colName)) ? "BINARY" : "NOCASE";
      meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${safeCol} ON data(${safeCol} COLLATE ${collation})`);
      // Timestamp columns: expression index so ORDER BY sort_datetime(col)
      // uses the index instead of calling JS per-row.
      if (meta.tsColumns.has(colName)) {
        meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_sort_${safeCol} ON data(sort_datetime(${safeCol}))`);
      }

      // Restore normal query pragmas
      meta.db.pragma("synchronous = NORMAL");
      meta.db.pragma("cache_size = -262144");
      meta.db.pragma("mmap_size = 536870912");
    } catch (e) {
      // Restore pragmas even on failure
      try { meta.db.pragma("synchronous = NORMAL"); } catch (_) {}
      try { meta.db.pragma("mmap_size = 536870912"); } catch (_) {}
    }
    meta.indexedCols.add(safeCol);
  }

  /**
   * Build FTS index on demand (called on first search).
   * If the async chunked build is in progress, this is a no-op (search
   * falls back to LIKE until FTS is ready). If it was never started
   * (e.g. session restore), builds synchronously as a fallback.
   */
  _ensureFts(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta || meta.ftsReady) return;
    // If async build is in progress, don't block — search will use LIKE fallback
    if (meta.ftsBuilding) return;

    const colList = meta.safeCols.map((c) => c.safe).join(", ");

    // Create FTS5 table if it doesn't exist yet
    if (!meta.ftsCreated) {
      meta.db.exec(
        `CREATE VIRTUAL TABLE IF NOT EXISTS data_fts USING fts5(${colList}, content=data, content_rowid=rowid)`
      );
      meta.ftsCreated = true;
    }

    meta.db.exec(
      `INSERT INTO data_fts(rowid, ${colList}) SELECT rowid, ${colList} FROM data`
    );
    meta.db.exec(`INSERT INTO data_fts(data_fts) VALUES('optimize')`);
    meta.ftsReady = true;
  }

  /**
   * Build FTS index asynchronously in chunks.
   * Yields to the event loop between chunks so IPC queries remain responsive.
   * Called automatically after finalizeImport — no UI hang.
   *
   * @param {string} tabId
   * @param {Function} onProgress - ({ indexed, total, done }) callback per chunk
   * @returns {Promise<void>}
   */
  buildFtsAsync(tabId, onProgress) {
    const meta = this.databases.get(tabId);
    if (!meta || meta.ftsReady || meta.ftsBuilding) return Promise.resolve();
    meta.ftsBuilding = true;

    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    const db = meta.db;

    // Create FTS5 virtual table
    if (!meta.ftsCreated) {
      db.exec(
        `CREATE VIRTUAL TABLE IF NOT EXISTS data_fts USING fts5(${colList}, content=data, content_rowid=rowid)`
      );
      meta.ftsCreated = true;
    }

    const totalRows = meta.rowCount || db.prepare("SELECT COUNT(*) as cnt FROM data").get().cnt;
    // 300k rows per chunk — keeps each blocking segment ~2-4s so UI stays responsive
    const CHUNK = 300000;
    let lastRowid = 0;

    // Aggressive pragmas for FTS build — keep WAL mode so concurrent reads
    // (queryRows, histogram, etc.) remain safe during the build.
    // Scale down for large files to prevent OOM
    const large = meta.isLargeFile;
    db.pragma("synchronous = OFF");
    db.pragma(`cache_size = ${large ? -262144 : -1048576}`); // 256MB or 1GB
    db.pragma(`temp_store = ${large ? "FILE" : "MEMORY"}`);
    db.pragma("threads = 8"); // parallel sort/merge

    // Send initial progress so the UI can show the FTS overlay immediately
    if (onProgress) onProgress({ indexed: 0, total: totalRows, done: false });

    return new Promise((resolve) => {
      const insertChunk = () => {
        // Tab may have been closed while building — check both map and flag
        if (meta.closed || !this.databases.has(tabId)) {
          meta.ftsBuilding = false;
          resolve();
          return;
        }

        try {
          const inserted = db.prepare(
            `INSERT INTO data_fts(rowid, ${colList}) SELECT rowid, ${colList} FROM data WHERE rowid > ? ORDER BY rowid LIMIT ?`
          ).run(lastRowid, CHUNK);

          // Track actual last rowid inserted (not fixed increment) —
          // handles non-contiguous rowids correctly
          if (inserted.changes > 0) {
            const last = db.prepare(`SELECT MAX(rowid) as m FROM data_fts`).get();
            lastRowid = last?.m || lastRowid + CHUNK;
          }
          const indexed = Math.min(lastRowid, totalRows);

          if (inserted.changes < CHUNK) {
            // All rows indexed — run ANALYZE now that all indexes + FTS exist
            try { db.exec("ANALYZE"); } catch (e) { dbg("DB", `ANALYZE failed`, { error: e.message }); }

            // Restore conservative query-mode pragmas
            db.pragma("synchronous = NORMAL");
            db.pragma("cache_size = -262144"); // 256MB for queries
            db.pragma("mmap_size = 536870912"); // 512MB mmap for reads
            try { db.pragma("wal_checkpoint(PASSIVE)"); } catch (e) { /* ignore */ }
            meta.ftsReady = true;
            meta.ftsBuilding = false;
            if (onProgress) onProgress({ indexed: totalRows, total: totalRows, done: true });
            resolve();
          } else {
            if (onProgress) onProgress({ indexed, total: totalRows, done: false });
            // Yield to event loop before next chunk — keeps UI responsive
            setImmediate(insertChunk);
          }
        } catch (e) {
          // DB handle was closed between our check and the operation
          dbg("DB", `buildFtsAsync chunk failed (tab likely closed)`, { tabId, error: e.message });
          meta.ftsBuilding = false;
          resolve();
        }
      };

      // Defer first chunk — let the UI render the FTS overlay first
      setImmediate(insertChunk);
    });
  }

  /**
   * Build column indexes asynchronously after import.
   * Yields to the event loop between each index so IPC queries remain responsive.
   * Called automatically after finalizeImport — the UI is already interactive.
   *
   * @param {string} tabId
   * @param {Function} onProgress - ({ built, total, done, currentCol }) callback per index
   * @returns {Promise<void>}
   */
  buildIndexesAsync(tabId, onProgress) {
    const meta = this.databases.get(tabId);
    if (!meta || meta.indexesReady || meta.indexesBuilding) return Promise.resolve();
    meta.indexesBuilding = true;

    const allCols = meta.safeCols.filter((c) => !meta.indexedCols.has(c.safe));

    // Prioritize timestamp columns first — users typically sort by time immediately
    const tsSet_ = meta.tsColumns || new Set();
    allCols.sort((a, b) => {
      const aTs = tsSet_.has(a.original) ? 0 : 1;
      const bTs = tsSet_.has(b.original) ? 0 : 1;
      return aTs - bTs;
    });

    // Pre-filter: skip columns with uniform values (cardinality ≤ 1)
    // Sample-based: check first + middle + last 100 rows instead of full DISTINCT scan
    const cols = [];
    const skippedCols = [];
    const midOffset = Math.max(0, Math.floor(meta.rowCount / 2));
    for (const col of allCols) {
      try {
        const distinct = meta.db
          .prepare(`SELECT COUNT(*) AS c FROM (SELECT DISTINCT ${col.safe} FROM (SELECT ${col.safe} FROM (SELECT * FROM data LIMIT 100) UNION ALL SELECT ${col.safe} FROM (SELECT * FROM data LIMIT 100 OFFSET ${midOffset}) UNION ALL SELECT ${col.safe} FROM (SELECT * FROM data ORDER BY rowid DESC LIMIT 100)))`)
          .get();
        if (distinct && distinct.c <= 1) {
          skippedCols.push(col.original);
          meta.indexedCols.add(col.safe); // Mark as "done" so _ensureIndex won't rebuild
          continue;
        }
      } catch { /* If check fails, build the index anyway */ }
      cols.push(col);
    }
    if (skippedCols.length > 0) {
      dbg("DB", `buildIndexesAsync skipping uniform columns`, { skipped: skippedCols });
    }

    // Determine collation per column: binary for numeric/timestamp, NOCASE for text
    const numericSet = meta.numericColumns || new Set();
    const tsSet = meta.tsColumns || new Set();

    const total = cols.length;
    let built = 0;

    dbg("DB", `buildIndexesAsync start`, { tabId, total, skipped: skippedCols.length });

    // Aggressive pragmas for index build — keep WAL mode so concurrent reads
    // (queryRows, histogram, etc.) remain safe during the build.
    // Scale down for large files to prevent OOM
    const large = meta.isLargeFile;
    meta.db.pragma("synchronous = OFF");
    meta.db.pragma(`cache_size = ${large ? -262144 : -1048576}`); // 256MB or 1GB
    meta.db.pragma(`temp_store = ${large ? "FILE" : "MEMORY"}`);
    meta.db.pragma("threads = 8"); // parallel sort for CREATE INDEX
    meta.db.pragma("mmap_size = 0"); // disable mmap — rely on cache (write-heavy)

    // Send initial progress so the UI overlay renders immediately
    if (onProgress) onProgress({ built: 0, total, done: false, currentCol: cols[0]?.original });

    return new Promise((resolve) => {
      const buildNext = () => {
        // Tab may have been closed while building — check both map and flag
        if (meta.closed || !this.databases.has(tabId)) {
          meta.indexesBuilding = false;
          resolve();
          return;
        }

        if (built >= cols.length) {
          // ANALYZE deferred to after FTS build completes — stats cover all indexes
          try {
            // Restore conservative query-mode pragmas
            meta.db.pragma("synchronous = NORMAL");
            meta.db.pragma("cache_size = -262144"); // 256MB for queries
            meta.db.pragma("mmap_size = 536870912"); // 512MB mmap for reads
            try { meta.db.pragma("wal_checkpoint(PASSIVE)"); } catch (e) { /* ignore */ }
          } catch (e) {
            dbg("DB", `buildIndexesAsync pragma restore failed (tab likely closed)`, { tabId, error: e.message });
          }

          meta.indexesReady = true;
          meta.indexesBuilding = false;
          dbg("DB", `buildIndexesAsync complete`, { tabId, total });
          if (onProgress) onProgress({ built: total, total, done: true, currentCol: null });
          resolve();
          return;
        }

        try {
          // Build up to 5 indexes per yield — each CREATE INDEX on 1M+ rows takes 1-3s,
          // batching reduces total build time ~50% while keeping UI responsive
          const BATCH = 5;
          for (let b = 0; b < BATCH && built < cols.length; b++) {
            if (meta.closed) break; // re-check between indexes
            const col = cols[built];
            try {
              // Use binary collation for numeric/timestamp columns (faster sort),
              // COLLATE NOCASE for text columns (case-insensitive filter/sort)
              const useBinary = numericSet.has(col.original) || tsSet.has(col.original);
              if (useBinary) {
                meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${col.safe} ON data(${col.safe})`);
              } else {
                meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_${col.safe} ON data(${col.safe} COLLATE NOCASE)`);
              }
              // Timestamp columns: add expression index on sort_datetime() so
              // ORDER BY sort_datetime(col) can use the index instead of calling
              // the JS function per-row during sort.
              if (tsSet.has(col.original)) {
                meta.db.exec(`CREATE INDEX IF NOT EXISTS idx_sort_${col.safe} ON data(sort_datetime(${col.safe}))`);
              }
              meta.indexedCols.add(col.safe);
            } catch (e) {
              dbg("DB", `index creation failed for ${col.original}`, { error: e.message });
            }
            built++;
          }
        } catch (e) {
          // DB handle was closed between our check and the operation
          dbg("DB", `buildIndexesAsync batch failed (tab likely closed)`, { tabId, error: e.message });
          meta.indexesBuilding = false;
          resolve();
          return;
        }

        if (onProgress) onProgress({ built, total, done: false, currentCol: cols[Math.min(built, cols.length) - 1]?.original });

        // Yield to event loop after each batch — keeps UI responsive
        setImmediate(buildNext);
      };

      // Defer first index — let the UI render the overlay first
      setImmediate(buildNext);
    });
  }

  /**
   * Check if background builds (indexes/FTS) are running on a tab.
   * Bookmark/tag mutations are blocked during builds to avoid write contention.
   */
  _isBuilding(tabId) {
    const meta = this.databases.get(tabId);
    return meta && (meta.indexesBuilding || meta.ftsBuilding);
  }

  /**
   * Query rows with filtering, sorting, and pagination
   * This is the main query method — only fetches the visible window
   */
  queryRows(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { rows: [], totalFiltered: 0 };

    const {
      offset = 0,
      limit = -1,
      sortCol = null,
      sortDir = "asc",
      searchTerm = "",
      searchMode = "mixed",
      searchCondition = "contains",
      columnFilters = {},
      checkboxFilters = {},
      bookmarkedOnly = false,
      tagFilter = null,
      groupCol = null,
      groupValue = undefined,
      groupFilters = [],
      dateRangeFilters = {},
      advancedFilters = [],
      // IQL filter passthrough — WHERE SQL fragment from runIqlQuery
      extraWhere = null,
    } = options;

    const db = meta.db;
    const params = [];
    let whereConditions = [];

    // ── Standard filters (column, checkbox, date range, bookmarks, tags, advanced, search) ──
    this._applyStandardFilters(options, meta, whereConditions, params);

    // ── IQL extra WHERE — injected by the query bar ──────────────────────────
    if (extraWhere && extraWhere.sql) {
      whereConditions.push(extraWhere.sql);
      params.push(...(extraWhere.params || []));
    }

    // ── Group filter (single - legacy) — queryRows-specific ──
    if (groupCol && groupValue !== undefined) {
      const safeCol = meta.colMap[groupCol];
      if (safeCol) {
        whereConditions.push(`${safeCol} = ?`);
        params.push(groupValue);
      }
    }

    // ── Multi-level group filters — queryRows-specific ──────
    for (const gf of groupFilters) {
      const safeCol = meta.colMap[gf.col];
      if (safeCol) {
        whereConditions.push(`${safeCol} = ?`);
        params.push(gf.value);
      }
    }

    const whereClause =
      whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")}`
        : "";

    // ── Count total filtered rows (cached by filter signature) ──
    const filterSig = whereClause + "|" + JSON.stringify(params);
    let totalFiltered;
    if (meta._countCache && meta._countCache.sig === filterSig) {
      totalFiltered = meta._countCache.cnt;
    } else {
      const countSql = `SELECT COUNT(*) as cnt FROM data ${whereClause}`;
      totalFiltered = db.prepare(countSql).get(...params).cnt;
      meta._countCache = { sig: filterSig, cnt: totalFiltered };
    }

    // ── Sort ───────────────────────────────────────────────────
    let orderClause = "ORDER BY data.rowid";
    if (sortCol) {
      if (sortCol === "__vt__") {
        // Virtual VT column — sort by verdict tag priority (malicious first in ASC)
        const dir = sortDir === "desc" ? "DESC" : "ASC";
        orderClause = `ORDER BY COALESCE((SELECT MIN(CASE tag WHEN 'VT: Malicious' THEN 1 WHEN 'VT: Suspicious' THEN 2 WHEN 'VT: Clean' THEN 3 ELSE 4 END) FROM tags WHERE tags.rowid = data.rowid AND tag LIKE 'VT:%'), 5) ${dir}, data.rowid ASC`;
      } else {
        const safeCol = meta.colMap[sortCol];
        if (safeCol) {
          // Lazy-build index on first sort for this column
          this._ensureIndex(tabId, sortCol);
          const dir = sortDir === "desc" ? "DESC" : "ASC";
          // Timestamp columns checked first (takes priority over numeric — prevents
          // false-positive numeric detection from breaking timestamp sorting)
          if (meta.tsColumns.has(sortCol)) {
            orderClause = `ORDER BY sort_datetime(${safeCol}) ${dir}`;
          } else if (meta.numericColumns.has(sortCol)) {
            orderClause = `ORDER BY CAST(${safeCol} AS REAL) ${dir}`;
          } else {
            orderClause = `ORDER BY ${safeCol} COLLATE NOCASE ${dir}`;
          }
        }
      }
    }

    // ── Fetch window ───────────────────────────────────────────
    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    const querySql = `SELECT data.rowid as _rowid, ${colList} FROM data ${whereClause} ${orderClause} LIMIT ? OFFSET ?`;
    const queryParams = [...params, limit, offset];

    const rawRows = db.prepare(querySql).all(...queryParams);

    // Map back to original column names — tight loop, no closures
    const colCount = meta.safeCols.length;
    const rows = new Array(rawRows.length);
    for (let r = 0; r < rawRows.length; r++) {
      const raw = rawRows[r];
      const row = { __idx: raw._rowid };
      for (let c = 0; c < colCount; c++) {
        row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] ?? "";
      }
      rows[r] = row;
    }

    // Get bookmark + tag data for fetched rows in batches
    // (SQLite max variable limit is ~32766, so batch large sets)
    const rowIds = rawRows.map((r) => r._rowid);
    const bookmarkedSet = new Set();
    const rowTags = {};
    const BATCH = 5000;
    for (let i = 0; i < rowIds.length; i += BATCH) {
      const batch = rowIds.slice(i, i + BATCH);
      const placeholders = batch.map(() => "?").join(",");
      try {
        const combined = db.prepare(
          `SELECT rowid, 'b' as t, '' as tag FROM bookmarks WHERE rowid IN (${placeholders})` +
          ` UNION ALL SELECT rowid, 't', tag FROM tags WHERE rowid IN (${placeholders})`
        ).all(...batch, ...batch);
        for (const r of combined) {
          if (r.t === "b") bookmarkedSet.add(r.rowid);
          else { if (!rowTags[r.rowid]) rowTags[r.rowid] = []; rowTags[r.rowid].push(r.tag); }
        }
      } catch (e) {
        // Fail gracefully — return rows without bookmark/tag decoration
      }
    }

    return {
      rows,
      totalFiltered,
      totalRows: meta.rowCount,
      bookmarkedRows: [...bookmarkedSet],
      rowTags,
    };
  }

  /**
   * Apply global search conditions to a WHERE clause.
   * Handles FTS, regex, and column-specific search uniformly.
   */
  _applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition = "contains") {
    if (!searchTerm.trim()) return;

    // Fuzzy search — uses custom fuzzy_match() SQLite function
    if (searchCondition === "fuzzy" && searchMode !== "regex") {
      const terms = searchMode === "exact" ? [searchTerm.trim()] : searchTerm.trim().split(/\s+/).filter(Boolean);
      const joinOp = searchMode === "or" ? " OR " : " AND ";
      const termConditions = terms.map((term) => {
        const colConds = meta.safeCols.map((c) => {
          params.push(term);
          return `fuzzy_match(${c.safe}, ?)`;
        });
        return `(${colConds.join(" OR ")})`;
      });
      whereConditions.push(`(${termConditions.join(joinOp)})`);
      return;
    }

    // Non-default conditions bypass FTS — use direct SQL LIKE/=
    if (searchCondition !== "contains" && searchMode !== "regex") {
      const terms = searchMode === "exact" ? [searchTerm.trim()] : searchTerm.trim().split(/\s+/).filter(Boolean);
      const joinOp = searchMode === "or" ? " OR " : " AND ";
      const termConditions = terms.map((term) => {
        const colConds = meta.safeCols.map((c) => {
          if (searchCondition === "startswith") { params.push(`${term}%`); return `${c.safe} LIKE ?`; }
          if (searchCondition === "like") { params.push(term); return `${c.safe} LIKE ?`; }
          if (searchCondition === "equals") { params.push(term); return `${c.safe} = ?`; }
          params.push(`%${term}%`); return `${c.safe} LIKE ?`;
        });
        return `(${colConds.join(" OR ")})`;
      });
      whereConditions.push(`(${termConditions.join(joinOp)})`);
      return;
    }

    if (searchMode === "regex") {
      // Concatenate all columns with separator and run single REGEXP — avoids
      // pushing N identical params and N separate REGEXP calls per row.
      const concat = meta.safeCols.map((c) => `COALESCE(${c.safe},'')`).join(" || ' ' || ");
      whereConditions.push(`(${concat}) REGEXP ?`);
      params.push(searchTerm.trim());
      return;
    }
    // If FTS is not ready yet (async build in progress), fall back to LIKE search.
    // Concatenate all columns into one string — 1 LIKE per term instead of N per column.
    if (!meta.ftsReady) {
      const concat = meta.safeCols.map((c) => `COALESCE(${c.safe},'')`).join(" || ' ' || ");
      const terms = searchMode === "exact" ? [searchTerm.trim()] : searchTerm.trim().split(/\s+/).filter(Boolean);
      const joinOp = (searchMode === "or") ? " OR " : " AND ";
      const termConditions = terms.map((term) => {
        params.push(`%${term}%`);
        return `(${concat}) LIKE ?`;
      });
      whereConditions.push(`(${termConditions.join(joinOp)})`);
      return;
    }
    const { ftsQuery, colConditions } = this._buildSearchQuery(searchTerm, searchMode, meta);
    if (ftsQuery) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM data_fts WHERE data_fts MATCH ?)`);
      params.push(ftsQuery);
    }
    for (const cc of colConditions) {
      whereConditions.push(cc.sql);
      params.push(cc.param);
    }
  }

  // ── Shared filter helpers (used by queryRows, preview*, getLateralMovement, etc.) ──

  _applyColumnFilters(columnFilters, meta, whereConditions, params) {
    for (const [cn, fv] of Object.entries(columnFilters)) {
      if (!fv) continue;
      if (cn === "__tags__") {
        whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag LIKE ?)`);
        params.push(`%${fv}%`);
        continue;
      }
      if (cn === "__vt__") {
        whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag LIKE 'VT:%' AND tag LIKE ? COLLATE NOCASE)`);
        params.push(`%${fv}%`);
        continue;
      }
      const sc = meta.colMap[cn];
      if (!sc) continue;
      whereConditions.push(`${sc} LIKE ?`);
      params.push(`%${fv}%`);
    }
  }

  _applyCheckboxFilters(checkboxFilters, meta, whereConditions, params) {
    for (const [cn, values] of Object.entries(checkboxFilters)) {
      if (!values || values.length === 0) continue;
      if (cn === "__vt__") {
        const ph = values.map(() => "?").join(",");
        whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag IN (${ph}))`);
        params.push(...values);
        continue;
      }
      const sc = meta.colMap[cn];
      if (!sc) continue;
      const hasNull = values.some((v) => v === null || v === "");
      const nonNull = values.filter((v) => v !== null && v !== "");
      const parts = [];
      if (hasNull) parts.push(`(${sc} IS NULL OR ${sc} = '')`);
      if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
      else if (nonNull.length > 1) { parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`); params.push(...nonNull); }
      whereConditions.push(parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0]);
    }
  }

  _applyDateRangeFilters(dateRangeFilters, meta, whereConditions, params) {
    for (const [cn, range] of Object.entries(dateRangeFilters)) {
      const sc = meta.colMap[cn];
      if (!sc) continue;
      if (range.from) { whereConditions.push(`${sc} >= ?`); params.push(range.from); }
      if (range.to) { whereConditions.push(`${sc} <= ?`); params.push(range.to); }
    }
  }

  _applyBookmarkFilter(bookmarkedOnly, whereConditions) {
    if (bookmarkedOnly) {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM bookmarks)`);
    }
  }

  _applyTagFilter(tagFilter, whereConditions, params) {
    if (tagFilter === "__any__") {
      whereConditions.push(`data.rowid IN (SELECT DISTINCT rowid FROM tags)`);
    } else if (Array.isArray(tagFilter) && tagFilter.length > 0) {
      const ph = tagFilter.map(() => "?").join(",");
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag IN (${ph}))`);
      params.push(...tagFilter);
    } else if (tagFilter && typeof tagFilter === "string") {
      whereConditions.push(`data.rowid IN (SELECT rowid FROM tags WHERE tag = ?)`);
      params.push(tagFilter);
    }
  }

  /**
   * Apply the standard set of filters to a WHERE clause.
   * Centralizes the filter logic shared by queryRows, exportQuery,
   * getColumnStats, getHistogramData, and all analysis methods.
   */
  _applyStandardFilters(options, meta, whereConditions, params) {
    const {
      columnFilters = {}, checkboxFilters = {},
      bookmarkedOnly = false, tagFilter = null,
      dateRangeFilters = {}, advancedFilters = [],
      searchTerm = "", searchMode = "mixed", searchCondition = "contains",
    } = options;
    this._applyColumnFilters(columnFilters, meta, whereConditions, params);
    this._applyCheckboxFilters(checkboxFilters, meta, whereConditions, params);
    this._applyDateRangeFilters(dateRangeFilters, meta, whereConditions, params);
    this._applyBookmarkFilter(bookmarkedOnly, whereConditions);
    this._applyTagFilter(tagFilter, whereConditions, params);
    this._applyAdvancedFilters(advancedFilters, meta, whereConditions, params);
    if (searchTerm.trim()) {
      this._applySearch(searchTerm, searchMode, meta, whereConditions, params, searchCondition);
    }
  }

  /**
   * Apply advanced multi-condition filters (Edit Filter feature).
   * Groups conditions by AND/OR logic with correct SQL precedence:
   *   A AND B OR C AND D  →  (A AND B) OR (C AND D)
   */
  _applyAdvancedFilters(advancedFilters, meta, whereConditions, params) {
    if (!advancedFilters || advancedFilters.length === 0) return;

    // Filter out incomplete conditions
    const valid = advancedFilters.filter((f) => {
      if (!f.column || !f.operator) return false;
      if (f.operator !== "is_empty" && f.operator !== "is_not_empty" && !f.value && f.value !== 0) return false;
      const sc = meta.colMap[f.column];
      return !!sc;
    });
    if (valid.length === 0) return;

    // Build SQL for a single condition
    const buildCondition = (f) => {
      const sc = meta.colMap[f.column];
      switch (f.operator) {
        case "contains":
          params.push(`%${f.value}%`);
          return `${sc} LIKE ?`;
        case "not_contains":
          params.push(`%${f.value}%`);
          return `${sc} NOT LIKE ?`;
        case "equals":
          params.push(f.value);
          return `${sc} = ?`;
        case "not_equals":
          params.push(f.value);
          return `${sc} != ?`;
        case "starts_with":
          params.push(`${f.value}%`);
          return `${sc} LIKE ?`;
        case "ends_with":
          params.push(`%${f.value}`);
          return `${sc} LIKE ?`;
        case "greater_than":
          params.push(f.value);
          return `CAST(${sc} AS REAL) > CAST(? AS REAL)`;
        case "less_than":
          params.push(f.value);
          return `CAST(${sc} AS REAL) < CAST(? AS REAL)`;
        case "is_empty":
          return `(${sc} IS NULL OR ${sc} = '')`;
        case "is_not_empty":
          return `(${sc} IS NOT NULL AND ${sc} != '')`;
        case "regex":
          params.push(f.value);
          return `${sc} REGEXP ?`;
        default:
          params.push(`%${f.value}%`);
          return `${sc} LIKE ?`;
      }
    };

    // Group consecutive AND-linked conditions, join groups with OR
    const groups = [];
    let currentGroup = [buildCondition(valid[0])];

    for (let i = 1; i < valid.length; i++) {
      if (valid[i].logic === "OR") {
        groups.push(currentGroup);
        currentGroup = [buildCondition(valid[i])];
      } else {
        currentGroup.push(buildCondition(valid[i]));
      }
    }
    groups.push(currentGroup);

    // Build final expression
    const expr = groups
      .map((g) => (g.length > 1 ? `(${g.join(" AND ")})` : g[0]))
      .join(" OR ");

    whereConditions.push(groups.length > 1 ? `(${expr})` : expr);
  }

  /**
   * Build search query from search term and mode.
   * Returns { ftsQuery, colConditions } where:
   *   - ftsQuery: FTS5 MATCH string (or null if no FTS terms)
   *   - colConditions: array of { sql, param } for column-specific Col:value filters
   */
  _buildSearchQuery(searchTerm, searchMode, meta) {
    // Lazy-build FTS index on first search
    this._ensureFts(meta.tabId);
    const result = { ftsQuery: null, colConditions: [] };
    try {
      if (searchMode === "exact") {
        const cleaned = searchTerm.replace(/"/g, "").trim();
        result.ftsQuery = `"${cleaned}"`;
        return result;
      }

      if (searchMode === "or") {
        const terms = searchTerm.trim().split(/\s+/).filter(Boolean);
        result.ftsQuery = terms.map((t) => `"${t.replace(/"/g, "")}"`).join(" OR ");
        return result;
      }

      if (searchMode === "and") {
        const terms = searchTerm.trim().split(/\s+/).filter(Boolean);
        result.ftsQuery = terms.map((t) => `"${t.replace(/"/g, "")}"`).join(" AND ");
        return result;
      }

      // Mixed mode — parse +AND, -EXCLUDE, "phrases", Column:value
      const tokens = [];
      const regex = /"([^"]+)"|(\S+)/g;
      let m;
      while ((m = regex.exec(searchTerm)) !== null) {
        tokens.push(m[1] ? `"${m[1]}"` : m[2]);
      }

      const ftsTerms = [];
      for (const token of tokens) {
        if (token.startsWith('"')) {
          ftsTerms.push(token);
        } else if (token.includes(":")) {
          // Column-specific filter: Col:value → WHERE colSafe LIKE %value%
          const colonIdx = token.indexOf(":");
          const colPart = token.substring(0, colonIdx);
          const valPart = token.substring(colonIdx + 1);
          if (valPart) {
            // Find matching column (case-insensitive)
            const matchCol = meta.headers.find((h) => h.toLowerCase() === colPart.toLowerCase());
            const safeCol = matchCol ? meta.colMap[matchCol] : null;
            if (safeCol) {
              result.colConditions.push({ sql: `${safeCol} LIKE ?`, param: `%${valPart}%` });
            }
          }
        } else if (token.startsWith("-")) {
          const term = token.slice(1);
          if (term) ftsTerms.push(`NOT "${term}"`);
        } else if (token.startsWith("+")) {
          const term = token.slice(1);
          if (term) ftsTerms.push(`"${term}"`);
        } else {
          ftsTerms.push(`"${token}"`);
        }
      }

      if (ftsTerms.length > 0) {
        const hasOperator = tokens.some((t) => t.startsWith("+") || t.startsWith("-"));
        // Default to AND for multi-word (DFIR analysts want all terms to match)
        result.ftsQuery = ftsTerms.join(hasOperator ? " AND " : (ftsTerms.length > 1 ? " AND " : ""));
      }

      return result;
    } catch (e) {
      result.ftsQuery = `"${searchTerm.replace(/"/g, "").trim()}"`;
      return result;
    }
  }

  /**
   * Toggle bookmark on a row
   */
  _invalidateCountCache(tabId) {
    const meta = this.databases.get(tabId);
    if (meta) { meta._countCache = null; meta._histoCache = null; }
    // Also clear analysis preview caches — they depend on filtered/tagged data
    if (this._ptPreviewCache) {
      const prefix = JSON.stringify(tabId);
      for (const k of this._ptPreviewCache.keys()) { if (k.startsWith("[" + prefix + ",")) this._ptPreviewCache.delete(k); }
    }
    if (this._lmPreviewCache) {
      const prefix = JSON.stringify(tabId);
      for (const k of this._lmPreviewCache.keys()) { if (k.startsWith("[" + prefix + ",")) this._lmPreviewCache.delete(k); }
    }
  }

  toggleBookmark(tabId, rowId) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    this._invalidateCountCache(tabId);
    const exists = meta.bmCheckStmt.get(rowId);
    if (exists) {
      meta.bmDeleteStmt.run(rowId);
      return false;
    } else {
      meta.bmInsertStmt.run(rowId);
      return true;
    }
  }

  /**
   * Bulk toggle bookmarks
   */
  setBookmarks(tabId, rowIds, add = true) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    this._invalidateCountCache(tabId);
    const stmt = add ? meta.bmInsertStmt : meta.bmDeleteStmt;
    const tx = meta.db.transaction((ids) => {
      for (const id of ids) stmt.run(id);
    });
    tx(rowIds);
  }

  /**
   * Get bookmark count
   */
  getBookmarkCount(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return 0;
    return meta.bmCountStmt.get().cnt;
  }

  /**
   * Get all bookmarked row IDs
   */
  getBookmarkedIds(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db
      .prepare("SELECT rowid FROM bookmarks")
      .all()
      .map((r) => r.rowid);
  }

  // ── Tag operations ─────────────────────────────────────────────

  addTag(tabId, rowId, tag) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    this._invalidateCountCache(tabId);
    meta.tagInsertStmt.run(rowId, tag);
  }

  removeTag(tabId, rowId, tag) {
    const meta = this.databases.get(tabId);
    if (!meta || this._isBuilding(tabId)) return;
    this._invalidateCountCache(tabId);
    meta.tagDeleteStmt.run(rowId, tag);
  }

  getTagsForRows(tabId, rowIds) {
    const meta = this.databases.get(tabId);
    if (!meta) return {};
    const result = {};
    for (let i = 0; i < rowIds.length; i += 500) {
      const batch = rowIds.slice(i, i + 500);
      const placeholders = batch.map(() => "?").join(",");
      const rows = meta.db.prepare(`SELECT rowid, tag FROM tags WHERE rowid IN (${placeholders})`).all(...batch);
      for (const r of rows) {
        if (!result[r.rowid]) result[r.rowid] = [];
        result[r.rowid].push(r.tag);
      }
    }
    return result;
  }

  getAllTags(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db.prepare("SELECT tag, COUNT(*) as cnt FROM tags GROUP BY tag ORDER BY cnt DESC").all();
  }

  getAllTagData(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    return meta.db.prepare("SELECT rowid, tag FROM tags").all();
  }

  /**
   * Fetch raw rows by SQLite rowid, preserving the requested order.
   * Returns rows mapped back to original header names plus `__idx`.
   */
  getRowsByIds(tabId, rowIds) {
    const meta = this.databases.get(tabId);
    if (!meta || !Array.isArray(rowIds) || rowIds.length === 0) return [];
    const ids = [...new Set(rowIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0))];
    if (ids.length === 0) return [];

    const rowsById = new Map();
    const colList = meta.safeCols.map((c) => c.safe).join(", ");
    for (let i = 0; i < ids.length; i += 500) {
      const batch = ids.slice(i, i + 500);
      const placeholders = batch.map(() => "?").join(",");
      const sql = `SELECT data.rowid as _rowid, ${colList} FROM data WHERE data.rowid IN (${placeholders})`;
      const rawRows = meta.db.prepare(sql).all(...batch);
      for (const raw of rawRows) {
        const row = { __idx: raw._rowid };
        for (let c = 0; c < meta.safeCols.length; c++) {
          row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] ?? "";
        }
        rowsById.set(raw._rowid, row);
      }
    }

    return ids.map((id) => rowsById.get(id)).filter(Boolean);
  }

  /**
   * Gather all data needed for HTML report generation.
   * Returns bookmarked rows, tagged rows grouped by tag, and summary stats.
   */
  getReportData(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;

    try {
      const d = meta.db;
      const colList = meta.safeCols.map((c) => c.safe).join(", ");
      const mapRow = (raw) => {
        const row = {};
        for (let c = 0; c < meta.safeCols.length; c++) {
          row[meta.safeCols[c].original] = raw[meta.safeCols[c].safe] ?? "";
        }
        return row;
      };

      // Bookmarked rows (full data)
      const bookmarkedRows = d.prepare(
        `SELECT ${colList} FROM data WHERE rowid IN (SELECT rowid FROM bookmarks) ORDER BY rowid`
      ).all().map(mapRow);

      // Tags: unique tags with counts
      const tagSummary = d.prepare(
        "SELECT tag, COUNT(*) as cnt FROM tags GROUP BY tag ORDER BY cnt DESC"
      ).all();

      // Tagged rows grouped by tag (single JOIN query instead of per-tag N+1)
      const taggedGroups = {};
      if (tagSummary.length > 0) {
        const allTaggedRows = d.prepare(
          `SELECT t.tag, ${colList} FROM data d INNER JOIN tags t ON d.rowid = t.rowid ORDER BY t.tag, d.rowid`
        ).all();
        for (const row of allTaggedRows) {
          const tag = row.tag;
          if (!taggedGroups[tag]) taggedGroups[tag] = [];
          const mapped = {};
          for (let c = 0; c < meta.safeCols.length; c++) {
            mapped[meta.safeCols[c].original] = row[meta.safeCols[c].safe] ?? "";
          }
          taggedGroups[tag].push(mapped);
        }
      }

      // Summary stats
      const totalRows = meta.rowCount;
      const bookmarkCount = d.prepare("SELECT COUNT(*) as cnt FROM bookmarks").get().cnt;
      const tagCount = d.prepare("SELECT COUNT(DISTINCT tag) as cnt FROM tags").get().cnt;
      const taggedRowCount = d.prepare("SELECT COUNT(DISTINCT rowid) as cnt FROM tags").get().cnt;

      // Timestamp range (from first ts column if available)
      let tsRange = null;
      if (meta.tsColumns && meta.tsColumns.size > 0) {
        const firstTsCol = [...meta.tsColumns][0];
        const safeCol = meta.colMap[firstTsCol];
        if (safeCol) {
          const range = d.prepare(
            `SELECT MIN(${safeCol}) as earliest, MAX(${safeCol}) as latest FROM data WHERE ${safeCol} IS NOT NULL AND ${safeCol} != ''`
          ).get();
          if (range?.earliest) tsRange = { column: firstTsCol, earliest: range.earliest, latest: range.latest };
        }
      }

      return {
        headers: meta.headers,
        totalRows,
        bookmarkCount,
        bookmarkedRows,
        tagSummary,
        taggedGroups,
        tagCount,
        taggedRowCount,
        tsRange,
      };
    } catch (e) {
      dbg("DB", `getReportData error`, { tabId, error: e.message });
      return null;
    }
  }

  bulkAddTags(tabId, tagMap) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    const tx = meta.db.transaction(() => {
      for (const [rowId, tags] of Object.entries(tagMap)) {
        for (const tag of tags) meta.tagInsertStmt.run(Number(rowId), tag);
      }
    });
    tx();
    this._invalidateCountCache(tabId);
  }

  /**
   * Bulk-tag rows within specific time ranges directly in SQL.
   * ranges = [{ from, to, tag }] — e.g. [{ from: "2024-01-15 08:30", to: "2024-01-15 10:45", tag: "Session 1" }]
   * Never materializes rowIds in JS — pure SQL INSERT...SELECT.
   */
  bulkTagByTimeRange(tabId, colName, ranges) {
    const meta = this.databases.get(tabId);
    if (!meta || ranges.length === 0) return { taggedCount: 0 };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { taggedCount: 0 };
    this._invalidateCountCache(tabId);
    const db = meta.db;
    let taggedCount = 0;
    const tx = db.transaction(() => {
      for (const { from, to, tag } of ranges) {
        const fromTs = from.length === 16 ? from + ":00" : from;
        const toTs = to.length === 16 ? to + ":59" : to;
        const result = db.prepare(`
          INSERT OR IGNORE INTO tags (rowid, tag)
          SELECT rowid, ? FROM data
          WHERE ${safeCol} >= ? AND ${safeCol} <= ?
            AND ${safeCol} IS NOT NULL AND ${safeCol} != ''
        `).run(tag, fromTs, toTs);
        taggedCount += result.changes;
      }
    });
    tx();
    return { taggedCount };
  }

  /**
   * Bulk tag all rows matching current filters.
   * Uses INSERT...SELECT — never materializes rowIds in JS.
   */
  bulkTagFiltered(tabId, tag, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta || !tag) return { tagged: 0 };

    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      const result = db.prepare(`INSERT OR IGNORE INTO tags (rowid, tag) SELECT data.rowid, ? FROM data ${whereClause}`).run(tag, ...params);
      this._invalidateCountCache(tabId);
      return { tagged: result.changes };
    } catch (e) {
      dbg("DB", `bulkTagFiltered error`, { tabId, error: e.message });
      return { tagged: 0, error: e.message };
    }
  }

  /**
   * Bulk bookmark (or un-bookmark) all rows matching current filters.
   * Uses INSERT...SELECT / DELETE...SELECT — never materializes rowIds in JS.
   */
  bulkBookmarkFiltered(tabId, add, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { affected: 0 };

    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
      let result;
      if (add) {
        result = db.prepare(`INSERT OR IGNORE INTO bookmarks (rowid) SELECT data.rowid FROM data ${whereClause}`).run(...params);
      } else {
        result = db.prepare(`DELETE FROM bookmarks WHERE rowid IN (SELECT data.rowid FROM data ${whereClause})`).run(...params);
      }
      this._invalidateCountCache(tabId);
      return { affected: result.changes };
    } catch (e) {
      dbg("DB", `bulkBookmarkFiltered error`, { tabId, error: e.message });
      return { affected: 0, error: e.message };
    }
  }

  /**
   * Match IOC patterns against all columns using REGEXP.
   * Returns matched rowIds and per-IOC hit counts.
   */
  matchIocs(tabId, iocPatterns, batchSize = 200) {
    const meta = this.databases.get(tabId);
    if (!meta || iocPatterns.length === 0) return { matchedRowIds: [], perIocCounts: {} };

    const db = meta.db;
    const colList = meta.safeCols.map((c) => c.safe);

    // Phase 1: batched REGEXP alternation scan for matching rowIds
    // Concatenate columns with COALESCE/|| in SQL so REGEXP is called once per row
    // instead of once per column×row — reduces function calls by ~Nx for N columns
    const concatExpr = colList.map((c) => `COALESCE(${c},'')`).join(" || ' ' || ");
    const matchedSet = new Set();
    for (let i = 0; i < iocPatterns.length; i += batchSize) {
      const batch = iocPatterns.slice(i, i + batchSize);
      const altPattern = batch.join("|");
      const rows = db.prepare(`SELECT rowid FROM data WHERE (${concatExpr}) REGEXP ?`).all(altPattern);
      for (const r of rows) matchedSet.add(r.rowid);
    }

    const matchedRowIds = [...matchedSet];
    if (matchedRowIds.length === 0) {
      const perIocCounts = {};
      for (const p of iocPatterns) perIocCounts[p] = 0;
      return { matchedRowIds, perIocCounts };
    }

    // Phase 2: per-IOC hit counts AND per-row IOC mapping
    const allMatchedRows = [];
    for (let i = 0; i < matchedRowIds.length; i += 500) {
      const batch = matchedRowIds.slice(i, i + 500);
      const ph = batch.map(() => "?").join(",");
      const rows = db.prepare(`SELECT rowid, ${colList.join(", ")} FROM data WHERE rowid IN (${ph})`).all(...batch);
      for (const r of rows) allMatchedRows.push(r);
    }

    // Pre-compile all regex patterns once
    const compiled = [];
    const perIocCounts = {};
    for (let pi = 0; pi < iocPatterns.length; pi++) {
      const pattern = iocPatterns[pi];
      try {
        compiled.push({ re: new RegExp(pattern, "i"), pi, pattern });
      } catch {
        perIocCounts[pattern] = 0;
      }
    }
    for (const c of compiled) perIocCounts[c.pattern] = 0;

    // Single pass over rows — test all compiled patterns per row (better cache locality)
    const perRowIocs = {}; // rowId -> [patternIndex, ...]
    for (const row of allMatchedRows) {
      // Concatenate all column values once per row for fast regex testing
      let concat = "";
      for (let ci = 0; ci < colList.length; ci++) {
        const v = row[colList[ci]];
        if (v) { concat += v; concat += " "; }
      }
      for (const { re, pi, pattern } of compiled) {
        if (re.test(concat)) {
          perIocCounts[pattern]++;
          if (!perRowIocs[row.rowid]) perRowIocs[row.rowid] = [];
          perRowIocs[row.rowid].push(pi);
        }
      }
    }

    return { matchedRowIds, perIocCounts, perRowIocs };
  }

  /**
   * Export filtered data as streaming CSV
   */
  exportQuery(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;

    const { sortCol = null, sortDir = "asc", visibleHeaders = null } = options;

    const headers = visibleHeaders || meta.headers;
    const safeCols = headers.map((h) => meta.colMap[h]).filter(Boolean);
    const colList = safeCols.join(", ");

    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause =
      whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")}`
        : "";

    let orderClause = "ORDER BY data.rowid";
    if (sortCol) {
      const safeCol = meta.colMap[sortCol];
      if (safeCol) {
        const dir = sortDir === "desc" ? "DESC" : "ASC";
        if (meta.tsColumns.has(sortCol)) {
          orderClause = `ORDER BY sort_datetime(${safeCol}) ${dir}`;
        } else if (meta.numericColumns.has(sortCol)) {
          orderClause = `ORDER BY CAST(${safeCol} AS REAL) ${dir}`;
        } else {
          orderClause = `ORDER BY ${safeCol} COLLATE NOCASE ${dir}`;
        }
      }
    }

    const sql = `SELECT ${colList} FROM data ${whereClause} ${orderClause}`;
    const stmt = meta.db.prepare(sql);
    const iter = stmt.iterate(...params);

    return {
      headers,
      iterator: iter,
      safeCols,
      reverseMap: meta.reverseColMap,
    };
  }

  /**
   * Get column statistics (unique values, min/max for numerics)
   */
  getColumnStats(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    const isTagCol = colName === "__tags__";
    const safeCol = isTagCol ? null : meta.colMap[colName];
    if (!isTagCol && !safeCol) return null;

    const db = meta.db;
    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    try {
      if (isTagCol) {
        // Tags column stats — query from tags table
        const totalRows = db.prepare(`SELECT COUNT(*) as cnt FROM data ${whereClause}`).get(...params).cnt;
        const joinWhere = whereClause ? `${whereClause} AND data.rowid = tags.rowid` : `WHERE data.rowid = tags.rowid`;
        const taggedRows = db.prepare(`SELECT COUNT(DISTINCT tags.rowid) as cnt FROM tags, data ${joinWhere}`).get(...params).cnt;
        const uniqueTags = db.prepare(`SELECT COUNT(DISTINCT tag) as cnt FROM tags, data ${joinWhere}`).get(...params).cnt;
        const topValues = db.prepare(`SELECT tag as val, COUNT(*) as cnt FROM tags, data ${joinWhere} GROUP BY tag ORDER BY cnt DESC LIMIT 25`).all(...params);
        return { totalRows, nonEmptyCount: taggedRows, emptyCount: totalRows - taggedRows, uniqueCount: uniqueTags, fillRate: totalRows > 0 ? Math.round((taggedRows / totalRows) * 10000) / 100 : 0, topValues };
      }

      // Combined stats query — 1 scan instead of 3 separate COUNT queries
      const isTs = meta.tsColumns.has(colName);
      const isNum = meta.numericColumns && meta.numericColumns.has(colName);
      let statsSql = `SELECT COUNT(*) as total, SUM(CASE WHEN ${safeCol} IS NOT NULL AND ${safeCol} != '' THEN 1 ELSE 0 END) as nonEmpty, COUNT(DISTINCT CASE WHEN ${safeCol} IS NOT NULL AND ${safeCol} != '' THEN ${safeCol} END) as uniq`;
      if (isTs) statsSql += `, MIN(sort_datetime(${safeCol})) as earliest, MAX(sort_datetime(${safeCol})) as latest`;
      if (isNum) statsSql += `, MIN(CAST(${safeCol} AS REAL)) as minVal, MAX(CAST(${safeCol} AS REAL)) as maxVal, AVG(CAST(${safeCol} AS REAL)) as avgVal`;
      statsSql += ` FROM data ${whereClause}`;
      const stats = db.prepare(statsSql).get(...params);

      const totalRows = stats.total;
      const nonEmptyCount = stats.nonEmpty;
      const emptyCount = totalRows - nonEmptyCount;
      const uniqueCount = stats.uniq;
      const fillRate = totalRows > 0 ? Math.round((nonEmptyCount / totalRows) * 10000) / 100 : 0;

      // Top 25 values (still needs separate GROUP BY query)
      const neWhere = whereConditions.length > 0
        ? `WHERE ${whereConditions.join(" AND ")} AND ${safeCol} IS NOT NULL AND ${safeCol} != ''`
        : `WHERE ${safeCol} IS NOT NULL AND ${safeCol} != ''`;
      const topValues = db.prepare(
        `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${neWhere} GROUP BY ${safeCol} ORDER BY cnt DESC LIMIT 25`
      ).all(...params);

      const result = { totalRows, nonEmptyCount, emptyCount, uniqueCount, fillRate, topValues };

      // Timestamp stats (already computed in combined query)
      if (isTs && stats.earliest) {
        result.tsStats = { earliest: stats.earliest, latest: stats.latest };
        try {
          const e = new Date(stats.earliest.replace(" ", "T"));
          const l = new Date(stats.latest.replace(" ", "T"));
          const diffMs = l.getTime() - e.getTime();
          if (!isNaN(diffMs) && diffMs >= 0) result.tsStats.timespanMs = diffMs;
        } catch { /* non-parseable */ }
      }

      // Numeric stats (already computed in combined query)
      if (isNum && stats.minVal != null) {
        result.numStats = {
          min: stats.minVal,
          max: stats.maxVal,
          avg: Math.round(stats.avgVal * 100) / 100,
        };
      }

      return result;
    } catch (e) {
      return { totalRows: 0, nonEmptyCount: 0, emptyCount: 0, uniqueCount: 0, fillRate: 0, topValues: [], error: e.message };
    }
  }

  /**
   * Get columns that are entirely empty (NULL or '')
   */
  getEmptyColumns(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    const db = meta.db;
    // Sample-based: check first 25K + last 25K rows instead of full table scan.
    // On 30M+ row tables, a full scan blocks the main thread for 10-30s.
    const checks = meta.safeCols.map((c) => `MAX(CASE WHEN ${c.safe} IS NOT NULL AND ${c.safe} != '' THEN 1 ELSE 0 END) as ${c.safe}`);
    const useFullScan = meta.rowCount <= 100000;
    const source = useFullScan
      ? "data"
      : `(SELECT * FROM (SELECT * FROM data LIMIT 25000) UNION ALL SELECT * FROM (SELECT * FROM data ORDER BY rowid DESC LIMIT 25000))`;
    const row = db.prepare(`SELECT ${checks.join(", ")} FROM ${source}`).get();
    if (!row) return [...meta.headers];
    return meta.headers.filter((h) => {
      const sc = meta.colMap[h];
      return sc && !row[sc];
    });
  }

  /**
   * Get tab metadata
   */
  getTabInfo(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return null;
    return {
      headers: meta.headers,
      rowCount: meta.rowCount,
      tsColumns: [...meta.tsColumns],
      numericColumns: meta.numericColumns ? [...meta.numericColumns] : [],
    };
  }

  /**
   * Get unique values for a column (for checkbox filter dropdowns)
   * Respects all active filters except the checkbox filter for this column.
   */
  getColumnUniqueValues(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];

    const safeCol = meta.colMap[colName];
    if (!safeCol) return [];

    const {
      filterText = "",
      filterRegex = false,
      limit = 1000,
      checkboxFilters = {},
    } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Exclude self-column from checkbox filters to avoid circular filtering
    const filteredOptions = checkboxFilters[colName]
      ? { ...options, checkboxFilters: Object.fromEntries(Object.entries(checkboxFilters).filter(([cn]) => cn !== colName)) }
      : options;
    this._applyStandardFilters(filteredOptions, meta, whereConditions, params);

    // Filter values list by search text (supports regex mode)
    if (filterText.trim()) {
      if (filterRegex) {
        whereConditions.push(`${safeCol} REGEXP ?`);
        params.push(filterText);
      } else {
        whereConditions.push(`${safeCol} LIKE ?`);
        params.push(`%${filterText}%`);
      }
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY cnt DESC LIMIT ?`;
    params.push(limit);

    return db.prepare(sql).all(...params);
  }

  /**
   * Get group values with counts (for column grouping display)
   * Respects all active filters.
   */
  getGroupValues(tabId, groupCol, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];

    const safeCol = meta.colMap[groupCol];
    if (!safeCol) return [];

    const { parentFilters = [] } = options;

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Parent group filters (for multi-level grouping)
    for (const pf of parentFilters) {
      const sc = meta.colMap[pf.col];
      if (sc) {
        whereConditions.push(`${sc} = ?`);
        params.push(pf.value);
      }
    }

    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY cnt DESC`;

    return db.prepare(sql).all(...params);
  }

  /**
   * Count rows matching a search term (for cross-tab find)
   */
  searchCount(tabId, searchTerm, searchMode = "mixed", searchCondition = "contains") {
    const meta = this.databases.get(tabId);
    if (!meta) return 0;
    if (!searchTerm.trim()) return 0;

    const conditions = [];
    const params = [];
    this._applySearch(searchTerm, searchMode, meta, conditions, params, searchCondition);
    if (conditions.length === 0) return 0;
    const sql = `SELECT COUNT(*) as cnt FROM data WHERE ${conditions.join(" AND ")}`;
    return meta.db.prepare(sql).get(...params).cnt;
  }

  /**
   * Get histogram data for a timestamp column (event density over time).
   * Groups by day (first 10 chars = YYYY-MM-DD) and respects all active filters.
   */
  getHistogramData(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return [];
    const safeCol = meta.colMap[colName];
    if (!safeCol) return [];
    const { granularity = "day" } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];
    this._applyStandardFilters(options, meta, whereConditions, params);
    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;
    const extractFn = granularity === "hour" ? `substr(extract_datetime_minute(${safeCol}), 1, 13)` : `extract_date(${safeCol})`;
    const sql = `SELECT ${extractFn} as day, COUNT(*) as cnt FROM data ${whereClause} GROUP BY day HAVING day IS NOT NULL ORDER BY day`;
    // Cache histogram results — same filters often redraw without data changes
    const histoSig = safeCol + "|" + granularity + "|" + whereClause + "|" + JSON.stringify(params);
    if (meta._histoCache && meta._histoCache.sig === histoSig) return meta._histoCache.data;
    try {
      const data = db.prepare(sql).all(...params);
      meta._histoCache = { sig: histoSig, data };
      return data;
    } catch (err) { console.error(`Histogram query failed: ${err.message}`); return []; }
  }

  /**
   * Gap Analysis — detect quiet periods and activity sessions.
   * Buckets timestamps by minute, finds gaps > threshold, segments into sessions.
   * Returns { gaps, sessions, totalEvents }.
   */
  getGapAnalysis(tabId, colName, gapThresholdMinutes = 60, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { gaps: [], sessions: [], totalEvents: 0 };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { gaps: [], sessions: [], totalEvents: 0 };
    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];
    this._applyStandardFilters(options, meta, whereConditions, params);
    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;
    const sql = `SELECT extract_datetime_minute(${safeCol}) as mb, COUNT(*) as cnt FROM data ${whereClause} GROUP BY mb HAVING mb IS NOT NULL ORDER BY mb`;
    try {
      const buckets = db.prepare(sql).all(...params);
      if (buckets.length === 0) return { gaps: [], sessions: [], totalEvents: 0 };
      const totalEvents = buckets.reduce((s, b) => s + b.cnt, 0);
      const thresholdMs = gapThresholdMinutes * 60000;
      const parseMin = (mb) => new Date(mb.replace(" ", "T") + ":00Z").getTime();
      const gaps = [];
      const sessions = [];
      let sStart = 0;
      let sEvents = buckets[0].cnt;
      for (let i = 1; i < buckets.length; i++) {
        const prevMs = parseMin(buckets[i - 1].mb);
        const currMs = parseMin(buckets[i].mb);
        const gapMs = currMs - prevMs;
        if (gapMs > thresholdMs) {
          sessions.push({
            idx: sessions.length + 1,
            from: buckets[sStart].mb,
            to: buckets[i - 1].mb,
            eventCount: sEvents,
            durationMinutes: Math.round((parseMin(buckets[i - 1].mb) - parseMin(buckets[sStart].mb)) / 60000),
          });
          gaps.push({
            from: buckets[i - 1].mb,
            to: buckets[i].mb,
            durationMinutes: Math.round(gapMs / 60000),
          });
          sStart = i;
          sEvents = buckets[i].cnt;
        } else {
          sEvents += buckets[i].cnt;
        }
      }
      sessions.push({
        idx: sessions.length + 1,
        from: buckets[sStart].mb,
        to: buckets[buckets.length - 1].mb,
        eventCount: sEvents,
        durationMinutes: Math.round((parseMin(buckets[buckets.length - 1].mb) - parseMin(buckets[sStart].mb)) / 60000),
      });
      return { gaps, sessions, totalEvents };
    } catch (e) {
      return { gaps: [], sessions: [], totalEvents: 0, error: e.message };
    }
  }

  /**
   * Log Source Coverage Map — shows which log sources are present,
   * their time span (earliest→latest), event count, and coverage.
   */
  getLogSourceCoverage(tabId, sourceCol, tsCol, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { sources: [], globalEarliest: null, globalLatest: null, totalEvents: 0, totalSources: 0 };
    const safeSourceCol = meta.colMap[sourceCol];
    const safeTsCol = meta.colMap[tsCol];
    if (!safeSourceCol || !safeTsCol) return { sources: [], globalEarliest: null, globalLatest: null, totalEvents: 0, totalSources: 0 };

    const db = meta.db;
    const params = [];
    const whereConditions = [
      `${safeSourceCol} IS NOT NULL`, `${safeSourceCol} != ''`,
      `${safeTsCol} IS NOT NULL`, `${safeTsCol} != ''`,
    ];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;

    try {
      const sql = `SELECT ${safeSourceCol} as source, COUNT(*) as cnt, MIN(${safeTsCol}) as earliest, MAX(${safeTsCol}) as latest FROM data ${whereClause} GROUP BY ${safeSourceCol} ORDER BY cnt DESC`;
      const sources = db.prepare(sql).all(...params);

      if (sources.length === 0) {
        return { sources: [], globalEarliest: null, globalLatest: null, totalEvents: 0, totalSources: 0 };
      }

      const totalEvents = sources.reduce((s, r) => s + r.cnt, 0);
      let globalEarliest = sources[0].earliest;
      let globalLatest = sources[0].latest;
      for (const s of sources) {
        if (s.earliest < globalEarliest) globalEarliest = s.earliest;
        if (s.latest > globalLatest) globalLatest = s.latest;
      }

      return { sources, globalEarliest, globalLatest, totalEvents, totalSources: sources.length };
    } catch (e) {
      return { sources: [], globalEarliest: null, globalLatest: null, totalEvents: 0, totalSources: 0, error: e.message };
    }
  }

  /**
   * Event Burst Detection — find windows with abnormally high event density.
   * Groups timestamps into windows, calculates median baseline, flags
   * windows exceeding baseline × multiplier, merges adjacent burst windows.
   */
  getBurstAnalysis(tabId, colName, windowMinutes = 5, thresholdMultiplier = 5, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0 };
    const safeCol = meta.colMap[colName];
    if (!safeCol) return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0 };

    const db = meta.db;
    const params = [];
    const whereConditions = [`${safeCol} IS NOT NULL`, `${safeCol} != ''`];
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = `WHERE ${whereConditions.join(" AND ")}`;

    try {
      // Step 1: Get minute-level buckets (same as gap analysis)
      const sql = `SELECT extract_datetime_minute(${safeCol}) as mb, COUNT(*) as cnt FROM data ${whereClause} GROUP BY mb HAVING mb IS NOT NULL ORDER BY mb`;
      const minuteBuckets = db.prepare(sql).all(...params);

      if (minuteBuckets.length === 0) {
        return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0 };
      }

      const totalEvents = minuteBuckets.reduce((s, b) => s + b.cnt, 0);
      const parseMin = (mb) => new Date(mb.replace(" ", "T") + ":00Z").getTime();

      // Step 2: Aggregate minute buckets into windows
      let windows;
      if (windowMinutes === 1) {
        windows = minuteBuckets.map((b) => ({ ts: b.mb, tsMs: parseMin(b.mb), cnt: b.cnt }));
      } else {
        const firstMs = parseMin(minuteBuckets[0].mb);
        const windowMs = windowMinutes * 60000;
        const windowMap = new Map();
        for (const b of minuteBuckets) {
          const bMs = parseMin(b.mb);
          const windowStart = firstMs + Math.floor((bMs - firstMs) / windowMs) * windowMs;
          if (windowMap.has(windowStart)) {
            windowMap.get(windowStart).cnt += b.cnt;
          } else {
            const d = new Date(windowStart);
            const ts = d.toISOString().slice(0, 16).replace("T", " ");
            windowMap.set(windowStart, { ts, tsMs: windowStart, cnt: b.cnt });
          }
        }
        windows = [...windowMap.values()].sort((a, b) => a.tsMs - b.tsMs);
      }

      const totalWindows = windows.length;

      // Step 3: Calculate median baseline
      const sortedCounts = windows.map((w) => w.cnt).sort((a, b) => a - b);
      const mid = Math.floor(sortedCounts.length / 2);
      const rawBaseline = sortedCounts.length % 2 === 0
        ? (sortedCounts[mid - 1] + sortedCounts[mid]) / 2
        : sortedCounts[mid];
      const baseline = rawBaseline || 1; // guard against zero
      const threshold = baseline * thresholdMultiplier;

      // Step 4: Identify burst windows
      const burstFlags = windows.map((w) => w.cnt > threshold);

      // Step 5: Merge adjacent burst windows into contiguous periods
      const bursts = [];
      let i = 0;
      while (i < windows.length) {
        if (!burstFlags[i]) { i++; continue; }
        const burstStart = i;
        let burstEvents = 0;
        let peakRate = 0;
        while (i < windows.length && burstFlags[i]) {
          burstEvents += windows[i].cnt;
          if (windows[i].cnt > peakRate) peakRate = windows[i].cnt;
          i++;
        }
        const burstEnd = i - 1;
        const fromTs = windows[burstStart].ts;
        const toMs = windows[burstEnd].tsMs + windowMinutes * 60000;
        const toDate = new Date(toMs);
        const toTs = toDate.toISOString().slice(0, 16).replace("T", " ");

        bursts.push({
          from: fromTs, to: toTs,
          eventCount: burstEvents, peakRate,
          burstFactor: Math.round((burstEvents / ((burstEnd - burstStart + 1) * baseline)) * 10) / 10,
          windowCount: burstEnd - burstStart + 1,
          durationMinutes: (burstEnd - burstStart + 1) * windowMinutes,
        });
      }

      // Step 6: Build sparkline data
      const sparkline = windows.map((w) => ({ ts: w.ts, cnt: w.cnt, isBurst: w.cnt > threshold }));

      return {
        bursts, baseline: Math.round(baseline * 10) / 10, threshold: Math.round(threshold * 10) / 10,
        windowMinutes, totalEvents, totalWindows,
        peakRate: windows.length > 0 ? Math.max(...windows.map((w) => w.cnt)) : 0,
        sparkline,
      };
    } catch (e) {
      return { bursts: [], baseline: 0, windowMinutes, totalEvents: 0, totalWindows: 0, error: e.message };
    }
  }

  /**
   * Stacking / Value Frequency Analysis
   * Returns all unique values for a column with counts, percentages, and totals.
   * Respects all active filters. No row limit — returns complete frequency distribution.
   */
  getStackingData(tabId, colName, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { totalRows: 0, totalUnique: 0, values: [] };
    const isTagCol = colName === "__tags__";
    const safeCol = isTagCol ? null : meta.colMap[colName];
    if (!isTagCol && !safeCol) return { totalRows: 0, totalUnique: 0, values: [] };
    const { filterText = "", sortBy = "count" } = options;
    const db = meta.db;
    const params = [];
    const whereConditions = [];
    this._applyStandardFilters(options, meta, whereConditions, params);
    if (!isTagCol && filterText.trim()) {
      whereConditions.push(`${safeCol} LIKE ?`); params.push(`%${filterText}%`);
    }
    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";
    const orderBy = sortBy === "value" ? `val ASC` : `cnt DESC, val ASC`;
    const MAX_STACKING_VALUES = 10000;
    try {
      if (isTagCol) {
        // Tags stacking: query from tags table joined with data filters
        const filterParams = [...params];
        const joinWhere = whereClause ? `${whereClause} AND data.rowid = tags.rowid` : `WHERE data.rowid = tags.rowid`;
        let tagWhere = joinWhere;
        if (filterText.trim()) {
          tagWhere = `${joinWhere} AND tag LIKE ?`;
          filterParams.push(`%${filterText}%`);
        }
        // Single GROUP BY query with LIMIT+1 to detect truncation
        const sql = `SELECT tag as val, COUNT(*) as cnt FROM tags, data ${tagWhere} GROUP BY tag ORDER BY ${orderBy} LIMIT ${MAX_STACKING_VALUES + 1}`;
        const rawValues = db.prepare(sql).all(...filterParams);
        const truncated = rawValues.length > MAX_STACKING_VALUES;
        const values = truncated ? rawValues.slice(0, MAX_STACKING_VALUES) : rawValues;
        let totalRows = 0;
        for (let i = 0; i < values.length; i++) totalRows += values[i].cnt;
        let totalUnique = values.length;
        if (truncated) {
          // Rare case: >10K unique tags — need exact counts
          const stats = db.prepare(`SELECT COUNT(DISTINCT data.rowid) as totalRows, COUNT(DISTINCT tag) as totalUnique FROM tags, data ${tagWhere}`).get(...filterParams);
          totalRows = stats?.totalRows || totalRows;
          totalUnique = stats?.totalUnique || totalUnique;
        }
        return { totalRows, totalUnique, values, truncated };
      }
      // Single GROUP BY query with LIMIT+1 to detect truncation — avoids 2 extra COUNT scans
      const sql = `SELECT ${safeCol} as val, COUNT(*) as cnt FROM data ${whereClause} GROUP BY ${safeCol} ORDER BY ${orderBy} LIMIT ${MAX_STACKING_VALUES + 1}`;
      const rawValues = db.prepare(sql).all(...params);
      const truncated = rawValues.length > MAX_STACKING_VALUES;
      const values = truncated ? rawValues.slice(0, MAX_STACKING_VALUES) : rawValues;
      let totalRows = 0;
      for (let i = 0; i < values.length; i++) totalRows += values[i].cnt;
      let totalUnique = values.length;
      if (truncated) {
        // Rare case: >10K unique values — need exact counts (single scan instead of 2)
        const stats = db.prepare(`SELECT COUNT(*) as totalRows, COUNT(DISTINCT ${safeCol}) as totalUnique FROM data ${whereClause}`).get(...params);
        totalRows = stats?.totalRows || totalRows;
        totalUnique = stats?.totalUnique || totalUnique;
      }
      return { totalRows, totalUnique, values, truncated };
    } catch { return { totalRows: 0, totalUnique: 0, values: [], truncated: false }; }
  }

  /**
   * Build a process tree from Sysmon EventID 1 (Process Create) events.
   * Auto-detects columns, queries filtered rows, builds parent-child map.
   */
  getProcessTree(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { processes: [], stats: {}, columns: {}, error: "No database" };

    const {
      pidCol: userPidCol, ppidCol: userPpidCol,
      guidCol: userGuidCol, parentGuidCol: userParentGuidCol,
      imageCol: userImageCol, cmdLineCol: userCmdLineCol,
      userCol: userUserCol, tsCol: userTsCol, eventIdCol: userEventIdCol, providerCol: userProviderCol,
      eventIdValue = "1,4688",
      maxRows = 200000,
    } = options;

    // Auto-detect columns (case-insensitive)
    const detect = (patterns) => {
      for (const pat of patterns) {
        const found = meta.headers.find((h) => pat.test(h));
        if (found) return found;
      }
      return null;
    };

    // Detect EvtxECmd format (KAPE output)
    const isEvtxECmdPT = meta.headers.some((h) => /^PayloadData1$/i.test(h)) && meta.headers.some((h) => /^ExecutableInfo$/i.test(h));
    const isHayabusaPT = this._isHayabusaDataset(meta);
    const isChainsawPT = this._isChainsawProcessDataset(meta);

    const columns = {
      pid:         userPidCol        || detect([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
      ppid:        userPpidCol       || detect([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^parent_pid$/i, /^CreatorProcessId$/i]),
      guid:        userGuidCol       || detect([/^ProcessGuid$/i, /^process_guid$/i]),
      parentGuid:  userParentGuidCol || detect([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
      image:       userImageCol      || detect([/^Image$/i, /^process_name$/i, /^exe$/i, /^FileName$/i, /^ImagePath$/i, /^NewProcessName$/i, ...(isChainsawPT ? [/^Event\.EventData\.Image$/i] : [])]),
      parentImage: detect([/^ParentImage$/i, /^ParentProcessName$/i]),
      cmdLine:     userCmdLineCol    || detect([/^CommandLine$/i, /^command_line$/i, /^cmd$/i, /^cmdline$/i, /^ProcessCommandLine$/i, ...(isChainsawPT ? [/^Event\.EventData\.CommandLine$/i] : [])]),
      user:        userUserCol       || detect([/^User$/i, /^UserName$/i, /^user_name$/i, /^SubjectUserName$/i, /^TargetUserName$/i]),
      ts:          userTsCol         || detect([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsawPT ? [/^system_time$/i] : [])]),
      eventId:     userEventIdCol    || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsawPT ? [/^id$/i] : [])]),
      elevation:   detect([/^TokenElevationType$/i, /^Token_Elevation_Type$/i]),
      integrity:   detect([/^MandatoryLabel$/i, /^Mandatory_Label$/i, /^IntegrityLevel$/i]),
      provider:    userProviderCol || detect([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
      hostname:    detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i, ...(isChainsawPT ? [/^computer_name$/i] : [])]),
      details:     isHayabusaPT ? detect([/^Details$/i]) : null,
      extra:       isHayabusaPT ? detect([/^ExtraFieldInfo$/i]) : null,
    };

    // EvtxECmd: OVERRIDE columns — ProcessId in CSV header is the logging service PID (e.g., Sysmon 5464),
    // NOT the created process PID. Real PID/GUID is inside PayloadData1/PayloadData5.
    // PayloadData1: "ProcessID: N, ProcessGUID: {guid}"
    // PayloadData5: "ParentProcessID: N, ParentProcessGUID: {guid}"
    // ExecutableInfo: full command line (image path extractable from first token)
    if (isEvtxECmdPT) {
      columns.pid = detect([/^PayloadData1$/i]) || columns.pid;       // MUST override — CSV ProcessId is service PID
      columns.ppid = detect([/^PayloadData5$/i]) || columns.ppid;     // MUST override
      columns.guid = detect([/^PayloadData1$/i]) || columns.guid;     // GUID parsed from same field as PID
      columns.parentGuid = detect([/^PayloadData5$/i]) || columns.parentGuid; // parent GUID from same field as PPID
      columns.image = detect([/^ExecutableInfo$/i]) || columns.image; // image extracted from command line
      columns.cmdLine = detect([/^ExecutableInfo$/i]) || columns.cmdLine;
    } else if (isHayabusaPT) {
      const detailsCol = detect([/^Details$/i]);
      const extraCol = detect([/^ExtraFieldInfo$/i]);
      columns.pid = detailsCol || columns.pid;
      columns.ppid = extraCol || detailsCol || columns.ppid;
      columns.guid = detailsCol || columns.guid;
      columns.parentGuid = detailsCol || columns.parentGuid;
      columns.image = detailsCol || columns.image;
      columns.parentImage = extraCol || detailsCol || columns.parentImage;
      columns.cmdLine = detailsCol || columns.cmdLine;
      columns.user = extraCol || detailsCol || columns.user;
      columns.elevation = extraCol || detailsCol || columns.elevation;
      columns.integrity = extraCol || detailsCol || columns.integrity;
    }
    columns._isEvtxECmd = isEvtxECmdPT;
    columns._isHayabusa = isHayabusaPT;
    columns._isChainsaw = isChainsawPT;

    const useGuid = !!(columns.guid && columns.parentGuid) || isEvtxECmdPT;
    if (!columns.pid && !columns.guid && !isEvtxECmdPT && !isHayabusaPT && !isChainsawPT) return { processes: [], stats: {}, columns, error: "Cannot detect ProcessId or ProcessGuid column" };
    if (!columns.ppid && !columns.parentGuid && !isEvtxECmdPT && !isHayabusaPT && !isChainsawPT) return { processes: [], stats: {}, columns, error: "Cannot detect ParentProcessId or ParentProcessGuid column" };

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    // Filter to EventID value(s) — supports comma-separated (e.g., "1,4688")
    // Probes exact match first; falls back to CAST normalization for non-clean formats
    // like "EventID 4688", "4688 - A new process has been created", etc.
    if (columns.eventId && eventIdValue) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        const eids = eventIdValue.split(",").map(s => s.trim()).filter(Boolean);
        // Probe: does exact match find any rows? (runs before other filters are added)
        const probeSql = `SELECT COUNT(*) as cnt FROM data WHERE ${safeEid} IN (${eids.map(() => "?").join(",")}) LIMIT 1`;
        const probeResult = db.prepare(probeSql).get(...eids);
        if (probeResult && probeResult.cnt > 0) {
          // Exact match works — fast path
          if (eids.length === 1) { whereConditions.push(`${safeEid} = ?`); params.push(eids[0]); }
          else { whereConditions.push(`${safeEid} IN (${eids.map(() => "?").join(",")})`); params.push(...eids); }
        } else {
          // Exact match failed — use CAST normalization
          const eidInts = eids.map(e => parseInt(e, 10)).filter(n => !isNaN(n));
          if (eidInts.length > 0) {
            whereConditions.push(`CAST(${safeEid} AS INTEGER) IN (${eidInts.join(",")})`);
          }
        }
      }
    }

    // EvtxECmd: auto-filter to Security + Sysmon providers only.
    // EvtxECmd CSV aggregates ALL providers — many have EID 1 (Kernel-IO, AzureGuestAgent, etc.)
    // that are NOT process creation events. Only Sysmon EID 1 and Security EID 4688 are relevant.
    // Falls back to no provider filter if provider column is mis-mapped or uses non-standard values.
    if (isEvtxECmdPT && columns.provider) {
      const safeProv = meta.colMap[columns.provider];
      if (safeProv) {
        // Probe: does provider filter find any rows combined with the EID filter?
        const provProbeWc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")} AND` : "WHERE";
        const provProbe = db.prepare(`SELECT COUNT(*) as cnt FROM data ${provProbeWc} (${safeProv} LIKE ? OR ${safeProv} LIKE ?) LIMIT 1`).get(...params, "%Sysmon%", "%Security-Auditing%");
        if (provProbe && provProbe.cnt > 0) {
          whereConditions.push(`(${safeProv} LIKE ? OR ${safeProv} LIKE ?)`);
          params.push("%Sysmon%", "%Security-Auditing%");
        }
        // else: skip provider filter — mis-mapped or non-standard provider values
      }
    }

    // Standard filter application
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    // Build SELECT — deduplicate when multiple keys map to the same column (e.g., EvtxECmd: pid+guid both from PayloadData1)
    const selectParts = ["data.rowid as _rowid"];
    const selectedCols = new Set();
    for (const [key, colName] of Object.entries(columns)) {
      if (key.startsWith("_")) continue;  // skip internal flags
      if (colName && meta.colMap[colName] && !selectedCols.has(colName)) {
        selectParts.push(`${meta.colMap[colName]} as [${key}]`);
        selectedCols.add(colName);
      }
    }

    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol ? `ORDER BY ${orderCol} ASC` : "ORDER BY data.rowid ASC";

    try {
      const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
      const rows = db.prepare(sql).all(...params);

      // Build parent-child map
      const processes = [];
      const byKey = new Map();
      const childrenOf = new Map();

      for (const row of rows) {
        let pid = row.pid || "";
        let ppid = row.ppid || "";
        let guid = row.guid || "";
        let parentGuid = row.parentGuid || "";
        let imagePath = row.image || "";
        let cmdLine = row.cmdLine || "";
        let parentImageRaw = row.parentImage || "";
        let resolvedUser = row.user || "";
        let resolvedElevation = row.elevation || "";
        let resolvedIntegrity = row.integrity || "";

        // EvtxECmd: parse structured PayloadData fields
        if (isEvtxECmdPT) {
          // PayloadData1: "ProcessID: 5668, ProcessGUID: 7bf9956e-0a95-6931-a700-000000000700"
          // row.pid holds PayloadData1 (may also be aliased as guid due to same column)
          const pd1 = row.pid || row.guid || "";
          const pidMatch = pd1.match(/ProcessID:\s*(\d+)/i);
          const guidMatch = pd1.match(/ProcessGUID:\s*([0-9a-f-]+)/i);
          if (pidMatch) pid = pidMatch[1];
          if (guidMatch) guid = guidMatch[1];

          // PayloadData5: "ParentProcessID: 4408, ParentProcessGUID: 7bf9956e-..."
          const pd5 = row.ppid || row.parentGuid || "";
          const ppidMatch = pd5.match(/ParentProcessID:\s*(\d+)/i);
          const pguidMatch = pd5.match(/ParentProcessGUID:\s*([0-9a-f-]+)/i);
          if (ppidMatch) ppid = ppidMatch[1];
          if (pguidMatch) parentGuid = pguidMatch[1];

          // ExecutableInfo: full command line — may be aliased as image or cmdLine depending on dedup order
          const execInfo = row.image || row.cmdLine || "";
          cmdLine = execInfo;
          // Extract image path from command line (first token, may be quoted)
          if (execInfo) {
            const qm = execInfo.match(/^"([^"]+)"/);
            imagePath = qm ? qm[1] : execInfo.split(/\s/)[0];
          }
        } else if (isHayabusaPT) {
          const compact = this._parseCompactKeyValues(row.details, row.extra);
          const eventId = String(row.eventId || "").trim();
          pid = this._compactGetInt(compact, "PID", "ProcessId", "NewProcessId");
          ppid = eventId === "4688"
            ? this._compactGetInt(compact, "ProcessId", "CreatorProcessId", "ParentPID", "ParentProcessId")
            : this._compactGetInt(compact, "ParentPID", "ParentProcessId", "CreatorProcessId");
          guid = this._compactGet(compact, "PGUID", "ProcessGuid", "ProcessGUID");
          parentGuid = this._compactGet(compact, "ParentPGUID", "ParentProcessGuid", "ParentProcessGUID");
          imagePath = this._compactGet(compact, "Proc", "Image", "NewProcessName", "ProcessName");
          cmdLine = this._compactGet(compact, "Cmdline", "CommandLine", "ProcessCommandLine");
          if (!imagePath && cmdLine) {
            const qm = cmdLine.match(/^"([^"]+)"/);
            imagePath = qm ? qm[1] : cmdLine.split(/\s+/)[0];
          }
          parentImageRaw = this._compactGet(compact, "ParentImage", "ParentProcessName");
          resolvedUser = this._compactGet(compact, "SubjectUserName", "TargetUserName", "TgtUser", "User");
          if (resolvedUser.includes("\\")) resolvedUser = resolvedUser.split("\\").pop();
          resolvedElevation = this._compactGet(compact, "TokenElevationType");
          resolvedIntegrity = this._compactGet(compact, "IntegrityLevel", "MandatoryLabel");
        } else if (isChainsawPT) {
          pid = this._extractFirstInteger(row.pid);
          ppid = this._extractFirstInteger(row.ppid);
          guid = this._cleanWrappedField(row.guid);
          parentGuid = this._cleanWrappedField(row.parentGuid);
          imagePath = this._cleanWrappedField(row.image);
          cmdLine = this._cleanWrappedField(row.cmdLine);
          if (!imagePath && cmdLine) {
            const qm = cmdLine.match(/^"([^"]+)"/);
            imagePath = qm ? qm[1] : cmdLine.split(/\s+/)[0];
          }
          if (!cmdLine) cmdLine = imagePath;
          parentImageRaw = this._cleanWrappedField(row.parentImage);
          resolvedUser = this._cleanWrappedField(row.user);
          resolvedElevation = this._cleanWrappedField(row.elevation);
          resolvedIntegrity = this._cleanWrappedField(row.integrity);
          if (!pid && !guid) pid = `chainsaw-${row._rowid}`;
        }

        // Hex PID conversion (Security 4688 format: "0x1a2c")
        if (typeof pid === "string" && /^0x[0-9a-f]+$/i.test(pid.trim())) pid = String(parseInt(pid.trim(), 16));
        if (typeof ppid === "string" && /^0x[0-9a-f]+$/i.test(ppid.trim())) ppid = String(parseInt(ppid.trim(), 16));

        const key = useGuid && guid
          ? guid
          : `pid:${pid}:${row._rowid}`;
        const parentKey = useGuid && parentGuid
          ? parentGuid
          : ppid ? `pid:${ppid}` : "";

        const processName = imagePath.split("\\").pop().split("/").pop() || "(unknown)";

        const parentProcessName = parentImageRaw.split("\\").pop().split("/").pop() || "";

        const node = {
          key, parentKey, rowid: row._rowid,
          pid, ppid, guid, parentGuid,
          image: imagePath, processName, parentImage: parentImageRaw, parentProcessName,
          cmdLine, user: this._cleanWrappedField(resolvedUser), ts: this._cleanWrappedField(row.ts || ""),
          elevation: resolvedElevation, integrity: resolvedIntegrity,
          provider: this._cleanWrappedField(row.provider || ""), eventId: this._cleanWrappedField(row.eventId || ""),
          hostname: this._cleanWrappedField(row.hostname || ""),
          childCount: 0, depth: 0,
        };
        processes.push(node);
        byKey.set(key, node);
        if (parentKey) {
          if (!childrenOf.has(parentKey)) childrenOf.set(parentKey, []);
          childrenOf.get(parentKey).push(key);
        }
      }

      // PID-based fallback: re-link any rows that lack usable GUID parents (mixed Sysmon/Security and Hayabusa 4688).
      const pidToNodes = new Map();
      for (const node of processes) {
        if (!node.pid) continue;
        if (!pidToNodes.has(node.pid)) pidToNodes.set(node.pid, []);
        pidToNodes.get(node.pid).push(node);
      }
      if (!useGuid) childrenOf.clear();
      for (const node of processes) {
        const needsPidRelink = !useGuid || !node.parentGuid;
        if (!needsPidRelink || !node.ppid) continue;
        const candidates = pidToNodes.get(node.ppid);
        if (!candidates || candidates.length === 0) continue;
        let parent = null;
        for (let i = candidates.length - 1; i >= 0; i--) {
          if (candidates[i].key !== node.key) {
            if (!node.ts || !candidates[i].ts || candidates[i].ts <= node.ts) { parent = candidates[i]; break; }
          }
        }
        if (!parent && candidates.length > 0 && candidates[0].key !== node.key) parent = candidates[0];
        if (!parent) continue;

        const oldParentKey = node.parentKey;
        node.parentKey = parent.key;
        if (oldParentKey && childrenOf.has(oldParentKey)) {
          const siblings = childrenOf.get(oldParentKey).filter((k) => k !== node.key);
          if (siblings.length > 0) childrenOf.set(oldParentKey, siblings);
          else childrenOf.delete(oldParentKey);
        }
        if (!childrenOf.has(parent.key)) childrenOf.set(parent.key, []);
        if (!childrenOf.get(parent.key).includes(node.key)) childrenOf.get(parent.key).push(node.key);
      }

      // Child counts
      for (const node of processes) node.childCount = (childrenOf.get(node.key) || []).length;

      // Compute depth via BFS from roots
      const roots = processes.filter((p) => !byKey.has(p.parentKey));
      const visited = new Set();
      const queue = roots.map((r) => ({ key: r.key, depth: 0 }));
      let qi = 0;
      while (qi < queue.length) {
        const { key, depth } = queue[qi++];
        if (visited.has(key)) continue; // guard against cycles
        visited.add(key);
        const node = byKey.get(key);
        if (node) node.depth = depth;
        for (const ck of (childrenOf.get(key) || [])) queue.push({ key: ck, depth: depth + 1 });
      }

      // Safe maxDepth computation (avoid spreading large arrays)
      let maxDepth = 0;
      for (const p of processes) { if (p.depth > maxDepth) maxDepth = p.depth; }

      return {
        processes, columns, useGuid,
        stats: {
          totalProcesses: processes.length,
          rootCount: roots.length,
          maxDepth,
          truncated: rows.length >= maxRows,
        },
      };
    } catch (e) {
      return { processes: [], stats: {}, columns, error: e.message };
    }
  }

  /**
   * Lightweight preview for Process Inspector config — returns event counts, column quality,
   * linking quality (GUID/PID coverage), and provider mix without building the full tree.
   */
  previewProcessTree(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { eventCounts: {}, columnQuality: {}, linkingQuality: {}, error: "No database" };

    const {
      pidCol: userPidCol, ppidCol: userPpidCol,
      guidCol: userGuidCol, parentGuidCol: userParentGuidCol,
      imageCol: userImageCol, cmdLineCol: userCmdLineCol,
      userCol: userUserCol, tsCol: userTsCol, eventIdCol: userEventIdCol, providerCol: userProviderCol,
      eventIdValue = "1,4688",
    } = options;

    const db = meta.db;
    try {
      // --- Column auto-detection (same as getProcessTree L2533-2574) ---
      const detect = (patterns) => {
        for (const pat of patterns) { const found = meta.headers.find((h) => pat.test(h)); if (found) return found; }
        return null;
      };
      const isEvtxECmd = meta.headers.some((h) => /^PayloadData1$/i.test(h)) && meta.headers.some((h) => /^ExecutableInfo$/i.test(h));
      const isHayabusa = this._isHayabusaDataset(meta);
      const isChainsaw = this._isChainsawProcessDataset(meta);

      const columns = {
        pid:         userPidCol        || detect([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
        ppid:        userPpidCol       || detect([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^parent_pid$/i, /^CreatorProcessId$/i]),
        guid:        userGuidCol       || detect([/^ProcessGuid$/i, /^process_guid$/i]),
        parentGuid:  userParentGuidCol || detect([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
        image:       userImageCol      || detect([/^Image$/i, /^process_name$/i, /^exe$/i, /^FileName$/i, /^ImagePath$/i, /^NewProcessName$/i, ...(isChainsaw ? [/^Event\.EventData\.Image$/i] : [])]),
        parentImage: detect([/^ParentImage$/i, /^ParentProcessName$/i]),
        cmdLine:     userCmdLineCol    || detect([/^CommandLine$/i, /^command_line$/i, /^cmd$/i, /^cmdline$/i, /^ProcessCommandLine$/i, ...(isChainsaw ? [/^Event\.EventData\.CommandLine$/i] : [])]),
        user:        userUserCol       || detect([/^User$/i, /^UserName$/i, /^user_name$/i, /^SubjectUserName$/i, /^TargetUserName$/i]),
        ts:          userTsCol         || detect([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
        eventId:     userEventIdCol    || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
        elevation:   detect([/^TokenElevationType$/i, /^Token_Elevation_Type$/i]),
        integrity:   detect([/^MandatoryLabel$/i, /^Mandatory_Label$/i, /^IntegrityLevel$/i]),
        provider:    userProviderCol || detect([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
        hostname:    detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
        details:     isHayabusa ? detect([/^Details$/i]) : null,
        extra:       isHayabusa ? detect([/^ExtraFieldInfo$/i]) : null,
      };

      // EvtxECmd overrides (same as getProcessTree L2566-2574)
      if (isEvtxECmd) {
        columns.pid = detect([/^PayloadData1$/i]) || columns.pid;
        columns.ppid = detect([/^PayloadData5$/i]) || columns.ppid;
        columns.guid = detect([/^PayloadData1$/i]) || columns.guid;
        columns.parentGuid = detect([/^PayloadData5$/i]) || columns.parentGuid;
        columns.image = detect([/^ExecutableInfo$/i]) || columns.image;
        columns.cmdLine = detect([/^ExecutableInfo$/i]) || columns.cmdLine;
      } else if (isHayabusa) {
        const detailsCol = detect([/^Details$/i]);
        const extraCol = detect([/^ExtraFieldInfo$/i]);
        columns.pid = detailsCol || columns.pid;
        columns.ppid = extraCol || detailsCol || columns.ppid;
        columns.guid = detailsCol || columns.guid;
        columns.parentGuid = detailsCol || columns.parentGuid;
        columns.image = detailsCol || columns.image;
        columns.parentImage = extraCol || detailsCol || columns.parentImage;
        columns.cmdLine = detailsCol || columns.cmdLine;
        columns.user = extraCol || detailsCol || columns.user;
        columns.elevation = extraCol || detailsCol || columns.elevation;
        columns.integrity = extraCol || detailsCol || columns.integrity;
      }
      columns._isEvtxECmd = isEvtxECmd;
      columns._isHayabusa = isHayabusa;
      columns._isChainsaw = isChainsaw;

      // --- Filter construction ---
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);
      const wc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

      // --- Cache ---
      const effectiveEventIdValue = eventIdValue == null ? "1,4688" : String(eventIdValue);
      const cacheKey = JSON.stringify([tabId, columns, effectiveEventIdValue, wc, params]);
      if (!this._ptPreviewCache) this._ptPreviewCache = new Map();
      if (this._ptPreviewCache.size > 50) { const first = this._ptPreviewCache.keys().next().value; this._ptPreviewCache.delete(first); }
      const cached = this._ptPreviewCache.get(cacheKey);
      if (cached) return cached;

      // --- Generic process-row fallback ---
      // Some datasets are not EVTX process-create logs, but still contain PID/PPID + image/cmdline
      // columns that Process Inspector can build from. Track those separately so preview does not
      // misleadingly report "0" usable rows just because EID 1/4688 is absent.
      const _nonEmptyText = (expr) => `${expr} IS NOT NULL AND TRIM(CAST(${expr} AS TEXT)) != '' AND CAST(${expr} AS TEXT) != '-'`;
      const _buildCandidateProcessExprs = () => {
        const idExprs = [];
        const parentExprs = [];
        const descExprs = [];
        const seen = { id: new Set(), parent: new Set(), desc: new Set() };
        const addExpr = (bucket, set, expr) => {
          if (!expr || set.has(expr)) return;
          set.add(expr);
          bucket.push(expr);
        };

        if (isEvtxECmd) {
          const pd1Safe = columns.pid && meta.colMap[columns.pid] ? meta.colMap[columns.pid] : (columns.guid && meta.colMap[columns.guid] ? meta.colMap[columns.guid] : null);
          const pd5Safe = columns.ppid && meta.colMap[columns.ppid] ? meta.colMap[columns.ppid] : (columns.parentGuid && meta.colMap[columns.parentGuid] ? meta.colMap[columns.parentGuid] : null);
          if (pd1Safe) addExpr(idExprs, seen.id, `(${pd1Safe} LIKE '%ProcessID:%' OR ${pd1Safe} LIKE '%ProcessGUID:%')`);
          if (pd5Safe) addExpr(parentExprs, seen.parent, `(${pd5Safe} LIKE '%ParentProcessID:%' OR ${pd5Safe} LIKE '%ParentProcessGUID:%')`);
        } else if (isHayabusa) {
          const detailsSafe = columns.details && meta.colMap[columns.details] ? meta.colMap[columns.details] : null;
          const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
          if (detailsSafe) {
            addExpr(idExprs, seen.id, `(${detailsSafe} LIKE '%PID:%' OR ${detailsSafe} LIKE '%PGUID:%' OR ${detailsSafe} LIKE '%ProcessGuid:%')`);
            addExpr(descExprs, seen.desc, `(${detailsSafe} LIKE '%Proc:%' OR ${detailsSafe} LIKE '%Cmdline:%')`);
            addExpr(parentExprs, seen.parent, `(${detailsSafe} LIKE '%ParentPID:%' OR ${detailsSafe} LIKE '%ParentPGUID:%')`);
          }
          if (extraSafe) {
            addExpr(parentExprs, seen.parent, `(${extraSafe} LIKE '%ParentImage:%' OR ${extraSafe} LIKE '%ParentProcessName:%' OR ${extraSafe} LIKE '%ProcessId:%')`);
          }
        } else if (isChainsaw) {
          const eidExprs = [];
          const descExprs = [];
          const seen = { eid: new Set(), desc: new Set() };
          const addExpr = (bucket, set, expr) => {
            if (!expr || set.has(expr)) return;
            set.add(expr);
            bucket.push(expr);
          };
          const eidSafe = columns.eventId && meta.colMap[columns.eventId] ? meta.colMap[columns.eventId] : null;
          if (eidSafe) addExpr(eidExprs, seen.eid, `${eidSafe} IN ('1','4688')`);
          const imageSafe = columns.image && meta.colMap[columns.image] ? meta.colMap[columns.image] : null;
          const cmdSafe = columns.cmdLine && meta.colMap[columns.cmdLine] ? meta.colMap[columns.cmdLine] : null;
          if (imageSafe) addExpr(descExprs, seen.desc, _nonEmptyText(imageSafe));
          if (cmdSafe) addExpr(descExprs, seen.desc, _nonEmptyText(cmdSafe));
          if (eidExprs.length === 0 || descExprs.length === 0) return { candidateExpr: null, linkableExpr: null };
          const candidateExpr = `(${eidExprs.join(" OR ")}) AND (${descExprs.join(" OR ")})`;
          return { candidateExpr, linkableExpr: candidateExpr };
        } else {
          const pidSafe = columns.pid && meta.colMap[columns.pid] ? meta.colMap[columns.pid] : null;
          const guidSafe = columns.guid && meta.colMap[columns.guid] ? meta.colMap[columns.guid] : null;
          const ppidSafe = columns.ppid && meta.colMap[columns.ppid] ? meta.colMap[columns.ppid] : null;
          const parentGuidSafe = columns.parentGuid && meta.colMap[columns.parentGuid] ? meta.colMap[columns.parentGuid] : null;
          if (pidSafe) addExpr(idExprs, seen.id, _nonEmptyText(pidSafe));
          if (guidSafe) addExpr(idExprs, seen.id, _nonEmptyText(guidSafe));
          if (ppidSafe) addExpr(parentExprs, seen.parent, _nonEmptyText(ppidSafe));
          if (parentGuidSafe) addExpr(parentExprs, seen.parent, _nonEmptyText(parentGuidSafe));
        }

        const imageSafe = columns.image && meta.colMap[columns.image] ? meta.colMap[columns.image] : null;
        const cmdSafe = columns.cmdLine && meta.colMap[columns.cmdLine] ? meta.colMap[columns.cmdLine] : null;
        if (imageSafe) addExpr(descExprs, seen.desc, _nonEmptyText(imageSafe));
        if (cmdSafe) addExpr(descExprs, seen.desc, _nonEmptyText(cmdSafe));

        if (idExprs.length === 0 || descExprs.length === 0) return { candidateExpr: null, linkableExpr: null };

        const candidateExpr = `(${idExprs.join(" OR ")}) AND (${descExprs.join(" OR ")})`;
        const linkableExpr = parentExprs.length > 0 ? `${candidateExpr} AND (${parentExprs.join(" OR ")})` : candidateExpr;
        return { candidateExpr, linkableExpr };
      };
      const candidateExprs = _buildCandidateProcessExprs();
      const _candidateProcessStats = (fullScope = false) => {
        if (!candidateExprs.candidateExpr) return { rows: 0, linkableRows: 0 };

        const { candidateExpr, linkableExpr } = candidateExprs;
        const fromScope = fullScope ? "" : ` ${wc}`;
        const bindParams = fullScope ? [] : params;
        const sql = `SELECT
          SUM(CASE WHEN ${candidateExpr} THEN 1 ELSE 0 END) as rows,
          SUM(CASE WHEN ${linkableExpr} THEN 1 ELSE 0 END) as linkableRows
          FROM data${fromScope}`;
        const qr = db.prepare(sql).get(...bindParams);
        return {
          rows: qr?.rows || 0,
          linkableRows: qr?.linkableRows || 0,
        };
      };

      const candidateStats = _candidateProcessStats(false);
      const candidateRows = candidateStats.rows || 0;
      const linkableCandidateRows = candidateStats.linkableRows || 0;
      let fullScopeCandidateRows = 0;
      if (candidateRows === 0) {
        const fullStats = _candidateProcessStats(true);
        fullScopeCandidateRows = fullStats.rows || 0;
      }

      // --- Event counts ---
      const eventCounts = {};
      const fullScopeEventCounts = {};
      let trackedEvents = 0;
      let fullScopeTrackedEvents = 0;
      let providerFallback = false;
      let eidNormalized = false;
      const uiEids = effectiveEventIdValue
        .split(",")
        .map((s) => String(s).trim())
        .filter(Boolean);
      if (uiEids.length > 0 && columns.eventId && meta.colMap[columns.eventId]) {
        const eidSafe = meta.colMap[columns.eventId];
        const eidWhere = wc ? `${wc} AND` : "WHERE";
        // For EvtxECmd, try provider-scoped first (Sysmon + Security), fall back to EID-only
        let provClause = "";
        const hasProvCol = isEvtxECmd && columns.provider && meta.colMap[columns.provider];
        if (hasProvCol) {
          const provSafe = meta.colMap[columns.provider];
          provClause = ` AND (${provSafe} LIKE '%Sysmon%' OR ${provSafe} LIKE '%Security%')`;
        }
        // Normalized EID expression: extracts integer from formats like "4688", "EventID 4688", "4688 - A new process"
        // CAST handles leading-digit values; LIKE fallback catches embedded IDs
        const eidNormExpr = `CASE WHEN CAST(${eidSafe} AS INTEGER) IN (${uiEids.join(",")}) THEN CAST(${eidSafe} AS INTEGER) WHEN ${eidSafe} LIKE '%4688%' THEN 4688 WHEN ${eidSafe} LIKE '% 1' OR ${eidSafe} LIKE '% 1 %' OR ${eidSafe} = '1' THEN 1 ELSE NULL END`;
        // Phase 1: exact match (fast path for clean data)
        const eidRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")})${provClause} GROUP BY ${eidSafe}`).all(...params, ...uiEids);
        for (const r of eidRows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = r.cnt; trackedEvents += r.cnt; } }
        // Phase 2: provider fallback (exact EID, no provider)
        if (trackedEvents === 0 && hasProvCol) {
          const fbRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${eidSafe}`).all(...params, ...uiEids);
          for (const r of fbRows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = r.cnt; trackedEvents += r.cnt; } }
          if (trackedEvents > 0) providerFallback = true;
        }
        // Phase 3: EID normalization fallback (handles non-clean EID values)
        if (trackedEvents === 0) {
          const normRows = db.prepare(`SELECT ${eidNormExpr} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidNormExpr} IS NOT NULL${providerFallback ? "" : provClause} GROUP BY 1`).all(...params);
          for (const r of normRows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = (eventCounts[k] || 0) + r.cnt; trackedEvents += r.cnt; } }
          if (trackedEvents > 0) eidNormalized = true;
        }

        // If the current scoped preview yields no process events, compute a lightweight
        // full-tab baseline so the UI can distinguish "no events in scope" from
        // "this dataset has no 1/4688 at all".
        if (trackedEvents === 0) {
          const fullEidWhere = "WHERE";
          const fullProvClause = provClause;
          const fullExactRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${fullEidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")})${fullProvClause} GROUP BY ${eidSafe}`).all(...uiEids);
          for (const r of fullExactRows) {
            if (r.eid != null) {
              const k = String(r.eid).trim();
              fullScopeEventCounts[k] = (fullScopeEventCounts[k] || 0) + r.cnt;
              fullScopeTrackedEvents += r.cnt;
            }
          }
          if (fullScopeTrackedEvents === 0 && hasProvCol) {
            const fullFbRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${fullEidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${eidSafe}`).all(...uiEids);
            for (const r of fullFbRows) {
              if (r.eid != null) {
                const k = String(r.eid).trim();
                fullScopeEventCounts[k] = (fullScopeEventCounts[k] || 0) + r.cnt;
                fullScopeTrackedEvents += r.cnt;
              }
            }
          }
          if (fullScopeTrackedEvents === 0) {
            const fullNormRows = db.prepare(`SELECT ${eidNormExpr} as eid, COUNT(*) as cnt FROM data ${fullEidWhere} ${eidNormExpr} IS NOT NULL GROUP BY 1`).all();
            for (const r of fullNormRows) {
              if (r.eid != null) {
                const k = String(r.eid).trim();
                fullScopeEventCounts[k] = (fullScopeEventCounts[k] || 0) + r.cnt;
                fullScopeTrackedEvents += r.cnt;
              }
            }
          }
        }
      }

      const previewMode = trackedEvents > 0 ? "process-events"
        : candidateRows > 0 ? "candidate-rows"
        : "empty";
      const autoGenericFallback = trackedEvents === 0 && fullScopeTrackedEvents === 0 && candidateRows > 0;
      const useCandidateLinkingPreview = autoGenericFallback && !!candidateExprs.candidateExpr;

      // --- Provider mix ---
      const providerMix = {};
      if (uiEids.length > 0 && columns.provider && meta.colMap[columns.provider] && columns.eventId && meta.colMap[columns.eventId]) {
        const provSafe = meta.colMap[columns.provider];
        const eidSafe = meta.colMap[columns.eventId];
        const pmWhere = wc ? `${wc} AND` : "WHERE";
        if (eidNormalized) {
          const eidNormExpr = `CASE WHEN CAST(${eidSafe} AS INTEGER) IN (${uiEids.join(",")}) THEN CAST(${eidSafe} AS INTEGER) WHEN ${eidSafe} LIKE '%4688%' THEN 4688 WHEN ${eidSafe} LIKE '% 1' OR ${eidSafe} LIKE '% 1 %' OR ${eidSafe} = '1' THEN 1 ELSE NULL END`;
          const pmRows = db.prepare(`SELECT ${provSafe} as prov, COUNT(*) as cnt FROM data ${pmWhere} ${eidNormExpr} IS NOT NULL GROUP BY ${provSafe}`).all(...params);
          for (const r of pmRows) { if (r.prov) providerMix[String(r.prov).trim()] = r.cnt; }
        } else {
          const pmRows = db.prepare(`SELECT ${provSafe} as prov, COUNT(*) as cnt FROM data ${pmWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${provSafe}`).all(...params, ...uiEids);
          for (const r of pmRows) { if (r.prov) providerMix[String(r.prov).trim()] = r.cnt; }
        }
      }

      // --- Column quality (batched 2000-row sample, same as LM L2871-2903) ---
      const columnQuality = {};
      const qualityKeys = ["pid", "ppid", "guid", "parentGuid", "image", "parentImage", "cmdLine", "user", "ts", "eventId", "elevation", "integrity", "provider", "hostname"];
      const mappedCols = qualityKeys.filter(k => columns[k] && meta.colMap[columns[k]]).map(k => [k, columns[k]]);
      if (mappedCols.length > 0) {
        const caseParts = [];
        for (const [key, cn] of mappedCols) {
          const safe = meta.colMap[cn];
          caseParts.push(`SUM(CASE WHEN ${safe} IS NULL OR TRIM(${safe}) = '' OR ${safe} = '-' THEN 1 ELSE 0 END) as null_${key}`);
        }
        const batchSql = `SELECT COUNT(*) as total, ${caseParts.join(", ")} FROM (SELECT * FROM data ${wc} LIMIT 2000)`;
        const qr = db.prepare(batchSql).get(...params);
        const sampleTotal = qr ? qr.total : 0;
        for (const [key] of mappedCols) {
          const nulls = qr ? (qr[`null_${key}`] || 0) : 0;
          columnQuality[key] = { mapped: true, nullRate: sampleTotal > 0 ? Math.round((nulls / sampleTotal) * 100) : 0 };
        }
        for (const k of qualityKeys) { if (!columnQuality[k]) columnQuality[k] = { mapped: false }; }
      } else {
        for (const k of qualityKeys) columnQuality[k] = { mapped: false };
      }

      // --- Linking quality (PI-unique) ---
      const linkingQuality = { guidCoverage: 0, pidCoverage: 0, parentImageCoverage: 0, cmdLineCoverage: 0 };
      {
        // Build WHERE for process-creation events only — provider is secondary hint, not hard gate
        const lqWhere = [...whereConditions];
        let lqParams;
        if (useCandidateLinkingPreview) {
          lqWhere.push(candidateExprs.candidateExpr);
          lqParams = [...params];
        } else if (uiEids.length > 0 && columns.eventId && meta.colMap[columns.eventId]) {
          const eidSafe = meta.colMap[columns.eventId];
          if (eidNormalized) {
            const eidNormExpr = `CASE WHEN CAST(${eidSafe} AS INTEGER) IN (${uiEids.join(",")}) THEN CAST(${eidSafe} AS INTEGER) WHEN ${eidSafe} LIKE '%4688%' THEN 4688 WHEN ${eidSafe} LIKE '% 1' OR ${eidSafe} LIKE '% 1 %' OR ${eidSafe} = '1' THEN 1 ELSE NULL END`;
            lqWhere.push(`${eidNormExpr} IS NOT NULL`);
            lqParams = [...params];
          } else {
            lqWhere.push(`${eidSafe} IN (${uiEids.map(() => "?").join(",")})`);
            lqParams = [...params, ...uiEids];
          }
        } else {
          lqParams = [...params];
        }
        // Only add provider clause if provider-gated event counts succeeded (not in fallback mode)
        if (!useCandidateLinkingPreview && !providerFallback && !eidNormalized && isEvtxECmd && columns.provider && meta.colMap[columns.provider]) {
          const provSafe = meta.colMap[columns.provider];
          lqWhere.push(`(${provSafe} LIKE '%Sysmon%' OR ${provSafe} LIKE '%Security%')`);
        }
        const lqWc = lqWhere.length > 0 ? `WHERE ${lqWhere.join(" AND ")}` : "";

        const lqParts = ["COUNT(*) as total"];

        // GUID coverage
        if (isEvtxECmd) {
          // EvtxECmd: GUID is embedded in PayloadData1/PayloadData5
          const pd1Safe = columns.guid && meta.colMap[columns.guid] ? meta.colMap[columns.guid] : null;
          const pd5Safe = columns.parentGuid && meta.colMap[columns.parentGuid] ? meta.colMap[columns.parentGuid] : null;
          if (pd1Safe && pd5Safe) {
            lqParts.push(`SUM(CASE WHEN ${pd1Safe} LIKE '%ProcessGUID:%' AND ${pd5Safe} LIKE '%ParentProcessGUID:%' THEN 1 ELSE 0 END) as guid_pairs`);
            lqParts.push(`SUM(CASE WHEN ${pd1Safe} LIKE '%ProcessID:%' AND ${pd5Safe} LIKE '%ParentProcessID:%' THEN 1 ELSE 0 END) as pid_pairs`);
          }
        } else if (isHayabusa) {
          const detailsSafe = columns.details && meta.colMap[columns.details] ? meta.colMap[columns.details] : null;
          const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
          if (detailsSafe) {
            lqParts.push(`SUM(CASE WHEN (${detailsSafe} LIKE '%PGUID:%' OR ${detailsSafe} LIKE '%ProcessGuid:%') AND (${detailsSafe} LIKE '%ParentPGUID:%' OR ${detailsSafe} LIKE '%ParentProcessGuid:%') THEN 1 ELSE 0 END) as guid_pairs`);
            const parentPidExpr = extraSafe
              ? `(${detailsSafe} LIKE '%ParentPID:%' OR ${extraSafe} LIKE '%ProcessId:%')`
              : `(${detailsSafe} LIKE '%ParentPID:%')`;
            lqParts.push(`SUM(CASE WHEN ${detailsSafe} LIKE '%PID:%' AND ${parentPidExpr} THEN 1 ELSE 0 END) as pid_pairs`);
            lqParts.push(`SUM(CASE WHEN ${detailsSafe} LIKE '%Cmdline:%' THEN 1 ELSE 0 END) as has_cmdline`);
          }
          if (extraSafe) {
            lqParts.push(`SUM(CASE WHEN ${extraSafe} LIKE '%ParentImage:%' OR ${extraSafe} LIKE '%ParentProcessName:%' THEN 1 ELSE 0 END) as has_parent_image`);
          }
        } else {
          // Standard columns
          const gSafe = columns.guid && meta.colMap[columns.guid] ? meta.colMap[columns.guid] : null;
          const pgSafe = columns.parentGuid && meta.colMap[columns.parentGuid] ? meta.colMap[columns.parentGuid] : null;
          if (gSafe && pgSafe) {
            lqParts.push(`SUM(CASE WHEN ${gSafe} IS NOT NULL AND TRIM(${gSafe}) != '' AND ${pgSafe} IS NOT NULL AND TRIM(${pgSafe}) != '' THEN 1 ELSE 0 END) as guid_pairs`);
          }
          const pSafe = columns.pid && meta.colMap[columns.pid] ? meta.colMap[columns.pid] : null;
          const ppSafe = columns.ppid && meta.colMap[columns.ppid] ? meta.colMap[columns.ppid] : null;
          if (pSafe && ppSafe) {
            lqParts.push(`SUM(CASE WHEN ${pSafe} IS NOT NULL AND TRIM(${pSafe}) != '' AND ${ppSafe} IS NOT NULL AND TRIM(${ppSafe}) != '' THEN 1 ELSE 0 END) as pid_pairs`);
          }
        }
        // Parent image + command line coverage
        const piSafe = columns.parentImage && meta.colMap[columns.parentImage] ? meta.colMap[columns.parentImage] : null;
        if (piSafe) lqParts.push(`SUM(CASE WHEN ${piSafe} IS NOT NULL AND TRIM(${piSafe}) != '' AND ${piSafe} != '-' THEN 1 ELSE 0 END) as has_parent_image`);
        const clSafe = columns.cmdLine && meta.colMap[columns.cmdLine] ? meta.colMap[columns.cmdLine] : null;
        if (clSafe) lqParts.push(`SUM(CASE WHEN ${clSafe} IS NOT NULL AND TRIM(${clSafe}) != '' AND ${clSafe} != '-' THEN 1 ELSE 0 END) as has_cmdline`);

        const lqSql = `SELECT ${lqParts.join(", ")} FROM (SELECT * FROM data ${lqWc} LIMIT 2000)`;
        const lqr = db.prepare(lqSql).get(...lqParams);
        const total = lqr ? lqr.total : 0;
        if (total > 0) {
          linkingQuality.guidCoverage = lqr.guid_pairs != null ? Math.round((lqr.guid_pairs / total) * 100) : 0;
          linkingQuality.pidCoverage = lqr.pid_pairs != null ? Math.round((lqr.pid_pairs / total) * 100) : 0;
          linkingQuality.parentImageCoverage = lqr.has_parent_image != null ? Math.round((lqr.has_parent_image / total) * 100) : 0;
          linkingQuality.cmdLineCoverage = lqr.has_cmdline != null ? Math.round((lqr.has_cmdline / total) * 100) : 0;
        }
      }

      const linkingMode = linkingQuality.guidCoverage > 50 ? "guid"
        : linkingQuality.pidCoverage > 50 ? "pid-only"
        : "insufficient";

      // --- Top values for critical columns (sampled from first 2000 rows in scope) ---
      const topValues = {};
      const topCols = { eventId: columns.eventId, provider: columns.provider, image: columns.image, cmdLine: columns.cmdLine };
      for (const [key, cn] of Object.entries(topCols)) {
        if (!cn || !meta.colMap[cn]) continue;
        const safe = meta.colMap[cn];
        try {
          const tvRows = db.prepare(`SELECT ${safe} as v, COUNT(*) as cnt FROM (SELECT ${safe} FROM data ${wc} LIMIT 2000) WHERE ${safe} IS NOT NULL AND TRIM(${safe}) != '' GROUP BY ${safe} ORDER BY cnt DESC LIMIT 5`).all(...params);
          topValues[key] = tvRows.map(r => ({ value: String(r.v).substring(0, 120), count: r.cnt }));
        } catch (_) { /* ignore column errors */ }
      }

      // --- Data shape: hosts, users, date span ---
      const dataShape = {};
      try {
        // Host count
        const hostCol = columns.hostname || (isEvtxECmd ? (meta.headers.find(h => /^Computer$/i.test(h)) || null) : null);
        if (hostCol && meta.colMap[hostCol]) {
          const hSafe = meta.colMap[hostCol];
          const hr = db.prepare(`SELECT COUNT(DISTINCT ${hSafe}) as cnt FROM (SELECT ${hSafe} FROM data ${wc} LIMIT 5000)`).get(...params);
          dataShape.hosts = hr ? hr.cnt : 0;
        }
        // User count
        if (columns.user && meta.colMap[columns.user]) {
          const uSafe = meta.colMap[columns.user];
          const ur = db.prepare(`SELECT COUNT(DISTINCT ${uSafe}) as cnt FROM (SELECT ${uSafe} FROM data ${wc} WHERE ${uSafe} IS NOT NULL AND TRIM(${uSafe}) != '' AND ${uSafe} != '-' LIMIT 5000)`).get(...params);
          dataShape.users = ur ? ur.cnt : 0;
        }
        // Date span
        if (columns.ts && meta.colMap[columns.ts]) {
          const tSafe = meta.colMap[columns.ts];
          const dr = db.prepare(`SELECT MIN(${tSafe}) as mn, MAX(${tSafe}) as mx FROM data ${wc}`).get(...params);
          if (dr && dr.mn && dr.mx) { dataShape.dateMin = dr.mn; dataShape.dateMax = dr.mx; }
        }
        // Active filter count (from whereConditions minus the EID/provider auto-filters)
        dataShape.activeFilters = whereConditions.length;
      } catch (_) { /* ignore shape errors */ }

      // --- Sample rows for inline preview (20 rows, critical columns only) ---
      const sampleRows = [];
      try {
        const sampleCols = [];
        const sampleHeaders = [];
        for (const [key, label] of [["eventId", "Event ID"], ["provider", "Provider"], ["image", "Image"], ["cmdLine", "Command Line"], ["pid", "PID"], ["ppid", "PPID"], ["user", "User"], ["ts", "Timestamp"]]) {
          if (columns[key] && meta.colMap[columns[key]]) {
            sampleCols.push({ key, safe: meta.colMap[columns[key]] });
            sampleHeaders.push({ key, label, col: columns[key] });
          }
        }
        if (sampleCols.length > 0) {
          const selParts = sampleCols.map(c => `${c.safe} as [${c.key}]`).join(", ");
          const sRows = db.prepare(`SELECT ${selParts} FROM data ${wc} LIMIT 20`).all(...params);
          for (const r of sRows) {
            const row = {};
            for (const c of sampleCols) { row[c.key] = r[c.key] != null ? String(r[c.key]).substring(0, 200) : null; }
            sampleRows.push(row);
          }
        }
        dataShape.sampleHeaders = sampleHeaders;
      } catch (_) { /* ignore sample errors */ }

      const result = {
        eventCounts,
        fullScopeEventCounts,
        columnQuality,
        linkingQuality,
        linkingMode,
        trackedEvents,
        fullScopeTrackedEvents,
        candidateRows,
        fullScopeCandidateRows,
        linkableCandidateRows,
        previewMode,
        autoGenericFallback,
        providerMix,
        providerFallback,
        eidNormalized,
        topValues,
        dataShape,
        sampleRows,
        resolvedColumns: columns,
        isEvtxECmd,
        isHayabusa,
        isChainsaw,
      };
      this._ptPreviewCache.set(cacheKey, result);
      if (columns.eventId) setImmediate(() => { try { this._ensureIndex(tabId, columns.eventId); } catch (_) {} });
      return result;
    } catch (e) {
      return { eventCounts: {}, columnQuality: {}, linkingQuality: {}, error: e.message };
    }
  }

  getProcessInspectorContext(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { selected: null, timeline: [], groups: [], enrichmentChips: [], error: "No database" };

    const {
      rowId,
      selected = {},
      windowMinutes = 5,
      contextMinutes = 15,
      maxWindowRows = 500,
      maxExactRows = 200,
      maxTimelineRows = 120,
    } = options;

    const detect = (patterns) => {
      for (const pat of patterns) {
        const found = meta.headers.find((h) => pat.test(h));
        if (found) return found;
      }
      return null;
    };

    const isEvtxECmd = meta.headers.some((h) => /^PayloadData1$/i.test(h)) && meta.headers.some((h) => /^ExecutableInfo$/i.test(h));
    const isHayabusa = this._isHayabusaDataset(meta);
    const isChainsaw = this._isChainsawDataset(meta);
    const isChainsawProcess = this._isChainsawProcessDataset(meta);

    const columns = {
      pid: detect([/^ProcessId$/i, /^pid$/i, /^process_id$/i, /^NewProcessId$/i]),
      ppid: detect([/^ParentProcessId$/i, /^ppid$/i, /^parent_process_id$/i, /^parent_pid$/i, /^CreatorProcessId$/i]),
      guid: detect([/^ProcessGuid$/i, /^process_guid$/i]),
      parentGuid: detect([/^ParentProcessGuid$/i, /^parent_process_guid$/i]),
      image: detect([/^Image$/i, /^process_name$/i, /^exe$/i, /^FileName$/i, /^ImagePath$/i, /^NewProcessName$/i, ...(isChainsawProcess ? [/^Event\.EventData\.Image$/i] : [])]),
      parentImage: detect([/^ParentImage$/i, /^ParentProcessName$/i]),
      cmdLine: detect([/^CommandLine$/i, /^command_line$/i, /^cmd$/i, /^cmdline$/i, /^ProcessCommandLine$/i, ...(isChainsawProcess ? [/^Event\.EventData\.CommandLine$/i] : [])]),
      user: detect([/^User$/i, /^UserName$/i, /^user_name$/i, /^SubjectUserName$/i, /^TargetUserName$/i, ...(isChainsaw ? [/^target_username$/i] : [])]),
      ts: detect([/^UtcTime$/i, /^datetime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
      eventId: detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
      provider: detect([/^Provider$/i, /^SourceName$/i, /^Channel$/i]),
      hostname: detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, /^MachineName$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
      details: detect([/^Details$/i]),
      extra: detect([/^ExtraFieldInfo$/i]),
      payload: detect([/^Payload$/i, /^Message$/i, /^RenderedMessage$/i]),
      payload2: detect([/^PayloadData2$/i]),
      payload3: detect([/^PayloadData3$/i]),
      payload4: detect([/^PayloadData4$/i]),
      payload5: detect([/^PayloadData5$/i]),
      payload6: detect([/^PayloadData6$/i]),
      execInfo: detect([/^ExecutableInfo$/i]),
      logonId: detect([/^LogonId$/i, /^SubjectLogonId$/i, /^Subject_Logon_ID$/i, /^TargetLogonId$/i, /^Target_Logon_ID$/i]),
      targetLogonId: detect([/^TargetLogonId$/i, /^Target_Logon_ID$/i]),
      logonType: detect([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsaw ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]),
      sourceIp: detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^ClientAddress$/i, ...(isChainsaw ? [/^source_ip$/i] : [])]),
      workstation: detect([/^WorkstationName$/i, /^ClientName$/i, /^workstation_name$/i]),
      channel: detect([/^Channel$/i, /^SourceName$/i]),
      ruleTitle: detect([/^RuleTitle$/i]),
      detectionRule: detect([/^detection_rules$/i, /^DetectionRule$/i]),
    };

    if (isEvtxECmd) {
      columns.pid = detect([/^PayloadData1$/i]) || columns.pid;
      columns.ppid = detect([/^PayloadData5$/i]) || columns.ppid;
      columns.guid = detect([/^PayloadData1$/i]) || columns.guid;
      columns.parentGuid = detect([/^PayloadData5$/i]) || columns.parentGuid;
      columns.image = detect([/^ExecutableInfo$/i]) || columns.image;
      columns.cmdLine = detect([/^ExecutableInfo$/i]) || columns.cmdLine;
      columns.logonType = detect([/^PayloadData2$/i]) || columns.logonType;
    } else if (isHayabusa) {
      const detailsCol = detect([/^Details$/i]);
      const extraCol = detect([/^ExtraFieldInfo$/i]);
      columns.pid = detailsCol || columns.pid;
      columns.ppid = extraCol || detailsCol || columns.ppid;
      columns.guid = detailsCol || columns.guid;
      columns.parentGuid = detailsCol || columns.parentGuid;
      columns.image = detailsCol || columns.image;
      columns.parentImage = extraCol || detailsCol || columns.parentImage;
      columns.cmdLine = detailsCol || columns.cmdLine;
      columns.user = extraCol || detailsCol || columns.user;
      columns.logonId = extraCol || detailsCol || columns.logonId;
      columns.logonType = extraCol || detailsCol || columns.logonType;
    }

    const selectParts = ["data.rowid as _rowid"];
    const added = new Set();
    for (const [key, colName] of Object.entries(columns)) {
      if (!colName || !meta.colMap[colName] || added.has(colName)) continue;
      selectParts.push(`${meta.colMap[colName]} as [${key}]`);
      added.add(colName);
    }
    const selectSql = selectParts.join(", ");
    const db = meta.db;

    const clean = (value, opts = {}) => this._cleanWrappedField(value, opts);
    const normalizeHost = (value) => clean(value).replace(/^\\\\/, "").toUpperCase();
    const normalizeUser = (value) => {
      let v = clean(value);
      if (v.includes("\\")) v = v.split("\\").pop();
      return v.toLowerCase();
    };
    const normalizeGuid = (value) => clean(value).replace(/[{}]/g, "").toLowerCase();
    const normalizePid = (value) => this._extractFirstInteger(value);
    const normalizeLogonId = (value) => {
      const raw = clean(value);
      if (!raw) return "";
      if (/^0x[0-9a-f]+$/i.test(raw)) return String(parseInt(raw, 16));
      const intLike = this._extractFirstInteger(raw);
      return intLike || raw.toLowerCase();
    };
    const hexVariants = (value) => {
      const n = Number.parseInt(value, 10);
      if (!Number.isFinite(n) || n < 0) return [];
      return [`0x${n.toString(16)}`, `0X${n.toString(16).toUpperCase()}`];
    };
    const runQuery = (whereSql, params = [], limit = 200, orderSql = "ORDER BY data.rowid ASC") => {
      const capped = Math.max(1, Math.min(Number(limit) || 200, 2000));
      const rows = db.prepare(`SELECT ${selectSql} FROM data ${whereSql} ${orderSql} LIMIT ${capped}`).all(...params);
      return rows;
    };

    const selectedRaw = rowId ? db.prepare(`SELECT ${selectSql} FROM data WHERE data.rowid = ? LIMIT 1`).get(Number(rowId)) : null;

    const normalizeEvent = (row, fallback = {}) => {
      if (!row && !fallback) return null;

      const compact = this._parseCompactKeyValues(row?.details, row?.extra);
      const haystack = row ? this._buildEvtxHaystack(row) : "";

      let pid = row?.pid || fallback.pid || "";
      let ppid = row?.ppid || fallback.ppid || "";
      let guid = row?.guid || fallback.guid || "";
      let parentGuid = row?.parentGuid || fallback.parentGuid || "";
      let image = row?.image || fallback.image || "";
      let cmdLine = row?.cmdLine || fallback.cmdLine || "";
      let parentImage = row?.parentImage || fallback.parentImage || "";
      let user = row?.user || fallback.user || "";
      let logonType = row?.logonType || "";
      let logonId = row?.logonId || row?.targetLogonId || "";

      if (isEvtxECmd && row) {
        const pd1 = row.pid || row.guid || "";
        const pd5 = row.ppid || row.parentGuid || "";
        const pidMatch = String(pd1).match(/ProcessID:\s*(\d+)/i);
        const guidMatch = String(pd1).match(/ProcessGUID:\s*([0-9a-f-]+)/i);
        const ppidMatch = String(pd5).match(/ParentProcessID:\s*(\d+)/i);
        const pguidMatch = String(pd5).match(/ParentProcessGUID:\s*([0-9a-f-]+)/i);
        if (pidMatch) pid = pidMatch[1];
        if (guidMatch) guid = guidMatch[1];
        if (ppidMatch) ppid = ppidMatch[1];
        if (pguidMatch) parentGuid = pguidMatch[1];
        const execInfo = row.image || row.cmdLine || row.execInfo || "";
        cmdLine = execInfo || cmdLine;
        if (execInfo) {
          const qm = String(execInfo).match(/^"([^"]+)"/);
          image = qm ? qm[1] : String(execInfo).split(/\s+/)[0];
        }
        if (!logonType && row.logonType) {
          const lt = String(row.logonType).match(/LogonType\s+(\d+)/i);
          if (lt) logonType = lt[1];
        }
      } else if (isHayabusa && row) {
        pid = this._compactGetInt(compact, "PID", "ProcessId", "NewProcessId") || pid;
        const eventId = String(row.eventId || "").trim();
        ppid = (eventId === "4688"
          ? this._compactGetInt(compact, "ProcessId", "CreatorProcessId", "ParentPID", "ParentProcessId")
          : this._compactGetInt(compact, "ParentPID", "ParentProcessId", "CreatorProcessId")) || ppid;
        guid = this._compactGet(compact, "PGUID", "ProcessGuid", "ProcessGUID") || guid;
        parentGuid = this._compactGet(compact, "ParentPGUID", "ParentProcessGuid", "ParentProcessGUID") || parentGuid;
        image = this._compactGet(compact, "Proc", "Image", "NewProcessName", "ProcessName") || image;
        cmdLine = this._compactGet(compact, "Cmdline", "CommandLine", "ProcessCommandLine") || cmdLine;
        parentImage = this._compactGet(compact, "ParentImage", "ParentProcessName") || parentImage;
        user = this._compactGet(compact, "SubjectUserName", "TargetUserName", "TgtUser", "User", "SrcUser") || user;
        logonType = this._compactGet(compact, "LogonType", "Type") || logonType;
        logonId = this._compactGet(compact, "SubjectLogonId", "TargetLogonId", "LogonId", "LID", "SessionId", "Session ID") || logonId;
      } else if (isChainsaw && row) {
        pid = this._extractFirstInteger(row.pid || pid);
        ppid = this._extractFirstInteger(row.ppid || ppid);
        guid = clean(row.guid || guid);
        parentGuid = clean(row.parentGuid || parentGuid);
        image = clean(row.image || image);
        cmdLine = clean(row.cmdLine || cmdLine);
        parentImage = clean(row.parentImage || parentImage);
        user = clean(row.user || user);
        logonType = this._extractFirstInteger(row.logonType || logonType) || clean(row.logonType || logonType);
      } else if (row) {
        pid = normalizePid(pid) || this._compactGetInt(compact, "PID", "ProcessId", "NewProcessId");
        ppid = normalizePid(ppid) || this._compactGetInt(compact, "ParentPID", "ParentProcessId", "CreatorProcessId", "ProcessId");
        guid = clean(guid) || this._compactGet(compact, "PGUID", "ProcessGuid", "ProcessGUID");
        parentGuid = clean(parentGuid) || this._compactGet(compact, "ParentPGUID", "ParentProcessGuid", "ParentProcessGUID");
        image = clean(image) || this._compactGet(compact, "Proc", "Image", "NewProcessName", "ProcessName", "Path");
        cmdLine = clean(cmdLine) || this._compactGet(compact, "Cmdline", "CommandLine", "ProcessCommandLine", "HostApplication");
        parentImage = clean(parentImage) || this._compactGet(compact, "ParentImage", "ParentProcessName");
        user = clean(user) || this._compactGet(compact, "SubjectUserName", "TargetUserName", "TgtUser", "User", "SrcUser", "AccountName");
        logonType = this._extractFirstInteger(logonType) || this._compactGet(compact, "LogonType", "Type");
        logonId = clean(logonId) || this._compactGet(compact, "SubjectLogonId", "TargetLogonId", "LogonId", "LID", "SessionId", "Session ID");
      }

      if (!image && cmdLine) {
        const qm = String(cmdLine).match(/^"([^"]+)"/);
        image = qm ? qm[1] : String(cmdLine).split(/\s+/)[0];
      }
      if (!cmdLine && image) cmdLine = image;

      const eventId = this._extractFirstInteger(row?.eventId || row?.id || fallback.eventId || "");
      const hostname = clean(row?.hostname || fallback.hostname || "");
      const timestamp = clean(row?.ts || fallback.ts || "");
      const tsMs = timestamp ? new Date(timestamp).getTime() : NaN;
      const procName = clean((image || fallback.processName || "").split(/[\\/]/).pop());
      const parentProcName = clean((parentImage || fallback.parentProcessName || "").split(/[\\/]/).pop());
      const channel = this._resolveEventChannel({
        eventId,
        provider: row?.provider || row?.channel || fallback.provider || "",
        channel: row?.channel || row?.provider || fallback.provider || "",
        source: row?.sourceIp || row?.payload2 || "",
        workstation: row?.workstation || "",
        user,
        logonType,
      });

      const enrichmentType = (() => {
        if (eventId === "4104") return "powershell";
        if (eventId === "7045" || eventId === "4697") return "service";
        if (eventId === "4698" || eventId === "4702") return "task";
        if (eventId === "4624" || eventId === "4648" || eventId === "4672") return "logon";
        if (eventId === "4689" || (eventId === "5" && channel === "sysmon")) return "terminate";
        return null;
      })();

      const eventLabel = (() => {
        if (eventId === "4104") return "PowerShell 4104";
        if (eventId === "7045") return "Service Install";
        if (eventId === "4697") return "Service Install (Security)";
        if (eventId === "4698") return "Task Created";
        if (eventId === "4702") return "Task Updated";
        if (eventId === "4624") return "Logon Success";
        if (eventId === "4648") return "Explicit Credentials";
        if (eventId === "4672") return "Admin Privileges";
        if (eventId === "4689") return "Process Terminated";
        if (eventId === "5" && channel === "sysmon") return "Sysmon Process Terminated";
        return eventId ? `Event ${eventId}` : "Event";
      })();

      const summary = (() => {
        const parts = [];
        if (enrichmentType === "powershell") {
          const scriptText = this._compactGet(compact, "ScriptBlockText", "ScriptBlock", "HostApplication");
          if (scriptText) return clean(scriptText, { lineJoiner: " | " }).slice(0, 240);
        }
        if (enrichmentType === "service") {
          const svc = this._compactGet(compact, "Svc", "ServiceName", "param1");
          const pathValue = this._compactGet(compact, "Path", "ImagePath", "ServiceFileName");
          if (svc) parts.push(svc);
          if (pathValue) parts.push(pathValue);
        } else if (enrichmentType === "task") {
          const taskName = this._compactGet(compact, "Task", "TaskName", "Name");
          const action = this._compactGet(compact, "Command", "Action", "Actions");
          if (taskName) parts.push(taskName);
          if (action) parts.push(action);
        } else if (enrichmentType === "logon") {
          if (user) parts.push(user);
          if (logonType) parts.push(`Type ${logonType}`);
          const src = this._compactGet(compact, "IpAddress", "SourceNetworkAddress", "ClientAddress", "SrcIP") || clean(row?.sourceIp || "");
          const wk = this._compactGet(compact, "WorkstationName", "ClientName", "SrcComp") || clean(row?.workstation || "");
          if (src) parts.push(src);
          else if (wk) parts.push(wk);
        } else if (enrichmentType === "terminate") {
          if (procName) parts.push(procName);
          if (image) parts.push(image);
        }
        if (parts.length > 0) return parts.join(" | ").slice(0, 240);
        return clean(cmdLine || image || haystack || procName, { lineJoiner: " | " }).replace(/\s+/g, " ").slice(0, 240);
      })();

      return {
        rowid: Number(row?._rowid || fallback.rowid || 0),
        timestamp,
        tsMs: Number.isFinite(tsMs) ? tsMs : 0,
        hostname,
        normHost: normalizeHost(hostname),
        user: clean(user),
        normUser: normalizeUser(user),
        pid: normalizePid(pid),
        ppid: normalizePid(ppid),
        guid: normalizeGuid(guid),
        parentGuid: normalizeGuid(parentGuid),
        image: clean(image),
        parentImage: clean(parentImage),
        processName: procName || clean(fallback.processName || ""),
        parentProcessName: parentProcName || clean(fallback.parentProcessName || ""),
        cmdLine: clean(cmdLine, { lineJoiner: " | " }),
        provider: clean(row?.provider || row?.channel || fallback.provider || ""),
        channel,
        eventId,
        eventLabel,
        enrichmentType,
        summary,
        logonType: this._extractFirstInteger(logonType) || clean(logonType),
        logonId: normalizeLogonId(logonId),
        sourceRow: row ? true : false,
      };
    };

    try {
      const selectedEvent = normalizeEvent(selectedRaw, selected);
      if (!selectedEvent) return { selected: null, timeline: [], groups: [], enrichmentChips: [], error: "No selected process" };

      const rowsById = new Map();
      const addRows = (rows) => {
        for (const row of (rows || [])) {
          const rid = Number(row?._rowid || 0);
          if (!rid || rowsById.has(rid)) continue;
          rowsById.set(rid, row);
        }
      };
      if (selectedRaw) addRows([selectedRaw]);

      if (selectedEvent.normHost && selectedEvent.tsMs && columns.hostname && meta.colMap[columns.hostname] && columns.ts && meta.colMap[columns.ts]) {
        const hostSafe = meta.colMap[columns.hostname];
        const tsSafe = meta.colMap[columns.ts];
        const fromIso = new Date(selectedEvent.tsMs - (Math.max(1, Number(windowMinutes) || 5) * 60000)).toISOString();
        const toIso = new Date(selectedEvent.tsMs + (Math.max(1, Number(windowMinutes) || 5) * 60000)).toISOString();
        addRows(runQuery(
          `WHERE UPPER(TRIM(CAST(${hostSafe} AS TEXT))) = UPPER(TRIM(?)) AND sort_datetime(${tsSafe}) >= sort_datetime(?) AND sort_datetime(${tsSafe}) <= sort_datetime(?)`,
          [selectedEvent.hostname, fromIso, toIso],
          maxWindowRows,
          `ORDER BY sort_datetime(${tsSafe}) ASC, data.rowid ASC`
        ));
      }

      if (selectedEvent.normHost && selectedEvent.normUser && selectedEvent.tsMs && columns.hostname && meta.colMap[columns.hostname] && columns.ts && meta.colMap[columns.ts] && columns.user && meta.colMap[columns.user]) {
        const hostSafe = meta.colMap[columns.hostname];
        const tsSafe = meta.colMap[columns.ts];
        const userSafe = meta.colMap[columns.user];
        const fromIso = new Date(selectedEvent.tsMs - (Math.max(1, Number(contextMinutes) || 15) * 60000)).toISOString();
        const toIso = new Date(selectedEvent.tsMs + (Math.max(1, Number(contextMinutes) || 15) * 60000)).toISOString();
        const rawUser = clean(selectedEvent.user || "");
        const baseUser = rawUser.includes("\\") ? rawUser.split("\\").pop() : rawUser;
        const userClauses = [];
        const userParams = [selectedEvent.hostname, fromIso, toIso];
        if (rawUser) {
          userClauses.push(`LOWER(TRIM(CAST(${userSafe} AS TEXT))) = LOWER(?)`);
          userParams.push(rawUser);
        }
        if (baseUser && baseUser.toLowerCase() !== rawUser.toLowerCase()) {
          userClauses.push(`LOWER(TRIM(CAST(${userSafe} AS TEXT))) = LOWER(?)`);
          userParams.push(baseUser);
          userClauses.push(`LOWER(TRIM(CAST(${userSafe} AS TEXT))) LIKE LOWER(?)`);
          userParams.push(`%\\${baseUser}`);
        }
        if (userClauses.length > 0) {
          addRows(runQuery(
            `WHERE UPPER(TRIM(CAST(${hostSafe} AS TEXT))) = UPPER(TRIM(?)) AND sort_datetime(${tsSafe}) >= sort_datetime(?) AND sort_datetime(${tsSafe}) <= sort_datetime(?) AND (${userClauses.join(" OR ")})`,
            userParams,
            maxExactRows,
            `ORDER BY sort_datetime(${tsSafe}) ASC, data.rowid ASC`
          ));
        }
      }

      const pidVariants = selectedEvent.pid ? [selectedEvent.pid, ...hexVariants(selectedEvent.pid)] : [];
      const ppidVariants = selectedEvent.ppid ? [selectedEvent.ppid, ...hexVariants(selectedEvent.ppid)] : [];
      const hostClause = selectedEvent.normHost && columns.hostname && meta.colMap[columns.hostname]
        ? ` AND UPPER(TRIM(CAST(${meta.colMap[columns.hostname]} AS TEXT))) = UPPER(TRIM(?))`
        : "";
      const hostParams = hostClause ? [selectedEvent.hostname] : [];

      if (selectedEvent.guid) {
        if (isEvtxECmd && columns.pid && meta.colMap[columns.pid] && columns.ppid && meta.colMap[columns.ppid]) {
          addRows(runQuery(
            `WHERE (${meta.colMap[columns.pid]} LIKE ? OR ${meta.colMap[columns.ppid]} LIKE ?)${hostClause}`,
            [`%${selectedEvent.guid}%`, `%${selectedEvent.guid}%`, ...hostParams],
            maxExactRows
          ));
        } else if (isHayabusa && columns.details && meta.colMap[columns.details]) {
          const detailsSafe = meta.colMap[columns.details];
          const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
          addRows(runQuery(
            `WHERE (${detailsSafe} LIKE ?${extraSafe ? ` OR ${extraSafe} LIKE ?` : ""})${hostClause}`,
            extraSafe
              ? [`%${selectedEvent.guid}%`, `%${selectedEvent.guid}%`, ...hostParams]
              : [`%${selectedEvent.guid}%`, ...hostParams],
            maxExactRows
          ));
        } else {
          const guidClauses = [];
          const params = [];
          if (columns.guid && meta.colMap[columns.guid]) {
            guidClauses.push(`LOWER(TRIM(CAST(${meta.colMap[columns.guid]} AS TEXT))) = LOWER(?)`);
            params.push(selectedEvent.guid);
          }
          if (columns.parentGuid && meta.colMap[columns.parentGuid]) {
            guidClauses.push(`LOWER(TRIM(CAST(${meta.colMap[columns.parentGuid]} AS TEXT))) = LOWER(?)`);
            params.push(selectedEvent.guid);
          }
          if (guidClauses.length > 0) addRows(runQuery(`WHERE (${guidClauses.join(" OR ")})${hostClause}`, [...params, ...hostParams], maxExactRows));
        }
      }

      if ((pidVariants.length > 0 || ppidVariants.length > 0) && (columns.pid || columns.ppid)) {
        if (isEvtxECmd && columns.pid && meta.colMap[columns.pid] && columns.ppid && meta.colMap[columns.ppid]) {
          const pidLikes = [];
          const params = [];
          for (const pv of pidVariants) {
            pidLikes.push(`${meta.colMap[columns.pid]} LIKE ?`);
            params.push(`%ProcessID: ${pv}%`);
            pidLikes.push(`${meta.colMap[columns.ppid]} LIKE ?`);
            params.push(`%ParentProcessID: ${pv}%`);
          }
          for (const pv of ppidVariants) {
            pidLikes.push(`${meta.colMap[columns.pid]} LIKE ?`);
            params.push(`%ProcessID: ${pv}%`);
            pidLikes.push(`${meta.colMap[columns.ppid]} LIKE ?`);
            params.push(`%ParentProcessID: ${pv}%`);
          }
          if (pidLikes.length > 0) addRows(runQuery(`WHERE (${pidLikes.join(" OR ")})${hostClause}`, [...params, ...hostParams], maxExactRows));
        } else if (isHayabusa && columns.details && meta.colMap[columns.details]) {
          const detailsSafe = meta.colMap[columns.details];
          const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
          const pidLikes = [];
          const params = [];
          for (const pv of [...pidVariants, ...ppidVariants]) {
            pidLikes.push(`${detailsSafe} LIKE ?`);
            params.push(`%${pv}%`);
            if (extraSafe) {
              pidLikes.push(`${extraSafe} LIKE ?`);
              params.push(`%${pv}%`);
            }
          }
          if (pidLikes.length > 0) addRows(runQuery(`WHERE (${pidLikes.join(" OR ")})${hostClause}`, [...params, ...hostParams], maxExactRows));
        } else {
          const pidClauses = [];
          const params = [];
          const addExactNumeric = (safeCol, values) => {
            if (!safeCol || values.length === 0) return;
            pidClauses.push(`LOWER(TRIM(CAST(${safeCol} AS TEXT))) IN (${values.map(() => "LOWER(?)").join(",")})`);
            params.push(...values);
          };
          if (columns.pid && meta.colMap[columns.pid]) addExactNumeric(meta.colMap[columns.pid], [...pidVariants, ...ppidVariants]);
          if (columns.ppid && meta.colMap[columns.ppid]) addExactNumeric(meta.colMap[columns.ppid], [...pidVariants, ...ppidVariants]);
          if (pidClauses.length > 0) addRows(runQuery(`WHERE (${pidClauses.join(" OR ")})${hostClause}`, [...params, ...hostParams], maxExactRows));
        }
      }

      if (selectedEvent.logonId) {
        if (columns.logonId && meta.colMap[columns.logonId]) {
          addRows(runQuery(
            `WHERE LOWER(TRIM(CAST(${meta.colMap[columns.logonId]} AS TEXT))) = LOWER(?)${hostClause}`,
            [selectedEvent.logonId, ...hostParams],
            maxExactRows
          ));
        } else if (isHayabusa && columns.details && meta.colMap[columns.details]) {
          const detailsSafe = meta.colMap[columns.details];
          const extraSafe = columns.extra && meta.colMap[columns.extra] ? meta.colMap[columns.extra] : null;
          addRows(runQuery(
            `WHERE (${detailsSafe} LIKE ?${extraSafe ? ` OR ${extraSafe} LIKE ?` : ""})${hostClause}`,
            extraSafe
              ? [`%${selectedEvent.logonId}%`, `%${selectedEvent.logonId}%`, ...hostParams]
              : [`%${selectedEvent.logonId}%`, ...hostParams],
            maxExactRows
          ));
        }
      }

      const events = [...rowsById.values()]
        .map((row) => normalizeEvent(row))
        .filter(Boolean)
        .sort((a, b) => (a.tsMs || Number.MAX_SAFE_INTEGER) - (b.tsMs || Number.MAX_SAFE_INTEGER) || a.rowid - b.rowid);

      const windowMs = Math.max(1, Number(windowMinutes) || 5) * 60000;
      const contextMs = Math.max(1, Number(contextMinutes) || 15) * 60000;
      const selectedHost = selectedEvent.normHost;
      const selectedPid = selectedEvent.pid;
      const selectedPpid = selectedEvent.ppid;
      const selectedGuid = selectedEvent.guid;
      const selectedParentGuid = selectedEvent.parentGuid;
      const selectedUser = selectedEvent.normUser;
      const selectedLogonId = selectedEvent.logonId;

      const relatedEvents = events.filter((evt) => {
        const matchTypes = [];
        if (evt.rowid === selectedEvent.rowid && selectedEvent.rowid) matchTypes.push("selected");
        if (selectedHost && selectedEvent.tsMs && evt.normHost === selectedHost && evt.tsMs && Math.abs(evt.tsMs - selectedEvent.tsMs) <= windowMs) matchTypes.push("hostWindow");
        if (selectedHost && selectedPid && evt.normHost === selectedHost && (evt.pid === selectedPid || evt.ppid === selectedPid)) matchTypes.push("samePid");
        if (selectedHost && selectedPpid && evt.normHost === selectedHost && (evt.pid === selectedPpid || evt.ppid === selectedPpid)) matchTypes.push("samePpid");
        if (selectedGuid && (evt.guid === selectedGuid || evt.parentGuid === selectedGuid)) matchTypes.push("sameGuid");
        if (selectedParentGuid && (evt.guid === selectedParentGuid || evt.parentGuid === selectedParentGuid)) matchTypes.push("sameParentGuid");
        if (selectedHost && selectedUser && evt.normHost === selectedHost && evt.normUser === selectedUser && evt.tsMs && selectedEvent.tsMs && Math.abs(evt.tsMs - selectedEvent.tsMs) <= contextMs) matchTypes.push("sameUser");
        if (selectedLogonId && evt.logonId && evt.logonId === selectedLogonId) matchTypes.push("sameLogon");
        if (evt.enrichmentType && selectedHost && evt.normHost === selectedHost && evt.tsMs && selectedEvent.tsMs && Math.abs(evt.tsMs - selectedEvent.tsMs) <= contextMs) matchTypes.push("enrichment");
        evt.matchTypes = [...new Set(matchTypes)];
        evt.isSelected = evt.matchTypes.includes("selected");
        return evt.matchTypes.length > 0;
      });

      const groupDefs = [
        {
          id: "hostWindow",
          label: `Same host +/-${Math.max(1, Number(windowMinutes) || 5)}m`,
          test: (evt) => evt.matchTypes.includes("hostWindow") && !evt.isSelected,
        },
        {
          id: "pidGuid",
          label: "Same PID / PPID / GUID",
          test: (evt) => !evt.isSelected && (
            evt.matchTypes.includes("samePid")
            || evt.matchTypes.includes("samePpid")
            || evt.matchTypes.includes("sameGuid")
            || evt.matchTypes.includes("sameParentGuid")
          ),
        },
        {
          id: "userLogon",
          label: "Same user / logon context",
          test: (evt) => !evt.isSelected && (evt.matchTypes.includes("sameUser") || evt.matchTypes.includes("sameLogon")),
        },
      ];

      const groups = groupDefs.map((group) => {
        const matches = relatedEvents.filter(group.test);
        return {
          id: group.id,
          label: group.label,
          count: matches.length,
          rows: matches.slice(0, 12),
        };
      }).filter((group) => group.count > 0);

      const enrichmentCounts = new Map();
      for (const evt of relatedEvents) {
        if (!evt.enrichmentType || evt.isSelected) continue;
        const key = evt.enrichmentType;
        const cur = enrichmentCounts.get(key) || { id: key, label: evt.eventLabel, count: 0 };
        cur.count += 1;
        if (
          key === "service"
          || key === "task"
          || key === "powershell"
          || key === "logon"
          || key === "terminate"
        ) cur.label = {
          powershell: "4104",
          service: "7045 / 4697",
          task: "4698 / 4702",
          logon: "4624 / 4648 / 4672",
          terminate: "4689 / Sysmon 5",
        }[key];
        enrichmentCounts.set(key, cur);
      }

      const timeline = relatedEvents
        .sort((a, b) => (a.tsMs || Number.MAX_SAFE_INTEGER) - (b.tsMs || Number.MAX_SAFE_INTEGER) || a.rowid - b.rowid)
        .slice(0, Math.max(10, Math.min(Number(maxTimelineRows) || 120, 300)));

      return {
        selected: selectedEvent,
        timeline,
        groups,
        enrichmentChips: [...enrichmentCounts.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)),
        stats: {
          totalRelated: relatedEvents.filter((evt) => !evt.isSelected).length,
          timelineCount: timeline.length,
        },
        columns: {
          hostname: columns.hostname || null,
          ts: columns.ts || null,
          eventId: columns.eventId || null,
          provider: columns.provider || null,
        },
      };
    } catch (e) {
      return { selected: null, timeline: [], groups: [], enrichmentChips: [], error: e.message };
    }
  }

  previewLateralMovement(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { eventCounts: {}, columnQuality: {}, error: "No database" };
    const {
      sourceCol, targetCol, userCol, logonTypeCol, eventIdCol, tsCol, domainCol,
      syntheticTargetHost = "",
      excludeLocalLogons = false, excludeServiceAccounts = false,
    } = options;
    const detect = (patterns) => { for (const p of patterns) { const f = meta.headers.find((h) => p.test(h)); if (f) return f; } return null; };
    const isEvtxECmd = meta.headers.some((h) => /^RemoteHost$/i.test(h)) && meta.headers.some((h) => /^PayloadData1$/i.test(h));
    const isHayabusa = this._isHayabusaDataset(meta);
    const isChainsaw = this._isChainsawLogonDataset(meta);
    const detailsCol = isHayabusa ? detect([/^Details$/i]) : null;
    const extraCol = isHayabusa ? detect([/^ExtraFieldInfo$/i]) : null;
    const cols = {
      source: sourceCol || detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^Source_Network_Address$/i, /^RemoteHost$/i, ...(isChainsaw ? [/^source_ip$/i] : [])]) || detailsCol,
      target: targetCol || detect([/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]),
      user: userCol || detect([/^TargetUserName$/i, /^Target_User_Name$/i, /^UserName$/i, ...(isChainsaw ? [/^target_username$/i] : []), ...(isEvtxECmd ? [/^PayloadData1$/i] : [])]) || detailsCol,
      logonType: logonTypeCol || detect([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsaw ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]) || detailsCol,
      eventId: eventIdCol || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
      ts: tsCol || detect([/^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
      domain: domainCol || detect([/^TargetDomainName$/i, /^Target_Domain_Name$/i, /^SubjectDomainName$/i]) || extraCol || detailsCol,
      details: detailsCol,
      extra: extraCol,
    };
    cols._isChainsaw = isChainsaw;
    cols._syntheticTarget = !cols.target && (syntheticTargetHost || isChainsaw) ? (syntheticTargetHost || "LOCAL_HOST") : "";
    try {
      const db = meta.db;
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);
      // Scope exclusions matching the analyzer's in-memory filters (getLateralMovement lines ~3127-3128)
      if (excludeLocalLogons && cols.source && meta.colMap[cols.source] && cols.target && meta.colMap[cols.target]) {
        // Analyzer skips when parsed sourceHost === targetHost but keeps rows where either is null/blank.
        // Use OR NULL guards so SQL doesn't drop null-source/null-target rows.
        const sc = meta.colMap[cols.source], tc = meta.colMap[cols.target];
        whereConditions.push(`(${sc} IS NULL OR TRIM(${sc}) = '' OR ${tc} IS NULL OR TRIM(${tc}) = '' OR UPPER(TRIM(${sc})) != UPPER(TRIM(${tc})))`);
      }
      if (excludeServiceAccounts && cols.user && meta.colMap[cols.user]) {
        // Match SERVICE_RE from analyzer: SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM-*, UMFD-*, ANONYMOUS LOGON, plus machine accounts (*$)
        const uc = meta.colMap[cols.user];
        whereConditions.push(`(${uc} IS NULL OR (${uc} NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') AND ${uc} NOT LIKE 'DWM-%' AND ${uc} NOT LIKE 'UMFD-%' AND ${uc} NOT LIKE '%$'))`);
      }
      const wc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

      // Cache key — return cached result if inputs unchanged
      const cacheKey = JSON.stringify([tabId, cols, wc, params]);
      if (!this._lmPreviewCache) this._lmPreviewCache = new Map();
      if (this._lmPreviewCache.size > 50) { const first = this._lmPreviewCache.keys().next().value; this._lmPreviewCache.delete(first); }
      const cached = this._lmPreviewCache.get(cacheKey);
      if (cached) return cached;

      // Event ID counts — single grouped query, only EIDs shown in the UI
      const eventCounts = {};
      let trackedEvents = 0;
      if (cols.eventId && meta.colMap[cols.eventId]) {
        const eidSafe = meta.colMap[cols.eventId];
        const uiEids = ["4624","4625","4648","4672","4769","1149","21","22","25","4698","5140","5145","7045","4697","4688","1"];
        const eidWhere = wc ? `${wc} AND` : "WHERE";
        const eidRows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${eidSafe}`).all(...params, ...uiEids);
        for (const r of eidRows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = r.cnt; trackedEvents += r.cnt; } }
      }

      // Column quality — single batched query sampling 2000 rows
      const columnQuality = {};
      const mappedCols = Object.entries(cols).filter(([, cn]) => cn && meta.colMap[cn]);
      if (mappedCols.length > 0) {
        const caseParts = [];
        for (const [key, cn] of mappedCols) {
          const safe = meta.colMap[cn];
          caseParts.push(`SUM(CASE WHEN ${safe} IS NULL OR TRIM(${safe}) = '' OR ${safe} = '-' THEN 1 ELSE 0 END) as null_${key}`);
        }
        // Source IP-only check: count IP-pattern values inline
        const srcSafe = cols.source && meta.colMap[cols.source] ? meta.colMap[cols.source] : null;
        if (srcSafe) {
          caseParts.push(`SUM(CASE WHEN ${srcSafe} IS NOT NULL AND TRIM(${srcSafe}) != '' AND ${srcSafe} != '-' AND ${srcSafe} GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN 1 ELSE 0 END) as src_ip`);
          caseParts.push(`SUM(CASE WHEN ${srcSafe} IS NOT NULL AND TRIM(${srcSafe}) != '' AND ${srcSafe} != '-' THEN 1 ELSE 0 END) as src_nonnull`);
        }
        const batchSql = `SELECT COUNT(*) as total, ${caseParts.join(", ")} FROM (SELECT * FROM data ${wc} LIMIT 2000)`;
        const qr = db.prepare(batchSql).get(...params);
        const sampleTotal = qr ? qr.total : 0;
        for (const [key, cn] of mappedCols) {
          const nulls = qr ? (qr[`null_${key}`] || 0) : 0;
          const qi = { mapped: true, nullRate: sampleTotal > 0 ? Math.round((nulls / sampleTotal) * 100) : 0 };
          if (key === "source" && srcSafe && qr && qr.src_nonnull > 0) {
            qi.ipOnlyRate = Math.round(((qr.src_ip || 0) / qr.src_nonnull) * 100);
          }
          columnQuality[key] = qi;
        }
        // Mark unmapped columns
        for (const [key, cn] of Object.entries(cols)) {
          if (!cn || !meta.colMap[cn]) columnQuality[key] = { mapped: false };
        }
      } else {
        for (const key of Object.keys(cols)) columnQuality[key] = { mapped: false };
      }

      const result = { eventCounts, columnQuality, trackedEvents, resolvedColumns: cols, isHayabusa, isEvtxECmd, isChainsaw };
      this._lmPreviewCache.set(cacheKey, result);
      // Opportunistically create eventId index after returning — speeds up future queries
      if (cols.eventId) setImmediate(() => { try { this._ensureIndex(tabId, cols.eventId); } catch (_) {} });
      return result;
    } catch (e) {
      return { eventCounts: {}, columnQuality: {}, error: e.message };
    }
  }

  getLateralMovement(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { nodes: [], edges: [], chains: [], stats: {}, columns: {}, error: "No database" };

    const {
      sourceCol: userSourceCol, targetCol: userTargetCol,
      userCol: userUserCol, logonTypeCol: userLogonTypeCol,
      eventIdCol: userEventIdCol, tsCol: userTsCol, domainCol: userDomainCol,
      syntheticTargetHost = "",
      eventIds = ["4624","4625","4634","4647","4648","4672","4769","4778","4779","5140","5145","1149","21","22","23","24","25","39","40"],
      excludeLocalLogons = true,
      excludeServiceAccounts = true,
      maxRows = 500000,
      disabledDetectors = [],
      rmmMode = "all",
      scanLimits = {},
      scanPageSize = 5000,
      requireMicrosoftSignature = false,
    } = options;
    const _disabledSet = new Set(disabledDetectors);

    const detect = (patterns) => {
      for (const pat of patterns) {
        const found = meta.headers.find((h) => pat.test(h));
        if (found) return found;
      }
      return null;
    };

    // Detect EvtxECmd format (KAPE output): RemoteHost, PayloadData1-6
    const isEvtxECmd = meta.headers.some((h) => /^RemoteHost$/i.test(h)) && meta.headers.some((h) => /^PayloadData1$/i.test(h));
    const isHayabusa = this._isHayabusaDataset(meta);
    const isChainsaw = this._isChainsawLogonDataset(meta);
    const detailsCol = isHayabusa ? detect([/^Details$/i]) : null;
    const extraCol = isHayabusa ? detect([/^ExtraFieldInfo$/i]) : null;

    const columns = {
      source:      userSourceCol    || detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^Source_Network_Address$/i, /^RemoteHost$/i, ...(isChainsaw ? [/^source_ip$/i] : [])]) || detailsCol,
      workstation: detect([/^WorkstationName$/i, /^Workstation_Name$/i, /^SourceHostname$/i, /^SourceComputerName$/i, ...(isChainsaw ? [/^workstation_name$/i] : [])]),
      target:      userTargetCol    || detect([/^Computer$/i, /^ComputerName$/i, /^computer_name$/i, /^Hostname$/i]),
      user:        userUserCol      || detect([/^TargetUserName$/i, /^Target_User_Name$/i, /^UserName$/i, ...(isChainsaw ? [/^target_username$/i] : []), ...(isEvtxECmd ? [/^PayloadData1$/i] : [])]) || detailsCol,
      logonType:   userLogonTypeCol || detect([/^LogonType$/i, /^Logon_Type$/i, ...(isChainsaw ? [/^logon_type$/i] : []), ...(isEvtxECmd ? [/^PayloadData2$/i] : [])]) || detailsCol,
      eventId:     userEventIdCol   || detect([/^EventID$/i, /^event_id$/i, /^eventid$/i, /^EventId$/, ...(isChainsaw ? [/^id$/i] : [])]),
      ts:          userTsCol        || detect([/^datetime$/i, /^UtcTime$/i, /^TimeCreated$/i, /^timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
      domain:      userDomainCol    || detect([/^TargetDomainName$/i, /^Target_Domain_Name$/i, /^SubjectDomainName$/i]) || extraCol || detailsCol,
      // 4778 session reconnect columns (RDP lateral movement — attacker hostname/IP)
      clientName:    detect([/^ClientName$/i, /^Client_Name$/i]),
      clientAddress: detect([/^ClientAddress$/i, /^Client_Address$/i, /^ClientIP$/i]),
      // 5140/5145 share access columns
      shareName: detect([/^ShareName$/i, /^Share_Name$/i]),
      relativeTargetName: detect([/^RelativeTargetName$/i, /^Relative_Target_Name$/i]),
      // EvtxECmd extra columns for value parsing
      _remoteHost: isEvtxECmd ? detect([/^RemoteHost$/i]) : null,
      _payloadData1: isEvtxECmd ? detect([/^PayloadData1$/i]) : null,
      _payloadData2: isEvtxECmd ? detect([/^PayloadData2$/i]) : null,
      _payloadData3: isEvtxECmd ? detect([/^PayloadData3$/i]) : null,
      _payloadData4: isEvtxECmd ? detect([/^PayloadData4$/i]) : null,
      _payloadData5: isEvtxECmd ? detect([/^PayloadData5$/i]) : null,
      _channel: detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
      // SubStatus for 4625 failure reason (may be in dedicated column or PayloadData)
      subStatus: detect([/^SubStatus$/i, /^Sub_Status$/i]),
      ticketEncryptionType: detect([/^TicketEncryptionType$/i, /^Ticket_Encryption_Type$/i]),
      serviceName: detect([/^ServiceName$/i, /^Service_Name$/i, /^TargetServiceName$/i]),
      ticketOptions: detect([/^TicketOptions$/i, /^Ticket_Options$/i]),
      details: detailsCol,
      extra: extraCol,
    };
    columns._isEvtxECmd = isEvtxECmd;
    columns._isHayabusa = isHayabusa;
    columns._isChainsaw = isChainsaw;
    columns._syntheticTarget = !columns.target && (syntheticTargetHost || isChainsaw) ? (syntheticTargetHost || "LOCAL_HOST") : "";

    if (!columns.source && !columns.workstation) return { nodes: [], edges: [], chains: [], stats: {}, columns, error: "Cannot detect source host column (IpAddress, WorkstationName, or RemoteHost)" };
    if (!columns.target && !columns._syntheticTarget) return { nodes: [], edges: [], chains: [], stats: {}, columns, error: "Cannot detect target host column (Computer)" };

    const db = meta.db;
    const params = [];
    const whereConditions = [];

    if (columns.eventId && eventIds.length > 0) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        whereConditions.push(`${safeEid} IN (${eventIds.map(() => "?").join(",")})`);
        params.push(...eventIds);
      }
    }

    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    const selectParts = ["data.rowid as _rowid"];
    for (const [key, colName] of Object.entries(columns)) {
      if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
    }

    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol ? `ORDER BY ${orderCol} ASC` : "ORDER BY data.rowid ASC";

    try {
      // Ensure indexes on key columns to speed up WHERE + ORDER BY
      if (columns.eventId) this._ensureIndex(tabId, columns.eventId);
      if (columns.ts) this._ensureIndex(tabId, columns.ts);

      // Invalidate stale preview cache for this tab (analysis params may have changed)
      if (this._lmPreviewCache) {
        const prefix = JSON.stringify(tabId) + ",";
        for (const k of this._lmPreviewCache.keys()) { if (k.startsWith("[" + prefix)) this._lmPreviewCache.delete(k); }
      }

      const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
      const rows = db.prepare(sql).all(...params);

      const EXCLUDED_IPS = new Set(["-", "::1", "127.0.0.1", "0.0.0.0", ""]);
      const SERVICE_RE = /^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON)$/i;
      // Session-only events are for RDP session correlation but don't create graph edges
      const SESSION_ONLY_EVENTS = new Set(["23","24","39","40","4634","4647","4672","4769","4779"]);

      const RDP_EVENT_DESC = {
        "1149": "Network auth succeeded", "4624": "Logon succeeded", "4625": "Logon failed",
        "21": "Session logon succeeded", "22": "Shell start notification", "23": "Session logoff",
        "24": "Session disconnected", "25": "Session reconnected", "39": "Disconnected by another session",
        "40": "Session disconnect (reason code)", "4634": "Account logged off", "4647": "User-initiated logoff",
        "4648": "Explicit credentials used", "4672": "Admin privileges assigned",
        "4778": "Session reconnected (window station)", "4779": "Session disconnected (window station)",
      };

      const edgeMap = new Map();
      const hostSet = new Map();
      const timeOrdered = [];
      const rdpEvents = []; // collect all events for RDP session correlation

      const _normLmHost = (value) => this._cleanWrappedField(value).replace(/^\\\\/, "").replace(/^[A-Z]+\/+/i, "").toUpperCase();

      for (const row of rows) {
        let targetHost = _normLmHost(row.target || columns._syntheticTarget || "");
        if (!targetHost) continue;

        const eventId = this._cleanWrappedField(row.eventId || "");

        // Detect channel for TerminalServices event parsing
        const channelRaw = row._channel ? String(row._channel).toLowerCase() : "";
        const channelNorm = this._resolveEventChannel(row);
        const isLocalSessionMgr = channelRaw.includes("localsessionmanager") || channelNorm === "localsessionmanager";
        const isRemoteConnMgr = channelRaw.includes("remoteconnectionmanager") || channelNorm === "remoteconnectionmanager";
        const isTermSvc = isLocalSessionMgr || isRemoteConnMgr;

        let clientName = "";
        let clientAddress = "";
        let sourceHost = "";
        let user = "";
        let logonType = "";
        let sessionId = "";
        let compact = null;

        if (isHayabusa) {
          compact = this._parseCompactKeyValues(row.details, row.extra);
        }

        // === TerminalServices event parsing ===
        if (isHayabusa) {
          if (eventId === "4648") {
            targetHost = _normLmHost(this._compactGet(compact, "TgtSvr", "TgtHost")) || targetHost;
          }
          if (eventId === "4778" || eventId === "4779") {
            clientName = this._compactGet(compact, "SrcComp", "ClientName");
            clientAddress = this._compactGet(compact, "SrcIP", "ClientAddress");
            sourceHost = _normLmHost(clientName || clientAddress);
            user = this._compactGet(compact, "TgtUser", "TargetUserName", "User");
          } else if (["21","22","23","24","25","39","40","1149"].includes(eventId)) {
            user = this._compactGet(compact, "User", "TgtUser", "TargetUserName", "SubjectUserName");
            sourceHost = _normLmHost(this._compactGet(compact, "SrcComp", "ClientName", "SrcIP", "ClientAddress"));
            logonType = this._extractFirstInteger(this._compactGet(compact, "Type", "LogonType"));
            sessionId = this._compactGetInt(compact, "SessionId", "Session ID", "LID");
          } else {
            sourceHost = _normLmHost(this._compactGet(compact, "SrcComp", "WorkstationName", "SrcHost"));
            if (!sourceHost || sourceHost === "-") sourceHost = _normLmHost(this._compactGet(compact, "SrcIP", "IpAddress", "SourceNetworkAddress"));
            user = this._compactGet(compact, "TgtUser", "TargetUserName", "SubjectUserName", "User", "SrcUser");
            logonType = this._extractFirstInteger(this._compactGet(compact, "Type", "LogonType"));
          }
          if (!targetHost && eventId === "4648") {
            targetHost = _normLmHost(this._compactGet(compact, "TgtSvr", "TgtHost"));
          }
        } else if (isTermSvc || (!channelRaw && ["21","22","23","24","25","39","40","1149"].includes(eventId) && isEvtxECmd && row._payloadData3)) {
          const pd1 = (row._payloadData1 || row.user || "").trim();
          const pd2 = (row._payloadData2 || row.logonType || "").trim();
          const pd3 = (row._payloadData3 || "").trim();

          if (isLocalSessionMgr || ["21","22","23","24","25","39","40"].includes(eventId)) {
            // LocalSessionManager: PD1="User: DOMAIN\user", PD2="Session ID: N", PD3="Source Network Address: x.x.x.x"
            const userMatch = pd1.match(/(?:^User:\s*|^)(?:([^\\]+)\\)?(.+)$/i);
            if (userMatch) user = userMatch[2].trim();
            const sidMatch = pd2.match(/Session\s*ID:\s*(\d+)/i);
            if (sidMatch) sessionId = sidMatch[1];
            const ipMatch = pd3.match(/Source\s*Network\s*Address:\s*(.+)/i);
            if (ipMatch) {
              const srcIP = ipMatch[1].trim();
              if (srcIP && srcIP !== "LOCAL" && !EXCLUDED_IPS.has(srcIP.toUpperCase())) sourceHost = srcIP.toUpperCase();
            }
          } else if (isRemoteConnMgr || eventId === "1149") {
            // RemoteConnectionManager 1149: PD1="User: username", PD2="Domain: DOMAIN", PD3="Source Network Address: x.x.x.x"
            const userMatch = pd1.match(/(?:^User:\s*|^)(.+)$/i);
            if (userMatch) user = userMatch[1].trim();
            const ipMatch = pd3.match(/Source\s*Network\s*Address:\s*(.+)/i);
            if (ipMatch) {
              const srcIP = ipMatch[1].trim();
              if (srcIP && !EXCLUDED_IPS.has(srcIP.toUpperCase())) sourceHost = srcIP.toUpperCase();
            }
          }

        // === 4778/4779: Session reconnect/disconnect — ClientName/ClientAddress ===
        } else if (eventId === "4778" || eventId === "4779") {
          clientName = (row.clientName || "").trim();
          clientAddress = (row.clientAddress || "").trim();
          if (isEvtxECmd && !clientName && row._payloadData1) {
            const cnMatch = row._payloadData1.match(/ClientName:\s*(.+?)(?:\s*$|,)/i);
            if (cnMatch) clientName = cnMatch[1].trim();
          }
          if (isEvtxECmd && !clientAddress && row._payloadData2) {
            const caMatch = row._payloadData2.match(/ClientAddress:\s*(.+?)(?:\s*$|,)/i);
            if (caMatch) clientAddress = caMatch[1].trim();
          }
          sourceHost = clientName ? clientName.toUpperCase() : clientAddress ? clientAddress.toUpperCase() : "";

          // Parse user from standard Security format
          user = row.user || "";
          if (isEvtxECmd && user) {
            const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
            if (pdMatch) user = pdMatch[2].trim();
            else user = "";
          }

        // === Standard Security event parsing (4624, 4625, 4634, 4647, 4648, 4672) ===
        } else {
          sourceHost = _normLmHost(row.workstation || "");
          if (!sourceHost || sourceHost === "-") sourceHost = _normLmHost(row.source || "");

          // EvtxECmd: RemoteHost format is "WorkstationName (IpAddress)"
          if (isEvtxECmd && row.source) {
            const rh = row.source.trim();
            if (/^\*/.test(rh) || /^LOCALSUBNET/i.test(rh) || /^LOCAL$/i.test(rh)) { continue; }
            const rhMatch = rh.match(/^(.+?)\s*\(([^)]+)\)$/);
            if (rhMatch) {
              const wkst = rhMatch[1].trim();
              const ip = rhMatch[2].trim();
              sourceHost = (wkst && wkst !== "-") ? _normLmHost(wkst) : _normLmHost(ip);
            } else {
              sourceHost = _normLmHost(rh);
            }
          }

          // EvtxECmd: PayloadData1 format is "Target: DOMAIN\User"
          user = this._cleanWrappedField(row.user || "");
          if (isEvtxECmd && user) {
            const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
            if (pdMatch) user = pdMatch[2].trim();
            else user = "";
          }

          // EvtxECmd: PayloadData2 format is "LogonType N"
          logonType = this._cleanWrappedField(row.logonType || "");
          if (isEvtxECmd && logonType) {
            const ltMatch = logonType.match(/LogonType\s+(\d+)/i);
            if (ltMatch) logonType = ltMatch[1];
            else logonType = "";
          }
        }

        if (user && user.includes("\\")) user = user.split("\\").pop();
        user = this._cleanWrappedField(user);
        if (logonType && !isEvtxECmd) {
          logonType = this._extractFirstInteger(logonType) || this._cleanWrappedField(logonType);
        }
        if (!logonType && compact) logonType = this._extractFirstInteger(this._compactGet(compact, "Type", "LogonType"));

        if (!sourceHost || EXCLUDED_IPS.has(sourceHost)) {
          // Still collect for RDP session correlation if we have target + user (for logoff/disconnect events)
          if (SESSION_ONLY_EVENTS.has(eventId) && targetHost && user) {
            rdpEvents.push({ eventId, ts: row.ts || "", user, sourceHost: "", targetHost, logonType, sessionId, channel: channelNorm || channelRaw });
          }
          continue;
        }
        if (excludeLocalLogons && sourceHost === targetHost) continue;
        if (excludeServiceAccounts && user && (SERVICE_RE.test(user) || user.endsWith("$"))) continue;

        const ts = row.ts || "";
        const isFailure = eventId === "4625";

        // Collect for RDP session correlation
        rdpEvents.push({ eventId, ts, user, sourceHost, targetHost, logonType, sessionId, channel: channelNorm || channelRaw });

        // Session-only events: don't create graph edges, only used for RDP session correlation
        if (SESSION_ONLY_EVENTS.has(eventId)) continue;

        // === Build graph edges (edge-creating events only) ===
        if (!hostSet.has(sourceHost)) hostSet.set(sourceHost, { isSource: false, isTarget: false, eventCount: 0 });
        if (!hostSet.has(targetHost)) hostSet.set(targetHost, { isSource: false, isTarget: false, eventCount: 0 });
        hostSet.get(sourceHost).isSource = true;
        hostSet.get(sourceHost).eventCount++;
        hostSet.get(targetHost).isTarget = true;
        hostSet.get(targetHost).eventCount++;

        const edgeKey = `${sourceHost}->${targetHost}`;
        if (!edgeMap.has(edgeKey)) {
          edgeMap.set(edgeKey, { source: sourceHost, target: targetHost, count: 0, users: new Set(), logonTypes: new Set(), firstSeen: ts, lastSeen: ts, hasFailures: false, clientNames: new Set(), clientAddresses: new Set(), eventBreakdown: new Map() });
        }
        const edge = edgeMap.get(edgeKey);
        // Track share access for 5140/5145 events separately from core logon/session count
        let shareName = "";
        const isShareEvt = eventId === "5140" || eventId === "5145";
        if (isShareEvt) {
          edge.shareAccessCount = (edge.shareAccessCount || 0) + 1;
          shareName = (row.shareName || "").trim();
          // EvtxECmd: share name may be in PayloadData fields
          if (!shareName && isEvtxECmd) {
            for (const pdKey of ["_payloadData1", "_payloadData2", "_payloadData3"]) {
              const pdVal = (row[pdKey] || "").toString();
              const snMatch = pdVal.match(/ShareName[:\s]+([^\s|,]+)/i) || pdVal.match(/\\\\[^\\]+\\([^\s|,]+)/);
              if (snMatch) { shareName = snMatch[1].trim(); break; }
            }
          } else if (!shareName && compact) {
            shareName = this._compactGet(compact, "ShareName", "Share");
          }
          if (shareName) {
            if (!edge.shareNames) edge.shareNames = new Set();
            edge.shareNames.add(shareName);
            const sn = shareName.replace(/^\\\\\*\\/, "").toUpperCase();
            if (/^(ADMIN\$|C\$|[A-Z]\$)$/.test(sn)) edge._adminShareCount = (edge._adminShareCount || 0) + 1;
          }
        } else {
          edge.count++; // core logon/session events only
        }
        if (user) edge.users.add(user);
        if (logonType) edge.logonTypes.add(logonType);
        if (logonType === "10" || logonType === "12") edge._rdpLogonCount = (edge._rdpLogonCount || 0) + 1;
        if (ts && ts < edge.firstSeen) edge.firstSeen = ts;
        if (ts && ts > edge.lastSeen) edge.lastSeen = ts;
        if (isFailure) edge.hasFailures = true;
        if (clientName) edge.clientNames.add(clientName);
        if (clientAddress && clientAddress !== "LOCAL") edge.clientAddresses.add(clientAddress);
        if (eventId) edge.eventBreakdown.set(eventId, (edge.eventBreakdown.get(eventId) || 0) + 1);

        // Parse SubStatus for 4625 failure reason context
        let subStatus = undefined;
        if (eventId === "4625") {
          if (row.subStatus) {
            subStatus = row.subStatus.toString().trim();
          } else if (compact) {
            subStatus = this._compactGet(compact, "SubStatus");
            if (subStatus) subStatus = subStatus.toUpperCase();
          } else if (isEvtxECmd) {
            // EvtxECmd: SubStatus often in PayloadData3 or PayloadData4 as "SubStatus: 0xC000006A"
            for (const pdKey of ["_payloadData3", "_payloadData4", "_payloadData5"]) {
              const pdVal = (row[pdKey] || "").toString();
              const ssMatch = pdVal.match(/Sub\s*Status[:\s]+(0x[0-9A-Fa-f]+)/i);
              if (ssMatch) { subStatus = ssMatch[1].toUpperCase(); break; }
            }
          }
        }

        timeOrdered.push({ source: sourceHost, target: targetHost, user, ts, logonType, eventId, shareName: shareName || undefined, subStatus });
      }

      // === RDP Session Correlation ===
      rdpEvents.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
      const rdpSessions = [];
      const openSessions = new Map(); // sessionKey => session
      const openByBase = new Map(); // baseKey => Set<sessionKey> (index for fast lookup)

      const findNearestSession = (baseKey, ts, windowMs) => {
        const keys = openByBase.get(baseKey);
        if (!keys || keys.size === 0) return null;
        let best = null, bestDiff = Infinity;
        for (const key of keys) {
          const session = openSessions.get(key);
          if (!session) continue;
          const lastEvt = session.events[session.events.length - 1];
          if (!lastEvt?.ts || !ts) { if (!best) best = session; continue; }
          const diff = Math.abs(new Date(ts) - new Date(lastEvt.ts));
          if (diff < windowMs && diff < bestDiff) { best = session; bestDiff = diff; }
        }
        return best;
      };

      for (const evt of rdpEvents) {
        const baseKey = `${evt.sourceHost || "?"}->${evt.targetHost}|${evt.user}`;
        const sessionKey = evt.sessionId ? `${baseKey}|s${evt.sessionId}` : baseKey;
        const eid = evt.eventId;
        const desc = (eid === "4624" && evt.logonType === "10") ? "RDP logon succeeded"
          : (eid === "4624" && evt.logonType === "7") ? "Reconnect logon"
          : (eid === "4624" && evt.logonType === "12") ? "Cached RDP logon"
          : RDP_EVENT_DESC[eid] || `Event ${eid}`;

        // Connection-starting events
        if (eid === "1149" || (eid === "4624" && ["10","7","12"].includes(evt.logonType))) {
          let session = openSessions.get(sessionKey);
          if (!session || eid === "1149") {
            session = {
              id: rdpSessions.length, source: evt.sourceHost || "", target: evt.targetHost,
              user: evt.user, sessionId: evt.sessionId || "",
              events: [], startTime: evt.ts, endTime: null,
              status: "connecting", isReconnect: evt.logonType === "7",
              hasAdmin: false, hasFailed: false,
            };
            rdpSessions.push(session);
            openSessions.set(sessionKey, session);
            if (!openByBase.has(baseKey)) openByBase.set(baseKey, new Set());
            openByBase.get(baseKey).add(sessionKey);
          }
          session.events.push({ eventId: eid, ts: evt.ts, description: desc, logonType: evt.logonType || "" });
        }
        // Session-active events: 21, 22, 25
        else if (["21","22","25"].includes(eid)) {
          const session = openSessions.get(sessionKey) || findNearestSession(baseKey, evt.ts, 30000);
          if (session) {
            session.status = "active";
            session.events.push({ eventId: eid, ts: evt.ts, description: desc, logonType: evt.logonType || "" });
            if (eid === "25") session.isReconnect = true;
          }
        }
        // Admin privilege: 4672
        else if (eid === "4672") {
          const session = findNearestSession(baseKey, evt.ts, 5000);
          if (session) {
            session.hasAdmin = true;
            session.events.push({ eventId: eid, ts: evt.ts, description: desc, logonType: "" });
          }
        }
        // Disconnect events: 24, 39, 40, 4779
        else if (["24","39","40","4779"].includes(eid)) {
          const session = openSessions.get(sessionKey) || findNearestSession(baseKey, evt.ts, 60000);
          if (session) {
            session.status = "disconnected";
            session.events.push({ eventId: eid, ts: evt.ts, description: desc, logonType: "" });
          }
        }
        // Logoff events: 23, 4634, 4647
        else if (["23","4634","4647"].includes(eid)) {
          const session = openSessions.get(sessionKey) || findNearestSession(baseKey, evt.ts, 60000);
          if (session) {
            session.status = "ended";
            session.endTime = evt.ts;
            session.events.push({ eventId: eid, ts: evt.ts, description: desc, logonType: "" });
            openSessions.delete(sessionKey);
            const baseSet = openByBase.get(baseKey); if (baseSet) baseSet.delete(sessionKey);
          }
        }
        // Failed logon: 4625
        else if (eid === "4625") {
          const session = openSessions.get(sessionKey);
          if (session) {
            session.hasFailed = true;
            session.status = "failed";
            session.events.push({ eventId: eid, ts: evt.ts, description: desc, logonType: "" });
            openSessions.delete(sessionKey);
            const baseSet = openByBase.get(baseKey); if (baseSet) baseSet.delete(sessionKey);
          } else {
            rdpSessions.push({
              id: rdpSessions.length, source: evt.sourceHost || "", target: evt.targetHost,
              user: evt.user, sessionId: "", events: [{ eventId: eid, ts: evt.ts, description: desc, logonType: "" }],
              startTime: evt.ts, endTime: evt.ts,
              status: "failed", isReconnect: false, hasAdmin: false, hasFailed: true,
            });
          }
        }
        // 4648: explicit creds, 4778: reconnect
        else if (eid === "4648" || eid === "4778") {
          const session = openSessions.get(sessionKey) || findNearestSession(baseKey, evt.ts, 30000);
          if (session) {
            session.events.push({ eventId: eid, ts: evt.ts, description: desc, logonType: "" });
            if (eid === "4778") { session.isReconnect = true; session.status = "active"; }
          }
        }
      }
      // Mark remaining open sessions
      for (const session of openSessions.values()) {
        if (session.status === "connecting" || session.status === "active") {
          session.status = session.events.length > 1 ? "active (no logoff)" : "incomplete";
        }
      }

      // === Failed Session Clustering ===
      // Collapse standalone 4625 events with same source→target→user within 5 min into one row
      const FAIL_CLUSTER_MS = 300000;
      const _failedStandalone = [];
      const _keptSessions = [];
      for (const s of rdpSessions) {
        if (s.status === "failed" && s.events.length === 1 && s.events[0].eventId === "4625") {
          _failedStandalone.push(s);
        } else {
          s.attemptCount = 1;
          _keptSessions.push(s);
        }
      }
      _failedStandalone.sort((a, b) => {
        const ka = `${a.source}|${a.target}|${a.user}`, kb = `${b.source}|${b.target}|${b.user}`;
        return ka < kb ? -1 : ka > kb ? 1 : (a.startTime || "").localeCompare(b.startTime || "");
      });
      let _fci = 0;
      while (_fci < _failedStandalone.length) {
        const anchor = _failedStandalone[_fci];
        const cKey = `${anchor.source}|${anchor.target}|${anchor.user}`;
        const cEvts = [...anchor.events];
        let cEnd = _fci + 1;
        let lastMs = new Date(anchor.startTime).getTime();
        while (cEnd < _failedStandalone.length) {
          const next = _failedStandalone[cEnd];
          if (`${next.source}|${next.target}|${next.user}` !== cKey) break;
          const nextMs = new Date(next.startTime).getTime();
          if (nextMs - lastMs > FAIL_CLUSTER_MS) break; // rolling: compare to last clustered event
          cEvts.push(...next.events);
          lastMs = nextMs;
          cEnd++;
        }
        const last = _failedStandalone[cEnd - 1];
        _keptSessions.push({
          id: 0, source: anchor.source, target: anchor.target, user: anchor.user,
          sessionId: "", events: cEvts,
          startTime: anchor.startTime, endTime: last.startTime,
          status: "failed", isReconnect: false, hasAdmin: false, hasFailed: true,
          attemptCount: cEnd - _fci,
        });
        _fci = cEnd;
      }
      _keptSessions.sort((a, b) => (a.startTime || "").localeCompare(b.startTime || ""));
      _keptSessions.forEach((s, i) => s.id = i);
      rdpSessions.length = 0;
      rdpSessions.push(..._keptSessions);

      // === Session Confidence ===
      for (const s of rdpSessions) {
        const eids = new Set(s.events.map(e => e.eventId));
        const has1149 = eids.has("1149");
        const has4624t10 = s.events.some(e => e.eventId === "4624" && ["10", "7", "12"].includes(e.logonType));
        const has2122 = eids.has("21") || eids.has("22");
        const chainParts = (has1149 ? 1 : 0) + (has4624t10 ? 1 : 0) + (has2122 ? 1 : 0);

        if (chainParts >= 3) s.confidence = "high";
        else if (chainParts >= 2) s.confidence = "medium";
        else if (has4624t10 || has2122) s.confidence = "medium";
        else if (s.status === "failed" && (s.attemptCount || 1) >= 3) s.confidence = "medium";
        else s.confidence = "low";

        // Missing expected events
        s.missingExpected = [];
        if (s.status !== "failed") {
          if (!has1149 && (has4624t10 || has2122)) s.missingExpected.push("1149");
          if (has1149 && !has4624t10 && !eids.has("4625")) s.missingExpected.push("4624");
          if ((has1149 || has4624t10) && !has2122) s.missingExpected.push("21/22");
        }
      }

      // === Reconnect Merging ===
      const RECONNECT_ONLY_EIDS = new Set(["25", "4778", "21", "22", "24", "39", "40"]);
      const RECONNECT_MAX_GAP_MS = 8 * 3600000; // 8 hours
      const _toRemoveIds = new Set();
      for (const s of rdpSessions) {
        if (!s.isReconnect || s.status === "failed") continue;
        const isReconnOnly = s.events.every(e => RECONNECT_ONLY_EIDS.has(e.eventId));
        if (!isReconnOnly) continue;
        let bestParent = null, bestGap = Infinity;
        for (const p of rdpSessions) {
          if (p === s || _toRemoveIds.has(p.id)) continue;
          if ((p.source || "").toUpperCase() !== (s.source || "").toUpperCase()) continue;
          if ((p.target || "").toUpperCase() !== (s.target || "").toUpperCase()) continue;
          if ((p.user || "").toUpperCase() !== (s.user || "").toUpperCase()) continue;
          if (p.isReconnect && p.events.every(e => RECONNECT_ONLY_EIDS.has(e.eventId))) continue;
          if (!p.startTime || !s.startTime || p.startTime >= s.startTime) continue;
          const pLastTs = p.events[p.events.length - 1]?.ts || p.endTime || p.startTime;
          const gap = new Date(s.startTime) - new Date(pLastTs);
          if (isNaN(gap) || gap < 0 || gap > RECONNECT_MAX_GAP_MS) continue;
          if (gap < bestGap) { bestParent = p; bestGap = gap; }
        }
        if (bestParent) {
          bestParent.events.push(...s.events);
          bestParent.events.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
          const sEnd = s.endTime || s.events[s.events.length - 1]?.ts;
          if (sEnd && (!bestParent.endTime || sEnd > bestParent.endTime)) bestParent.endTime = sEnd;
          bestParent.isReconnect = true;
          bestParent.mergedReconnects = (bestParent.mergedReconnects || 0) + 1;
          if (s.status === "active" || s.status === "active (no logoff)") bestParent.status = s.status;
          _toRemoveIds.add(s.id);
        }
      }
      if (_toRemoveIds.size > 0) {
        const filtered = rdpSessions.filter(s => !_toRemoveIds.has(s.id));
        rdpSessions.length = 0;
        rdpSessions.push(...filtered);
        rdpSessions.forEach((s, i) => s.id = i);
      }

      // === Technique Assignment ===
      for (const s of rdpSessions) {
        s.mergedReconnects = s.mergedReconnects || 0;
        if (s.status === "failed") {
          s.technique = (s.attemptCount || 1) >= 5 ? "RDP Brute Force" : "RDP Failed Auth";
        } else if (s.isReconnect) {
          s.technique = "RDP Reconnect";
        } else {
          s.technique = "RDP";
        }
      }

      // Session grouping deferred until after suspicion scoring (see below return block)

      // === Chain Detection: hop-candidate chaining with user continuity + bounded gaps ===
      // Step 1: Build time-windowed hop instances from timeOrdered events
      const _CHAIN_EXCLUDE = /^(127\.\d|::1|0\.0\.0\.0|LOCAL$|-:-$|-$|::1:\d)/i;
      const _hopTech = (evt) => {
        if (["10", "12"].includes(evt.logonType) || ["1149", "21", "22", "24", "25"].includes(evt.eventId)) return "RDP";
        if (evt.logonType === "3" && ["7045", "4697"].includes(evt.eventId)) return "Service Exec";
        if ((evt.eventId === "5140" || evt.eventId === "5145") && evt.shareName) {
          const sn = evt.shareName.replace(/^\\\\\*\\/, "").toUpperCase();
          if (/^(ADMIN\$|C\$|[A-Z]\$)$/.test(sn)) return "Admin Share";
        }
        if (evt.logonType === "3") return "Network Logon";
        if (evt.logonType === "8") return "Cleartext";
        if (evt.logonType === "2") return "Interactive";
        return null;
      };
      // Collect all valid hop events, keeping each distinct time instance
      const _hopEvents = [];
      for (const evt of timeOrdered) {
        if (!evt.source || !evt.target || evt.source === evt.target) continue;
        if (_CHAIN_EXCLUDE.test(evt.source) || _CHAIN_EXCLUDE.test(evt.target)) continue;
        if (["4625", "4771", "4776"].includes(evt.eventId)) continue; // skip failures
        const tech = _hopTech(evt);
        if (!tech) continue;
        const user = (evt.user || "").toUpperCase();
        if (!user || user === "-" || user === "ANONYMOUS LOGON" || user === "ANONYMOUS") continue;
        _hopEvents.push({ source: evt.source, target: evt.target, user: evt.user || "(unknown)", ts: evt.ts, technique: tech, eventId: evt.eventId, logonType: evt.logonType, shareName: evt.shareName });
      }
      // Deduplicate within 2-min windows per pair+user (collapse duplicate events, keep distinct instances)
      _hopEvents.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
      const HOP_DEDUP_MS = 120000; // 2 min
      const _hops = [];
      const _lastHopTs = new Map(); // "src->tgt|USER" -> lastTs
      for (const evt of _hopEvents) {
        const hk = `${evt.source}->${evt.target}|${evt.user.toUpperCase()}`;
        const lastTs = _lastHopTs.get(hk);
        if (lastTs) {
          const gap = new Date(evt.ts) - new Date(lastTs);
          if (!isNaN(gap) && gap < HOP_DEDUP_MS) continue; // skip near-duplicate
        }
        _lastHopTs.set(hk, evt.ts);
        _hops.push(evt);
      }
      // Hop technique enrichment deferred to after findings (see "Chain Hop Technique Enrichment" block)
      // Build adjacency index: source host -> hops departing from it (sorted by ts)
      const _departFrom = new Map();
      for (const h of _hops) {
        if (!_departFrom.has(h.source)) _departFrom.set(h.source, []);
        _departFrom.get(h.source).push(h);
      }

      // Step 2: Build chains by linking hops with user continuity + bounded gaps
      // Same-user gap: 30 min (no relaxation without session continuity evidence)
      // Different-user gap: 15 min (requires tighter temporal proximity)
      const HOP_GAP_SAME_USER_MS = 1800000; // 30 min
      const HOP_GAP_DIFF_USER_MS = 900000;  // 15 min
      const MAX_CHAINS = 100;
      const rawChains = [];

      for (const startHop of _hops) {
        if (rawChains.length >= MAX_CHAINS) break;
        const chain = [startHop];
        const visitedHosts = new Set([startHop.source, startHop.target]);
        let currentHop = startHop;
        while (chain.length < 8) {
          const nextHops = _departFrom.get(currentHop.target) || [];
          let bestNext = null;
          let bestGap = Infinity;
          for (const nh of nextHops) {
            if (visitedHosts.has(nh.target)) continue;
            if (!nh.ts || !currentHop.ts) continue;
            const gapMs = new Date(nh.ts) - new Date(currentHop.ts);
            if (gapMs < 0) continue;
            const sameUser = nh.user.toUpperCase() === currentHop.user.toUpperCase();
            const maxGap = sameUser ? HOP_GAP_SAME_USER_MS : HOP_GAP_DIFF_USER_MS;
            if (gapMs > maxGap) continue;
            // Prefer: (1) same user, (2) shortest gap
            const isBetter = !bestNext
              || (sameUser && bestNext.user.toUpperCase() !== currentHop.user.toUpperCase())
              || (sameUser === (bestNext.user.toUpperCase() === currentHop.user.toUpperCase()) && gapMs < bestGap);
            if (isBetter) { bestNext = nh; bestGap = gapMs; }
          }
          if (!bestNext) break;
          chain.push(bestNext);
          visitedHosts.add(bestNext.target);
          currentHop = bestNext;
        }
        if (chain.length >= 2) rawChains.push(chain);
      }

      // Step 3: Deduplicate — group chains by normalized path + user
      const _chainDedup = new Map(); // "path|user" => { chain, occurrences, firstTs, lastTs }
      for (const chain of rawChains) {
        const pathKey = chain.map(h => `${h.source}->${h.target}`).join("|");
        const userKey = chain.map(h => h.user.toUpperCase()).join("|");
        const dk = `${pathKey}::${userKey}`;
        const firstTs = chain[0].ts;
        const lastTs = chain[chain.length - 1].ts;
        if (!_chainDedup.has(dk)) {
          _chainDedup.set(dk, { chain, occurrences: 1, firstTs, lastTs });
        } else {
          const existing = _chainDedup.get(dk);
          existing.occurrences++;
          if (firstTs < existing.firstTs) existing.firstTs = firstTs;
          if (lastTs > existing.lastTs) existing.lastTs = lastTs;
        }
      }

      // Step 4: Build chain objects (confidence scoring deferred until after findings/shared vars)
      const chains = [];
      for (const [, entry] of _chainDedup) {
        const ch = entry.chain;
        const hops = ch.length;
        const path = [ch[0].source, ...ch.map(h => h.target)];
        const hopDetails = ch.map(h => ({
          source: h.source, target: h.target, user: h.user, ts: h.ts,
          technique: h.technique, eventId: h.eventId, logonType: h.logonType,
        }));
        const users = [...new Set(ch.map(h => h.user).filter(Boolean))];
        const techniques = [...new Set(ch.map(h => h.technique).filter(Boolean))];
        const timestamps = [ch[0].ts, ...ch.map(h => h.ts)];
        chains.push({
          path, timestamps, users, hops, techniques, hopDetails,
          _rawHops: ch, // kept for deferred confidence scoring
          occurrences: entry.occurrences, firstTs: entry.firstTs, lastTs: entry.lastTs,
        });
      }

      // === First-seen Flags ===
      let globalMinTs = null, globalMaxTs = null;
      for (const edge of edgeMap.values()) {
        if (edge.firstSeen) {
          if (!globalMinTs || edge.firstSeen < globalMinTs) globalMinTs = edge.firstSeen;
          if (!globalMaxTs || edge.lastSeen > globalMaxTs) globalMaxTs = edge.lastSeen;
        }
      }
      const totalRangeMs = globalMinTs && globalMaxTs ? (new Date(globalMaxTs) - new Date(globalMinTs)) : 0;
      const firstSeenThresholdTs = totalRangeMs > 0 ? new Date(new Date(globalMinTs).getTime() + totalRangeMs * 0.01).toISOString() : null;
      const firstConnPerSource = new Map();
      for (const edge of edgeMap.values()) {
        const ex = firstConnPerSource.get(edge.source);
        if (!ex || edge.firstSeen < ex) firstConnPerSource.set(edge.source, edge.firstSeen);
      }
      for (const edge of edgeMap.values()) {
        edge.isFirstSeen = (firstSeenThresholdTs && edge.firstSeen <= firstSeenThresholdTs) || firstConnPerSource.get(edge.source) === edge.firstSeen;
      }

      // === Edge Technique Inference + Source Label ===
      // Primary technique = dominant by event count; otherTechniques = supporting list
      const _techPriority = { "Admin Share": 7, "Service Exec": 6, "Cleartext": 5, "RDP": 4, "Interactive": 3, "Network Logon": 2, "Cached": 1, "Reconnect": 0 };
      for (const edge of edgeMap.values()) {
        const lt = edge.logonTypes; // Set
        const eb = edge.eventBreakdown; // Map
        const techCounts = new Map(); // technique -> event count contributing
        // Admin Share: ADMIN$/C$/[A-Z]$ access via 5140/5145
        if (edge._adminShareCount > 0) {
          techCounts.set("Admin Share", edge._adminShareCount);
        }
        if (lt.has("10") || lt.has("12") || eb.has("1149") || eb.has("21") || eb.has("22")) {
          // Count RDP-specific events + Type 10/12 4624 logons (tracked in edge._rdpLogonCount)
          const rdpSpecific = (eb.get("1149") || 0) + (eb.get("21") || 0) + (eb.get("22") || 0) + (eb.get("24") || 0) + (eb.get("25") || 0);
          techCounts.set("RDP", Math.max(1, rdpSpecific + (edge._rdpLogonCount || 0)));
        }
        if (lt.has("3") && (eb.has("7045") || eb.has("4697"))) {
          techCounts.set("Service Exec", (eb.get("7045") || 0) + (eb.get("4697") || 0));
        } else if (lt.has("3")) {
          // Count type-3 logon events (4624 w/ type 3 approximated by total 4624 minus RDP attribution)
          techCounts.set("Network Logon", (eb.get("4624") || 0));
        }
        if (lt.has("7")) techCounts.set("Reconnect", 1);
        if (lt.has("8")) techCounts.set("Cleartext", (eb.get("4624") || 0));
        if (lt.has("11")) techCounts.set("Cached", 1);
        if (lt.has("2")) techCounts.set("Interactive", (eb.get("4624") || 0));
        // Pick primary by count, break ties by priority
        const techArr = [...techCounts.entries()].sort((a, b) => b[1] - a[1] || (_techPriority[b[0]] || 0) - (_techPriority[a[0]] || 0));
        if (techArr.length > 0) {
          edge.technique = techArr[0][0];
          edge.otherTechniques = techArr.slice(1).map(t => t[0]);
        } else {
          edge.technique = "Unknown";
          edge.otherTechniques = [];
        }
        // Source identity label
        const _src = edge.source;
        if (!_src || _src === "-:-" || _src === "::1:0" || _src === "-") edge.sourceLabel = "unresolved";
        else if (/^(127\.|::1|0\.0\.0\.0|LOCAL$)/i.test(_src)) edge.sourceLabel = "loopback";
        else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(_src) || (_src.includes(":") && !_src.includes("."))) edge.sourceLabel = "IP";
        else edge.sourceLabel = "host";
      }

      // === Attack Pattern Detection ===
      const findings = [];
      let fid = 0;

      // Outlier host detection — flag default/generic/suspicious hostnames
      // Frequency-aware: DESKTOP-*/WIN-* are only outliers if they're a minority (<20%) of hosts.
      // In environments where most workstations have default names, they're the norm, not outliers.
      // Attack tool hostnames (Kali, Parrot, etc.) and generic names are always flagged regardless of frequency.
      const _DEFAULT_WIN_PAT = /^(DESKTOP-[A-Z0-9]{5,}|WIN-[A-Z0-9]{5,})$/;
      const OUTLIER_PATS_ALWAYS = [
        [/^KALI$/i, "Kali Linux default"],
        [/^PARROT$/i, "Parrot OS default"],
        [/^(USER-?PC|YOURNAME|ADMIN|TEST|PC|WIN10|WIN11|OWNER-?PC|USER|WINDOWS|LOCALHOST|HACKER|ATTACKER|ROOT)$/i, "Generic hostname"],
        [/[^\x00-\x7F]/, "Non-ASCII hostname"],
      ];
      const detectOutlier = (hostname) => {
        for (const [pat, reason] of OUTLIER_PATS_ALWAYS) {
          if (pat.test(hostname)) return reason;
        }
        return null;
      };
      const _outlierHosts = new Set();
      // Count DESKTOP-*/WIN-* hosts to determine if they're a minority
      const totalHosts = hostSet.size;
      let defaultWinCount = 0;
      for (const [id] of hostSet) {
        if (_DEFAULT_WIN_PAT.test(id)) defaultWinCount++;
      }
      const defaultWinIsMinority = totalHosts > 0 && (defaultWinCount / totalHosts) < 0.2;
      for (const [id] of hostSet) {
        const alwaysOutlier = detectOutlier(id);
        if (alwaysOutlier) {
          _outlierHosts.add(id);
        } else if (defaultWinIsMinority && _DEFAULT_WIN_PAT.test(id)) {
          // Only flag DESKTOP-*/WIN-* when they're rare in this environment
          _outlierHosts.add(id);
        }
      }
      // DC pattern: matches common naming conventions including prefixed/suffixed variants
      // e.g., DC01, PDC-NYC, CORPDC01, AD-PROD-01, ADCS01, DC01-HQ
      const _DC_PAT = /(?:^|[\-_])(DC|PDC|BDC|ADDS|ADCS|ADFS)\d{0,3}(?:$|[\-_])|^AD\d{0,3}$/i;
      const _SRV_PAT = /^(SVR|SRV|SERVER|FS|SQL|EXCH|MAIL|WEB|APP|DB|CA|WSUS|SCCM|SCOM|PRINT|FILE|DNS|DHCP|NPS|RADIUS|VPN|RDS|RDSH|RDCB|RDGW)/i;

      // Brute Force (T1110.001): 5+ failed logons same src->tgt within 5 min
      // Now logon-type-aware: groups failures by pair + logon type family so analysts
      // can distinguish RDP brute force (Type 10) from network (Type 3) from local (Type 2).
      // Type 2 (interactive) where source === target is dampened (password mistype/lockout).
      const _BF_TYPE_LABELS = { "2": "Interactive", "3": "Network", "7": "Unlock", "8": "Cleartext", "10": "RDP", "12": "Cached RDP" };
      const _bfTypeFamily = (lt) => {
        if (lt === "10" || lt === "12") return "rdp";
        if (lt === "3") return "network";
        if (lt === "2") return "interactive";
        if (lt === "8") return "cleartext";
        return "other";
      };
      // SubStatus reason mapping for 4625 failure context
      const _SUBSTATUS_REASONS = {
        "0XC000006A": "bad password", "0XC0000064": "unknown user", "0XC000006D": "bad credentials",
        "0XC0000234": "account locked", "0XC0000072": "account disabled", "0XC000006E": "account restriction",
        "0XC000006F": "outside hours", "0XC0000070": "workstation restriction", "0XC0000071": "password expired",
        "0XC0000193": "account expired", "0XC0000133": "clock skew", "0XC0000224": "must change password",
        "0XC0000413": "auth firewall", "0XC000015B": "logon type denied",
      };
      // Collect failures keyed by pair + logon type family
      const _bfByPairType = new Map(); // "src->tgt|family" -> {tss[], users, logonTypes, subStatuses}
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4625") continue;
        const family = _bfTypeFamily(evt.logonType);
        const k = `${evt.source}->${evt.target}|${family}`;
        if (!_bfByPairType.has(k)) _bfByPairType.set(k, { tss: [], users: new Set(), logonTypes: new Set(), subStatuses: new Map() });
        const entry = _bfByPairType.get(k);
        entry.tss.push(evt.ts);
        const u = (evt.user || "").trim().toUpperCase();
        if (u) entry.users.add(u);
        if (evt.logonType) entry.logonTypes.add(evt.logonType);
        if (evt.subStatus) entry.subStatuses.set(evt.subStatus.toUpperCase(), (entry.subStatuses.get(evt.subStatus.toUpperCase()) || 0) + 1);
      }
      // SubStatus codes that indicate non-attack failures (dampen severity)
      const _BF_NOISE_SUBSTATUS = new Set(["0XC0000234","0XC0000072","0XC000006E","0XC000006F","0XC0000070","0XC0000071","0XC0000193","0XC0000133","0XC0000224","0XC000015B"]);
      for (const [k, data] of _bfByPairType) {
        const { tss, users, logonTypes, subStatuses } = data;
        if (tss.length < 5) continue;
        tss.sort();
        const [pairPart, family] = k.split("|");
        const [src, tgt] = pairPart.split("->");
        // Dampener: Type 2 (interactive) where source === target is password mistype, not attack
        if (family === "interactive" && src === tgt) continue;
        // SubStatus context: build summary and check if mostly non-attack
        const ssTotal = [...subStatuses.values()].reduce((a, b) => a + b, 0);
        const ssNoiseCount = [...subStatuses.entries()].filter(([code]) => _BF_NOISE_SUBSTATUS.has(code)).reduce((a, [, c]) => a + c, 0);
        const ssMostlyNoise = ssTotal > 0 && (ssNoiseCount / ssTotal) > 0.8;
        const ssLabels = [...subStatuses.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([code, cnt]) => `${_SUBSTATUS_REASONS[code] || code} (${cnt})`);
        const typeLabel = [...logonTypes].map(lt => _BF_TYPE_LABELS[lt] || `Type ${lt}`).join("/");
        let _bfBurstCount = 0;
        for (let i = 0; i <= tss.length - 5;) {
          const ws = new Date(tss[i]), we = new Date(tss[i + 4]);
          if (isNaN(ws) || isNaN(we)) { i++; continue; }
          if ((we - ws) <= 300000) {
            let end = i + 4;
            while (end + 1 < tss.length && (new Date(tss[end + 1]) - ws) <= 300000) end++;
            _bfBurstCount++;
            // Severity: RDP/cleartext = high, network = high, interactive = medium
            let severity = "high";
            if (family === "interactive") severity = "medium";
            // Dampener: >80% of failures are non-attack SubStatus (locked, disabled, expired, etc.)
            if (ssMostlyNoise) {
              if (severity === "high") severity = "medium";
              else if (severity === "medium") severity = "low";
            }
            const _bfPills = [{ text: `${end - i + 1} failures in 5 min`, type: "context" }];
            _bfPills.push({ text: typeLabel, type: "context" });
            if (_bfBurstCount > 1) _bfPills.push({ text: `burst ${_bfBurstCount}`, type: "context" });
            // Add top SubStatus reason as pill for analyst context
            if (ssLabels.length > 0) _bfPills.push({ text: ssLabels[0], type: ssMostlyNoise ? "context" : "credential" });
            if (ssMostlyNoise) _bfPills.push({ text: "non-attack failures (dampened)", type: "context" });
            if (tgt && _DC_PAT.test(tgt)) _bfPills.push({ text: "DC target", type: "target" });
            else if (tgt && _SRV_PAT.test(tgt)) _bfPills.push({ text: "server target", type: "target" });
            if (src && _outlierHosts.has(src)) _bfPills.push({ text: "outlier source", type: "context" });
            const ssDesc = ssLabels.length > 0 ? `. Failure reasons: ${ssLabels.join(", ")}` : "";
            findings.push({ id: fid++, severity, category: "Brute Force", mitre: "T1110.001", title: `Brute force (${typeLabel}): ${src} \u2192 ${tgt}${_bfBurstCount > 1 ? ` (burst ${_bfBurstCount})` : ""}`, description: `${end - i + 1} failed ${typeLabel} logons within 5 minutes${ssDesc}`, source: src, target: tgt, timeRange: { from: tss[i], to: tss[end] }, eventCount: end - i + 1, evidencePills: _bfPills, users: [...users] });
            i = end + 1; // advance past consumed window
          } else {
            i++;
          }
        }
      }

      // Password Spray (T1110.003): same source, same/few users, many distinct targets, failures only
      // Thresholds: 5+ targets = high, 8+ = critical, 3-4 only if source is outlier
      // Dampeners: management sources, service accounts, server targets from known admin nodes
      const _spMgmt = /^(JUMP|JMP|PAM|BASTION|MGMT|MANAGE|SCCM|SCOM|WSUS|MONITOR|NAGIOS|ZABBIX|ANSIBLE|PUPPET|CHEF|SALT|ORCH)[\-_]|^ADMIN[\-_](JUMP|BASTION|PAM|MGMT|SRV|SERVER)/i;
      const _spSvc = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP|TASK[_\-]|SCH[_\-]|SA[_\-])/i;
      const _spOutlier = [/^DESKTOP-[A-Z0-9]{5,}$/, /^WIN-[A-Z0-9]{5,}$/, /^KALI$/i, /^PARROT$/i, /^(USER-?PC|YOURNAME|ADMIN|TEST|PC|WIN10|WIN11|OWNER-?PC|USER|WINDOWS|LOCALHOST|HACKER|ATTACKER|ROOT)$/i];
      const _spIsOutlier = (h) => { for (const p of _spOutlier) { if (p.test(h)) return true; } return false; };
      const failedBySrc = new Map();
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4625") continue;
        if (!failedBySrc.has(evt.source)) failedBySrc.set(evt.source, []);
        failedBySrc.get(evt.source).push({ target: evt.target, ts: evt.ts, user: (evt.user || "").trim().toUpperCase() });
      }
      // Also index successful logons per source to detect "no success in window"
      const _spSuccBySrc = new Map();
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4624") continue;
        if (!_spSuccBySrc.has(evt.source)) _spSuccBySrc.set(evt.source, []);
        _spSuccBySrc.get(evt.source).push(evt.ts);
      }
      for (const [src, evts] of failedBySrc) {
        if (evts.length < 3) continue;
        evts.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
        const isMgmt = src && _spMgmt.test(src);
        const isOutlier = src && _spIsOutlier(src);
        // Sliding window: find all distinct spray windows (not just first)
        const sprayFindings = [];
        const usedEvts = new Set(); // track consumed event indices to avoid overlapping windows
        for (let i = 0; i < evts.length; i++) {
          if (usedEvts.has(i)) continue;
          const ws = new Date(evts[i].ts);
          if (isNaN(ws)) continue;
          const we = new Date(ws.getTime() + 1800000); // 30-min window
          const tgts = new Set();
          const users = new Set();
          let j = i;
          while (j < evts.length) {
            const t = new Date(evts[j].ts);
            if (isNaN(t) || t > we) break;
            tgts.add(evts[j].target);
            if (evts[j].user) users.add(evts[j].user);
            j++;
          }
          const tgtCount = tgts.size;
          const userCount = users.size;
          // Minimum threshold: 5 targets for standard, 3 for outlier sources
          const minTgt = isOutlier ? 3 : 5;
          if (tgtCount < minTgt) continue;
          // Skip if many distinct users (likely not a spray — more like distributed auth failure)
          if (userCount > 3 && userCount > tgtCount * 0.5) continue;
          // Check for success in window (weakens spray signal)
          const succList = _spSuccBySrc.get(src) || [];
          const hasSuccInWindow = succList.some(st => { const sd = new Date(st); return !isNaN(sd) && sd >= ws && sd <= we; });
          // Base severity from target count
          let severity;
          if (tgtCount >= 8) severity = "critical";
          else if (tgtCount >= 5) severity = "high";
          else severity = "medium"; // 3-4 targets (only reachable for outlier sources)
          // Dampeners
          if (isMgmt) severity = severity === "critical" ? "high" : severity === "high" ? "medium" : "low";
          const allSvc = users.size > 0 && [...users].every(u => _spSvc.test(u) || u.endsWith("$"));
          if (allSvc) severity = severity === "critical" ? "high" : severity === "high" ? "medium" : "low";
          if (hasSuccInWindow && tgtCount < 8) severity = severity === "critical" ? "high" : severity === "high" ? "medium" : severity;
          // Drop if dampened below medium (unless outlier source)
          if (severity === "low" && !isOutlier) continue;
          // Build description
          const desc = [];
          desc.push(`${tgtCount} distinct targets, ${j - i} failures in ${Math.round((new Date(evts[j - 1].ts) - ws) / 60000)} min`);
          if (userCount <= 2) desc.push(`user${userCount > 1 ? "s" : ""}: ${[...users].join(", ")}`);
          else desc.push(`${userCount} distinct users`);
          const ctx = [];
          if (isOutlier) ctx.push("outlier source");
          if (isMgmt) ctx.push("management source (dampened)");
          if (allSvc) ctx.push("service accounts (dampened)");
          if (hasSuccInWindow) ctx.push("success in window");
          sprayFindings.push({
            severity, tgtCount, from: evts[i].ts, to: evts[j - 1].ts, eventCount: j - i,
            targets: [...tgts], users: [...users], description: desc.join("; ") + (ctx.length > 0 ? `. ${ctx.join(", ")}` : ""),
          });
          // Mark events as consumed
          for (let x = i; x < j; x++) usedEvts.add(x);
        }
        for (const sp of sprayFindings) {
          const _spPills = [{ text: `${sp.tgtCount} targets`, type: "context" }];
          if (isOutlier) _spPills.push({ text: "outlier source", type: "context" });
          if (isMgmt) _spPills.push({ text: "management source", type: "context" });
          if (sp.description.includes("service accounts")) _spPills.push({ text: "service accounts", type: "context" });
          if (sp.description.includes("success in window")) _spPills.push({ text: "success in window", type: "credential" });
          findings.push({ id: fid++, severity: sp.severity, category: "Password Spray", mitre: "T1110.003", title: `Password spray from ${src} (${sp.tgtCount} targets)`, description: sp.description, source: src, target: sp.targets.join(", "), timeRange: { from: sp.from, to: sp.to }, eventCount: sp.eventCount, evidencePills: _spPills, users: sp.users });
        }
      }

      // Credential Compromise (T1078): failed then success for SAME USER within 10 min
      // Key by source->target|user to avoid cross-user false positives
      // Clusters repeated fail→success sequences per user per pair
      // FP controls:
      //   - Type 7 (unlock/reconnect) excluded — users unlocking after lockout always produce fail→success
      //   - Type 3 (network) single-failure requires corroborating evidence (stale tickets/NLA retries are common)
      //   - Type 3 single-failure severity capped at medium unless corroborated
      const _ccAnon = /^(-|ANONYMOUS LOGON|ANONYMOUS|DWM-\d|UMFD-\d|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|FONT DRIVER HOST|WINDOW MANAGER)$/i;
      const _ccExcludeLogonTypes = new Set(["7"]); // Type 7 = unlock/reconnect — always noisy
      const _ccEvtsByKey = new Map();
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4625" && evt.eventId !== "4624" && evt.eventId !== "4648") continue;
        // Skip Type 7 events entirely — unlock/reconnect fail→success is not credential compromise
        if (evt.logonType && _ccExcludeLogonTypes.has(evt.logonType)) continue;
        const user = (evt.user || "").trim().toUpperCase();
        if (!user || _ccAnon.test(user)) continue;
        const k = `${evt.source}->${evt.target}|${user}`;
        if (!_ccEvtsByKey.has(k)) _ccEvtsByKey.set(k, []);
        _ccEvtsByKey.get(k).push({ eventId: evt.eventId, ts: evt.ts, user: evt.user, logonType: evt.logonType, source: evt.source, target: evt.target });
      }
      for (const [k, evts] of _ccEvtsByKey) {
        evts.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
        // Determine dominant logon type for this key (used for Type 3 dampening)
        const _ccLogonTypes = new Map();
        for (const e of evts) { if (e.logonType) _ccLogonTypes.set(e.logonType, (_ccLogonTypes.get(e.logonType) || 0) + 1); }
        let _ccDominantLT = null, _ccDominantCount = 0;
        for (const [lt, cnt] of _ccLogonTypes) { if (cnt > _ccDominantCount) { _ccDominantLT = lt; _ccDominantCount = cnt; } }
        const isType3 = _ccDominantLT === "3";
        // Type 3 uses tighter 5-min window; others use standard 10-min
        const _ccWindowMs = isType3 ? 300000 : 600000;
        // Collect all fail→success sequences for this user+pair
        const sequences = [];
        const usedSucc = new Set(); // avoid double-counting a success event
        for (let i = 0; i < evts.length; i++) {
          if (evts[i].eventId !== "4625") continue;
          const ft = new Date(evts[i].ts);
          if (isNaN(ft)) continue;
          for (let j = i + 1; j < evts.length; j++) {
            if (evts[j].eventId !== "4624") continue;
            if (usedSucc.has(j)) continue;
            const st = new Date(evts[j].ts);
            if (isNaN(st)) continue;
            const diff = st - ft;
            if (diff > _ccWindowMs) break; // beyond window
            if (diff >= 0) {
              // Context compatibility: check logon type if both present
              const flt = evts[i].logonType, slt = evts[j].logonType;
              if (flt && slt && flt !== slt) continue; // incompatible logon context
              sequences.push({ failTs: evts[i].ts, succTs: evts[j].ts, diffMs: diff, failIdx: i, succIdx: j });
              usedSucc.add(j);
              break; // match this failure to nearest success, move to next failure
            }
          }
        }
        if (sequences.length === 0) continue;
        // Type 3 single-failure gate: require corroborating evidence, otherwise skip entirely.
        // A single network logon fail→success is extremely common (stale Kerberos, NLA retries, multi-DC).
        if (isType3 && sequences.length === 1) {
          const [_t3Src, _t3Rest] = k.split("->");
          const [_t3Tgt] = _t3Rest.split("|");
          const _t3Has4648 = evts.some(e => {
            if (e.eventId !== "4648") return false;
            const et = new Date(e.ts), ft = new Date(sequences[0].failTs), st = new Date(sequences[0].succTs);
            return !isNaN(et) && !isNaN(ft) && !isNaN(st) && et >= new Date(ft.getTime() - 300000) && et <= new Date(st.getTime() + 300000);
          });
          const _t3IsDC = _t3Tgt && _DC_PAT.test(_t3Tgt);
          const _t3IsSrv = _t3Tgt && _SRV_PAT.test(_t3Tgt);
          const _t3IsOutlier = _t3Src && _outlierHosts.has(_t3Src);
          if (!_t3Has4648 && !_t3IsDC && !_t3IsSrv && !_t3IsOutlier) continue;
        }
        const [src, rest] = k.split("->");
        const [tgt] = rest.split("|");
        const user = evts[0].user || "(unknown)";
        // Cluster sequences within 10-min gaps
        const clusters = [];
        let cur = [sequences[0]];
        for (let s = 1; s < sequences.length; s++) {
          const prevEnd = new Date(cur[cur.length - 1].succTs);
          const nextStart = new Date(sequences[s].failTs);
          if (!isNaN(prevEnd) && !isNaN(nextStart) && (nextStart - prevEnd) <= 600000) {
            cur.push(sequences[s]);
          } else {
            clusters.push(cur);
            cur = [sequences[s]];
          }
        }
        clusters.push(cur);
        for (const cluster of clusters) {
          const failCount = cluster.length;
          const fastestDiff = Math.min(...cluster.map(s => s.diffMs));
          const firstFail = cluster[0].failTs;
          const lastSucc = cluster[cluster.length - 1].succTs;
          // Check for explicit creds (4648) within this cluster's time range + 5 min buffer
          const clusterStart = new Date(firstFail);
          const clusterEnd = new Date(lastSucc);
          const has4648 = !isNaN(clusterStart) && !isNaN(clusterEnd) && evts.some(e => {
            if (e.eventId !== "4648") return false;
            const et = new Date(e.ts);
            return !isNaN(et) && et >= new Date(clusterStart.getTime() - 300000) && et <= new Date(clusterEnd.getTime() + 300000);
          });
          // Severity logic:
          //   critical: <=5 min + 4648 explicit creds
          //   high:     default for RDP/interactive or multi-failure clusters
          //   medium:   Type 3 single-failure (passed corroboration gate above but weaker signal)
          let severity = "high";
          if (fastestDiff <= 300000 && has4648) severity = "critical";
          if (isType3 && failCount === 1 && severity !== "critical") {
            severity = (tgt && _DC_PAT.test(tgt)) ? "high" : "medium";
          }
          // Note: post-success tool correlation will be checked after all findings are built
          // (we store the pair key for later cross-referencing in edge scoring)
          const desc = failCount === 1
            ? `Failed logon followed by success within ${Math.round(fastestDiff / 1000)}s`
            : `${failCount} fail\u2192success sequences (fastest: ${Math.round(fastestDiff / 1000)}s)`;
          const ctx = [];
          if (has4648) ctx.push("explicit creds (4648)");
          if (failCount > 3) ctx.push(`${failCount} repeated sequences`);
          if (isType3) ctx.push("network logon (Type 3)");
          const _ccPills = [{ text: "same user fail\u2192success", type: "credential" }];
          if (has4648) _ccPills.push({ text: "4648 explicit creds", type: "credential" });
          if (failCount > 3) _ccPills.push({ text: `${failCount} repeated sequences`, type: "context" });
          if (isType3) _ccPills.push({ text: "Type 3 network", type: "context" });
          if (tgt && _DC_PAT.test(tgt)) _ccPills.push({ text: "DC target", type: "target" });
          else if (tgt && _SRV_PAT.test(tgt)) _ccPills.push({ text: "server target", type: "target" });
          findings.push({ id: fid++, severity, category: "Credential Compromise", mitre: "T1078", title: `Credential compromise: ${user} @ ${src} \u2192 ${tgt}`, description: desc + (ctx.length > 0 ? `. Context: ${ctx.join(", ")}` : ""), source: src, target: tgt, timeRange: { from: firstFail, to: lastSucc }, eventCount: failCount * 2, _ccUser: user, _ccPair: `${src}->${tgt}`, evidencePills: _ccPills, users: [user] });
        }
      }

      // === Process/Service/Task Scan — Stratified Queries + Per-Detector Isolation ===
      const warnings = [];
      const scanStats = {};
      const _scanEidCol = columns.eventId ? meta.colMap[columns.eventId] : null;
      const _scanTsCol = columns.ts ? meta.colMap[columns.ts] : null;
      const _scanChanCol = columns._channel ? meta.colMap[columns._channel] : null;
      const _scanDetect = (pats) => { for (const p of pats) { const f = meta.headers.find(h => p.test(h)); if (f) return meta.colMap[f]; } return null; };
      const _scanColImage = _scanDetect([/^Image$/i, /^NewProcessName$/i, /^process_name$/i, /^FileName$/i, /^ImagePath$/i]) || (isHayabusa ? _scanDetect([/^Details$/i]) : null);
      const _scanColParent = _scanDetect([/^ParentImage$/i, /^ParentProcessName$/i, /^ParentCommandLine$/i]) || (isHayabusa ? _scanDetect([/^ExtraFieldInfo$/i]) : null);
      const _scanColCmd = _scanDetect([/^CommandLine$/i, /^command_line$/i, /^ProcessCommandLine$/i, /^cmdline$/i]) || (isHayabusa ? _scanDetect([/^Details$/i]) : null);
      const _scanCols = [
        _scanColCmd, _scanColImage, _scanColParent,
        _scanDetect([/^ExecutableInfo$/i]),
        _scanDetect([/^ServiceName$/i]),
        _scanDetect([/^MapDescription$/i]),
        _scanDetect([/^Details$/i]),
        _scanDetect([/^ExtraFieldInfo$/i]),
        _scanDetect([/^RuleTitle$/i]),
        ...[1,2,3,4,5,6].map(n => { const h = meta.headers.find(h => new RegExp(`^PayloadData${n}$`, "i").test(h)); return h ? meta.colMap[h] : null; }),
      ].filter(Boolean);
      // RMM_SIGS: type = "rmm" (remote management) | "tunnel" (network tunneling)
      // exe: exact executable names (matched against _image basename)
      // svc: service names (matched against _svc field)
      // kw: fallback keywords for _alltext (only used when exe/svc don't match)
      const RMM_SIGS = [
        { name: "ConnectWise ScreenConnect", type: "rmm", exe: ["screenconnect.clientservice.exe","screenconnect.windowsclient.exe","screenconnect.service.exe"], svc: ["screenconnect client"], kw: [] },
        { name: "AnyDesk", type: "rmm", exe: ["anydesk.exe"], svc: ["anydesk"], kw: [] },
        { name: "TeamViewer", type: "rmm", exe: ["teamviewer.exe","teamviewer_service.exe"], svc: ["teamviewer"], kw: [] },
        { name: "Atera", type: "rmm", exe: ["ateraagent.exe","alphaagent.exe"], svc: ["ateraagent","aaboragent"], kw: [] },
        { name: "NetSupport Manager", type: "rmm", exe: ["client32.exe"], svc: ["client32"], kw: [] },
        { name: "Splashtop", type: "rmm", exe: ["strwinclt.exe","srservice.exe","splashtop.exe"], svc: ["splashtop","srservice"], kw: [] },
        { name: "RustDesk", type: "rmm", exe: ["rustdesk.exe"], svc: ["rustdesk"], kw: [] },
        { name: "PDQ Connect", type: "rmm", exe: ["pdqconnectagent.exe"], svc: ["pdqconnect"], kw: [] },
        { name: "MeshAgent/MeshCentral", type: "rmm", exe: ["meshagent.exe"], svc: ["meshagent","mesh agent"], kw: [] },
        { name: "Action1", type: "rmm", exe: ["action1_connector.exe","action1_agent.exe"], svc: ["action1_agent","action1_connector"], kw: [] },
        { name: "Ammyy Admin", type: "rmm", exe: ["aa_v3.exe","ammyy_admin.exe"], svc: [], kw: [] },
        { name: "Remote Utilities", type: "rmm", exe: ["rutview.exe","rutserv.exe"], svc: ["rutserv"], kw: [] },
        { name: "SimpleHelp", type: "rmm", exe: ["simplehelp.exe","simpleservice.exe"], svc: ["simplehelp"], kw: [] },
        { name: "TacticalRMM", type: "rmm", exe: ["tacticalrmm.exe"], svc: ["tacticalrmm"], kw: [] },
        { name: "FleetDeck", type: "rmm", exe: ["fleetdeck_agent.exe"], svc: ["fleetdeck"], kw: [] },
        { name: "Level.io", type: "rmm", exe: ["level-windows-amd64.exe"], svc: ["level"], kw: [] },
        { name: "DWService", type: "rmm", exe: ["dwagsvc.exe","dwagent.exe"], svc: ["dwservice","dwagsvc"], kw: [] },
        { name: "ISL Online", type: "rmm", exe: ["isllight.exe"], svc: ["isl online"], kw: [] },
        { name: "HopToDesk", type: "rmm", exe: ["hoptodesk.exe"], svc: ["hoptodesk"], kw: [] },
        { name: "Lite Manager", type: "rmm", exe: ["lmnoipserver.exe","romserver.exe"], svc: ["litemanager"], kw: [] },
        { name: "UltraVNC", type: "rmm", exe: ["uvnc_launch.exe","winvnc.exe","vncviewer.exe"], svc: ["ultravnc","uvnc_service"], kw: [] },
        { name: "TigerVNC", type: "rmm", exe: ["tvnserver.exe","vncviewer.exe"], svc: ["tvnserver"], kw: [] },
        { name: "RAdmin", type: "rmm", exe: ["rserver3.exe","radmin.exe"], svc: ["r_server"], kw: [] },
        { name: "Zoho Assist", type: "rmm", exe: ["zaservice.exe"], svc: ["zoho assist"], kw: [] },
        { name: "Pulseway", type: "rmm", exe: ["pcmonitormanager.exe","pcmonitorsrv.exe"], svc: ["pulseway","pcmonitormanager"], kw: [] },
        { name: "LabTech/Automate", type: "rmm", exe: ["ltsvc.exe","ltsvcmon.exe","lttray.exe"], svc: ["ltservice","ltsvcmon"], kw: [] },
        { name: "Kaseya VSA", type: "rmm", exe: ["agentmon.exe","kagent.exe"], svc: ["kaseya agent"], kw: [] },
        { name: "N-able/SolarWinds", type: "rmm", exe: ["solarwinds.msp.cacheservice.exe","winagent.exe"], svc: ["n-able","solarwinds.msp"], kw: [] },
        // Additional RMM tools — high-abuse in BEC/ransomware
        { name: "GoTo Resolve/LogMeIn", type: "rmm", exe: ["logmein.exe","logmeinrescue.exe","lmi_rescue.exe","goto-opener.exe","g2ax_comm_gotoresolve.exe","gotoresolve-executor.exe"], svc: ["logmein","logmeinrescue","gotoresolve"], kw: [] },
        { name: "BeyondTrust (Bomgar)", type: "rmm", exe: ["bomgar-scc.exe","bomgar-rdp.exe","btservice.exe","beyondtrustclient.exe"], svc: ["bomgar","btservice","beyondtrust"], kw: [] },
        { name: "Dameware", type: "rmm", exe: ["dwrcc.exe","dwrcst.exe","dameware mini remote control.exe"], svc: ["dameware","dwmrcs"], kw: [] },
        { name: "Supremo", type: "rmm", exe: ["supremo.exe","supremoservice.exe","supremohelper.exe"], svc: ["supremoservice"], kw: [] },
        { name: "FixMe.IT", type: "rmm", exe: ["fixmeit_client.exe","fixmeit_expert.exe","fixmeitclient.exe"], svc: ["fixmeit"], kw: [] },
        // Tunnels — separate type
        { name: "ngrok", type: "tunnel", exe: ["ngrok.exe"], svc: [], kw: [] },
        { name: "Tailscale", type: "tunnel", exe: ["tailscale.exe","tailscaled.exe"], svc: ["tailscale"], kw: [] },
        { name: "Cloudflared", type: "tunnel", exe: ["cloudflared.exe"], svc: ["cloudflared"], kw: [] },
        { name: "Chisel", type: "tunnel", exe: ["chisel.exe"], svc: [], kw: [] },
        { name: "ligolo-ng", type: "tunnel", exe: ["ligolo-agent.exe","ligolo-proxy.exe"], svc: [], kw: [] },
        { name: "ZeroTier", type: "tunnel", exe: ["zerotier-one.exe","zerotier_desktop_ui.exe"], svc: ["zerotierone","zerotier one"], kw: [] },
        { name: "WireGuard", type: "tunnel", exe: ["wireguard.exe","wg.exe"], svc: ["wireguard","wgservice"], kw: [] },
      ];
      // Build lookup indexes
      const _rmmByExe = new Map();   // basename -> tool
      const _rmmBySvc = new Map();   // service name -> tool
      for (const tool of RMM_SIGS) {
        for (const e of tool.exe) _rmmByExe.set(e.toLowerCase(), tool);
        for (const s of tool.svc) _rmmBySvc.set(s.toLowerCase(), tool);
      }
      const _isSanctionedCortexPayload = (imagePath, cmd, allText) => {
        const blob = `${imagePath || ""} ${cmd || ""} ${allText || ""}`.toLowerCase();
        if (!blob.includes("cortex-xdr-payload.exe")) return false;
        return blob.includes("palo alto networks")
          || /offline_collector_config\.json|--offline-collector|--collect-artifacts|xdr_collector/i.test(blob);
      };
      // Unusual parents for RMM context scoring
      const _rmmSusParents = new Set(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","certutil.exe","bitsadmin.exe"]);
      // Normal enterprise parents (services hosting RMM is expected)
      const _rmmNormalParents = new Set(["services.exe","svchost.exe","explorer.exe","userinit.exe","winlogon.exe","msiexec.exe"]);
      // Suspicious paths
      const _rmmSusPaths = /\\(temp|tmp|downloads|appdata\\local\\temp|users\\[^\\]+\\desktop|public|recycle)/i;
      // Microsoft productivity/sync binaries that are common in enterprise environments.
      // Use strict binary + expected path matching to avoid over-allowlisting.
      const _msProductPaths = /(?:\\appdata\\local\\microsoft\\onedrive\\|program files(?:\s*\(x86\))?\\microsoft onedrive\\|program files(?:\s*\(x86\))?\\microsoft\\edgeupdate\\|program files\\common files\\microsoft shared\\clicktorun\\|program files(?:\s*\(x86\))?\\microsoft office\\|\\office\d+\\)/i;
      const _msProductBins = new Set([
        "onedrive.exe", "groove.exe", "officeclicktorun.exe", "microsoftedgeupdate.exe", "microsoftedgeupdatecore.exe",
        "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "teams.exe", "ms-teams.exe", "ms-teamsupdate.exe",
      ]);
      const _extractExeCandidate = (blob = "") => {
        const s = String(blob || "").trim().replace(/^[`'"]+|[`'"]+$/g, "");
        if (!s) return "";
        const m = s.match(/^"([^"]+\.exe)"/i) || s.match(/([a-z]:\\[^"'\s|]+\.exe)\b/i) || s.match(/([^\s"'|]+\.exe)\b/i);
        return (m ? m[1] : "").replace(/"/g, "");
      };
      const _isExpectedMicrosoftBinary = (blob = "", signatureBlob = "") => {
        const exe = _extractExeCandidate(blob).toLowerCase();
        if (!exe) return false;
        const base = exe.includes("\\") ? exe.substring(exe.lastIndexOf("\\") + 1) : exe;
        if (!_msProductBins.has(base) || !_msProductPaths.test(exe)) return false;
        const sig = String(signatureBlob || "").toLowerCase();
        const hasSigContext = /(?:signer|signature|signed)\s*:/.test(sig);
        if (requireMicrosoftSignature) {
          return /(?:signer|signature)\s*:\s*.*microsoft/.test(sig) || (/\bsigned\s*:\s*true\b/.test(sig) && /microsoft/.test(sig));
        }
        if (hasSigContext) {
          if (/\bsigned\s*:\s*false\b/.test(sig)) return false;
          if (/(?:signer|signature)\s*:\s*(?!.*microsoft)/.test(sig)) return false;
        }
        return true;
      };
      const COMMON_SVC = new Set([
        // Generic English words common in service names
        "system","service","server","client","agent","local","admin","power","event","setup","shell","start","print","audit","group","share","trust","alert","cache","debug","error","index","input","media","model","panel","patch","proxy","query","queue","route","scene","scope","stack","stage","state","store","style","super","table","theme","timer","token","trace","track","train","trend","union","unity","usage","valid","watch",
        // Virtualization / hypervisor drivers
        "qemu","virtio","spice","vbox","vmware","hyper","xen",
        // Security / EDR / AV vendors and drivers
        "cortex","traps","cyverak","cyvrfsfd","cyvrmtgn","cyeason","cylance","carbon","sentinel","crowdstrike","falcon","defend","defender","mdatp","sense","epdr","eset","sophos","hmpalert","savservice","sophossps","mbam","npcap","winpcap","usbpcap",
        "tedrdrv","tdevflt","trellix","mfemms","mfefire","mfehidk","mfeavfk","mfevtp","enterceptagent",
        "kaspersky","klif","klifks","klflt","klhk","ksld","kneps",
        "avast","avgnt","bdagent","bitdefender","clamav","comodo",
        // Enterprise management / deployment
        "ccmsetup","ccmexec","sccm","intune","landesk","altiris","bigfix","tanium","puppet","chef","ansible","salt",
        // Common vendor services
        "google","mozilla","firefox","chrome","adobe","java","oracle","dell","lenovo","vmtools","splunk","elastic","wazuh",
        // OS / platform services
        "printer","spooler","wuauserv","bits","themes","dnscache","dhcp","winrm","winmgmt","msiserver","office","onedrive","teams",
      ]);
      if (_scanEidCol && _scanCols.length > 0) {
        // Stratified queries: separate budgets per event family to prevent bias
        const _scanConcat = _scanCols.map(c => `COALESCE(${c}, '')`).join(" || '|' || ");
        const _scanSelParts = ["data.rowid as _rid", `(${_scanConcat}) as _alltext`, `${_scanEidCol} as _eid`];
        if (_scanTsCol) _scanSelParts.push(`${_scanTsCol} as _ts`);
        const _scanHostCol = columns.target ? meta.colMap[columns.target] : null;
        if (_scanHostCol) _scanSelParts.push(`${_scanHostCol} as _host`);
        if (_scanColImage) _scanSelParts.push(`${_scanColImage} as _image`);
        if (_scanColParent) _scanSelParts.push(`${_scanColParent} as _parent`);
        if (_scanColCmd) _scanSelParts.push(`${_scanColCmd} as _cmd`);
        const _scanColSvc = _scanDetect([/^ServiceName$/i, /^Service_Name$/i]) || (isHayabusa ? _scanDetect([/^Details$/i, /^ExtraFieldInfo$/i]) : null);
        if (_scanColSvc) _scanSelParts.push(`${_scanColSvc} as _svc`);
        const _scanChanFilter = _scanChanCol
          ? ` AND (LOWER(${_scanChanCol}) LIKE '%security%' OR LOWER(${_scanChanCol}) LIKE '%sysmon%' OR LOWER(${_scanChanCol}) LIKE '%system%' OR LOWER(${_scanChanCol}) IN ('sec','sysmon','sys'))`
          : "";
        const _scanSelectClause = _scanSelParts.join(", ");
        const _scanOrderClause = " ORDER BY data.rowid ASC";
        // Per-family budgets
        const _limitFromCfg = (k, d) => {
          const v = Number(scanLimits?.[k]);
          return Number.isFinite(v) && v > 0 ? Math.floor(v) : d;
        };
        const _scanFamilies = [
          { eids: ["4688", "1"], limit: _limitFromCfg("process", 30000), label: "process" },
          { eids: ["7045", "4697"], limit: _limitFromCfg("service", 10000), label: "service" },
          { eids: ["4698"], limit: _limitFromCfg("task", 10000), label: "task" },
          { eids: ["17", "18"], limit: _limitFromCfg("namedpipe", 5000), label: "namedpipe" },
          { eids: ["8"], limit: _limitFromCfg("createthread", 5000), label: "createthread" },
        ];
        let _scanRows = [];
        for (const fam of _scanFamilies) {
          try {
            const placeholders = fam.eids.map(() => "?").join(",");
            const page = Math.max(500, Math.min(Number(scanPageSize) || 5000, 20000));
            let fetched = 0;
            let lastRid = 0;
            const famRows = [];
            while (fetched < fam.limit) {
              const chunk = Math.min(page, fam.limit - fetched);
              const sql = `SELECT ${_scanSelectClause} FROM data WHERE ${_scanEidCol} IN (${placeholders})${_scanChanFilter} AND data.rowid > ?${_scanOrderClause} LIMIT ${chunk}`;
              const rows = db.prepare(sql).all(...fam.eids, lastRid);
              if (rows.length === 0) break;
              famRows.push(...rows);
              fetched += rows.length;
              lastRid = Number(rows[rows.length - 1]._rid || lastRid);
              if (rows.length < chunk) break;
            }
            scanStats[fam.label] = famRows.length;
            if (fetched >= fam.limit) {
              warnings.push(`${fam.label} event scan hit configured limit ${fam.limit} — increase options.scanLimits.${fam.label} for fuller coverage`);
            }
            _scanRows = _scanRows.concat(famRows);
          } catch (qErr) {
            warnings.push(`${fam.label} event query failed: ${qErr.message}`);
          }
        }
        // Sort merged rows by timestamp
        if (_scanTsCol) _scanRows.sort((a, b) => ((a._ts || "") > (b._ts || "") ? 1 : (a._ts || "") < (b._ts || "") ? -1 : 0));
        const _extractHost = (row) => (row._host || "").toString().trim();

          // Accumulators: PsExec, Impacket, credential access, remote service, WMI, WinRM, RMM, scheduled tasks
          const _psexecNative = [];
          const _psexecImpacket = [];
          const _impCredAccess = [];
          const _remoteSvcExec = [];
          const _wmiHits = [];
          const _winrmHits = [];
          const _rmmHits = []; // structured per-event hits
          const _schedTaskHits = [];
          const _csHits = []; // Cobalt Strike indicators {ts, eid, host, category, detail, confidence}

          // Scan loop — isolated so a single bad row doesn't kill all detectors
          try { for (const row of _scanRows) {
            const text = (row._alltext || "").toLowerCase();
            const eid = String(row._eid || "");
            const ts = row._ts || "";
            const host = _extractHost(row);
            // Structured fields for directional detection (null if column absent)
            const _image = row._image ? row._image.toString().toLowerCase() : null;
            const _parent = row._parent ? row._parent.toString().toLowerCase() : null;
            const _cmd = row._cmd ? row._cmd.toString().toLowerCase() : null;
            const _svc = row._svc ? row._svc.toString().toLowerCase() : null;
            const _isCortexCollector = _isSanctionedCortexPayload(_image, _cmd, text);

            // --- Native PsExec (Sysinternals PSEXESVC) — checked first ---
            let isNativePsExec = false;
            // a) PSEXESVC service install (7045/4697) — destination-side
            if ((eid === "7045" || eid === "4697") && text.includes("psexesvc")) {
              _psexecNative.push({ ts, eid, d: "PSEXESVC service installed", host, side: "dest" });
              isNativePsExec = true;
            }
            // b) PSEXESVC.exe process creation (4688/1) — destination-side
            if (!isNativePsExec && text.includes("psexesvc.exe")) {
              _psexecNative.push({ ts, eid, d: "PSEXESVC.exe process execution", host, side: "dest" });
              isNativePsExec = true;
            }
            // c) psexec.exe / psexec64.exe source-side execution (4688/1)
            if (!isNativePsExec && (eid === "4688" || eid === "1") && (text.includes("psexec.exe") || text.includes("psexec64.exe"))) {
              _psexecNative.push({ ts, eid, d: "psexec.exe process execution", host, side: "source" });
              isNativePsExec = true;
            }

            // --- Impacket pattern matching — confidence: strong/medium per pattern ---
            let isImpacket = false;
            if (!isNativePsExec) {
              // Source-side: python invoking Impacket scripts (strong)
              if (!isImpacket && (eid === "4688" || eid === "1") && text.includes("python")) {
                // Credential access tools → separate category
                if (/secretsdump\.py/.test(text)) {
                  _impCredAccess.push({ ts, eid, host, side: "source", evidence: "python secretsdump.py execution" });
                  isImpacket = true;
                } else {
                  const _impScripts = [
                    { re: /psexec\.py/, v: "psexec.py" }, { re: /smbexec\.py/, v: "smbexec.py" },
                    { re: /wmiexec\.py/, v: "wmiexec.py" }, { re: /dcomexec\.py/, v: "dcomexec.py" },
                    { re: /atexec\.py/, v: "atexec.py" },
                  ];
                  for (const s of _impScripts) {
                    if (s.re.test(text)) {
                      _psexecImpacket.push({ v: s.v, ts, eid, host, side: "source", confidence: "strong", evidence: `python ${s.v} execution on source` });
                      isImpacket = true; break;
                    }
                  }
                }
              }
              // 1. Generic Impacket: cmd.exe /Q /c ... \\127.0.0.1\ADMIN$ — confidence varies by refinement
              if (!isImpacket && text.includes("/q /c") && text.includes("\\\\127.0.0.1\\") && text.includes("admin$")) {
                let v = "Impacket", conf = "medium";
                if (text.includes("__output")) { v = "smbexec.py"; conf = "strong"; }
                else if (text.includes("wmiprvse")) { v = "wmiexec.py"; }
                else if (text.includes("mmc.exe") || text.includes("-embedding")) { v = "dcomexec.py"; }
                else if (text.includes("admin$\\__")) { v = "wmiexec.py"; }
                _psexecImpacket.push({ v, ts, eid, host, side: "dest", confidence: conf, evidence: "cmd.exe /Q /c with ADMIN$ output redirect" }); isImpacket = true;
              }
              // 2. smbexec __output + redirect (strong)
              if (!isImpacket && text.includes("__output") && (text.includes("2^>^&1") || text.includes("2>&1"))) {
                _psexecImpacket.push({ v: "smbexec.py", ts, eid, host, side: "dest", confidence: "strong", evidence: "__output redirect pattern" }); isImpacket = true;
              }
              // 3. smbexec COMSPEC + triple .bat (medium)
              if (!isImpacket && text.includes("%comspec%") && (text.match(/\.bat/g) || []).length >= 3) {
                _psexecImpacket.push({ v: "smbexec.py", ts, eid, host, side: "dest", confidence: "medium", evidence: "%COMSPEC% batch execution chain" }); isImpacket = true;
              }
              // 4. wmiexec: wmiprvse.exe spawning cmd.exe /Q (medium)
              if (!isImpacket && text.includes("wmiprvse.exe") && text.includes("cmd.exe") && text.includes("/q")) {
                _psexecImpacket.push({ v: "wmiexec.py", ts, eid, host, side: "dest", confidence: "medium", evidence: "wmiprvse.exe spawning cmd.exe /Q" }); isImpacket = true;
              }
              // 5. dcomexec: mmc.exe -Embedding ONLY with execution indicators
              // Bare mmc.exe -Embedding is normal Windows DCOM snap-in behavior (gpedit, diskmgmt, etc.)
              // Require cmd.exe /c or powershell follow-on to distinguish dcomexec.py from admin tools
              if (!isImpacket && text.includes("mmc.exe") && text.includes("-embedding") && (text.includes("cmd.exe") || text.includes("cmd /c") || text.includes("powershell") || text.includes("pwsh"))) {
                _psexecImpacket.push({ v: "dcomexec.py", ts, eid, host, side: "dest", confidence: "medium", evidence: "MMC DCOM execution with command follow-on" }); isImpacket = true;
              }
              // 6. atexec: output to Windows\Temp\*.tmp + redirect (medium)
              if (!isImpacket && text.includes("\\temp\\") && /\\[a-z]{8}\.tmp/i.test(text) && text.includes("2>&1")) {
                _psexecImpacket.push({ v: "atexec.py", ts, eid, host, side: "dest", confidence: "medium", evidence: "Temp .tmp output file with redirect" }); isImpacket = true;
              }
              // 7. atexec: hardcoded StartBoundary (strong)
              if (!isImpacket && text.includes("2015-07-15t20:35:13")) {
                _psexecImpacket.push({ v: "atexec.py", ts, eid, host, side: "dest", confidence: "strong", evidence: "Hardcoded StartBoundary 2015-07-15T20:35:13" }); isImpacket = true;
              }
              // 8. psexec.py: RemCom named pipes (strong)
              if (!isImpacket && (text.includes("remcom_communicat") || text.includes("remcom_stdin") || text.includes("remcom_stdout") || text.includes("remcom_stderr"))) {
                _psexecImpacket.push({ v: "psexec.py", ts, eid, host, side: "dest", confidence: "strong", evidence: "RemCom named pipe" }); isImpacket = true;
              }
              // 9. smbexec: BTOBTO service name (strong)
              if (!isImpacket && (eid === "7045" || eid === "4697") && text.includes("btobto")) {
                _psexecImpacket.push({ v: "smbexec.py", ts, eid, host, side: "dest", confidence: "strong", evidence: 'Service name "BTOBTO"' }); isImpacket = true;
              }
            }

            // --- Remote Service Execution fallback (suspicious service installs without Impacket anchor) ---
            if (!isImpacket && !isNativePsExec && (eid === "7045" || eid === "4697")) {
              let suspicious = false;
              let reason = "";
              const _sigBlob = `${_image || ""} ${_cmd || ""} ${text}`;
              const _isMsExpectedSvc = _isExpectedMicrosoftBinary(_image || "", _sigBlob)
                || _isExpectedMicrosoftBinary(_cmd || "", _sigBlob)
                || _isExpectedMicrosoftBinary(text, _sigBlob);
              // a) Service binary using command interpreter
              const hasCmdBin = text.includes("cmd /c") || text.includes("cmd.exe /c") || text.includes("%comspec%") || ((text.includes("powershell") || text.includes("pwsh")) && (text.includes("-encodedcommand") || text.includes("-enc ") || /\s-e\s+[A-Za-z0-9+/=]{20,}/.test(text)));
              if (hasCmdBin) {
                suspicious = true;
                reason = "Service binary uses command interpreter";
              }
              // b) Service image in user-writable/temporary path
              if (!suspicious && /\\(?:users\\|appdata\\|temp\\|tmp\\|downloads\\|public\\|programdata\\)/i.test(text)) {
                suspicious = true;
                reason = "Service binary from user-writable path";
              }
              // c) LOLBin used directly as service image
              if (!suspicious && /\b(?:rundll32|regsvr32|mshta|wscript|cscript|powershell|pwsh|cmd\.exe|certutil|bitsadmin|msiexec)\b/i.test(text)) {
                suspicious = true;
                reason = "Service image uses LOLBin";
              }
              // d) Remote-admin-share / UNC service image path
              if (!suspicious && /\\\\[^\\]+\\(?:admin\$|c\$|[a-z]\$)\\[^|"\s]+/i.test(text)) {
                suspicious = true;
                reason = "Service image from remote admin share";
              }
              // e) Random short service name (4-8 alpha chars, not in COMMON_SVC)
              // Use structured ServiceName field when available; fall back to regex on blob
              if (!suspicious && !_isMsExpectedSvc) {
                let _svcName = null;
                if (_svc) {
                  // Structured ServiceName column — use directly
                  const svcTrim = _svc.trim();
                  if (/^[a-z]{4,8}$/i.test(svcTrim)) _svcName = svcTrim;
                } else {
                  // Blob fallback: match "ServiceName: xxx" or "Name: xxx" patterns from EvtxECmd
                  const snMatch = text.match(/\bservice\s*name[:\s]+([a-z]{4,8})\b/i) || text.match(/\bname[:\s]+([a-z]{4,8})\b/i);
                  if (snMatch) _svcName = snMatch[1];
                }
                if (_svcName && !COMMON_SVC.has(_svcName.toLowerCase())) {
                  // Additional FP guard: skip names that look like known vendor driver prefixes
                  const _sn = _svcName.toLowerCase();
                  const _knownPrefixes = /^(cyv[a-z]|ted[a-z]|tde[a-z]|mfe[a-z]|kl[a-z]{2}|sav[a-z]|hmp[a-z]|avg[a-z]|bdl[a-z]|epa[a-z])/;
                  if (!_knownPrefixes.test(_sn)) {
                    suspicious = true;
                    reason = `Random ${_svcName.length}-char service name: ${_svcName}`;
                  }
                }
              }
              if (suspicious) {
                _remoteSvcExec.push({ ts, eid, d: reason, host, side: "dest" });
              }
            }

            // --- WMI detection (exec flag separates execution from query/activity) ---
            if (!isNativePsExec && !isImpacket && (eid === "4688" || eid === "1")) {
              // Destination-side: wmiprvse.exe spawning shell/LOLBin — requires directional parent-child evidence
              const _wmiChildBins = ["cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "cscript.exe", "wscript.exe"];
              if (text.includes("wmiprvse.exe")) {
                if (_parent && _image) {
                  // Structured fields: require ParentImage = wmiprvse.exe, Image = child binary
                  const parentBin = _parent.split("\\").pop();
                  const imageBin = _image.split("\\").pop();
                  if (parentBin === "wmiprvse.exe") {
                    for (const child of _wmiChildBins) {
                      if (imageBin === child) {
                        _wmiHits.push({ ts, eid, d: `wmiprvse.exe \u2192 ${child}`, host, side: "dest", exec: true, _blob: false });
                        break;
                      }
                    }
                  }
                  // else: wmiprvse.exe is the Image (process itself), not parent — not a WMI exec spawn
                } else {
                  // Blob fallback: no structured columns — lower confidence, require stronger co-occurrence
                  if (text.includes("cmd.exe") && (text.includes("/q") || text.includes("/c "))) {
                    _wmiHits.push({ ts, eid, d: "wmiprvse.exe + cmd.exe /c (blob match)", host, side: "dest", exec: true, _blob: true });
                  } else if ((text.includes("powershell") || text.includes("pwsh")) && (text.includes("-c ") || text.includes("-command") || text.includes("-enc"))) {
                    _wmiHits.push({ ts, eid, d: "wmiprvse.exe + powershell (blob match)", host, side: "dest", exec: true, _blob: true });
                  }
                }
              }
              // Source-side: wmic.exe /node:TARGET — exec only if explicit process creation
              else if ((text.includes("wmic.exe") || text.includes("wmic ")) && text.includes("/node:")) {
                const nodeMatch = text.match(/\/node:\s*"?([^\s"]+)"?/i);
                const remoteTarget = nodeMatch ? nodeMatch[1] : null;
                const isWmicExec = text.includes("process call create") || text.includes("win32_process.create");
                _wmiHits.push({ ts, eid, d: `wmic.exe /node:${remoteTarget || "?"}${isWmicExec ? " (process create)" : ""}`, host, side: "source", remoteTarget, exec: isWmicExec });
              }
              // Source-side: PowerShell WMI/CIM methods — split exec vs query
              else {
                // Execution primitives: invoke methods, process creation
                const _wmiExec = ["invoke-wmimethod", "invoke-cimmethod", "win32_process.create"];
                // Query/session primitives: remote access but not execution
                const _wmiQuery = ["get-wmiobject", "gwmi ", "[wmiclass]", "get-ciminstance", "new-cimsession"];
                let matched = false;
                for (const m of _wmiExec) {
                  if (text.includes(m)) {
                    const cnMatch = text.match(/-computername\s+["']?([^\s"',;]+)/i);
                    const remoteTarget = cnMatch ? cnMatch[1] : null;
                    _wmiHits.push({ ts, eid, d: `PowerShell WMI/CIM: ${m.trim()}${remoteTarget ? ` → ${remoteTarget}` : ""}`, host, side: "source", remoteTarget, exec: true });
                    matched = true; break;
                  }
                }
                if (!matched) {
                  for (const m of _wmiQuery) {
                    if (text.includes(m)) {
                      const cnMatch = text.match(/-computername\s+["']?([^\s"',;]+)/i);
                      const remoteTarget = cnMatch ? cnMatch[1] : null;
                      // Only emit query hits with an explicit remote target — local queries are not lateral movement
                      if (remoteTarget) {
                        _wmiHits.push({ ts, eid, d: `PowerShell WMI/CIM: ${m.trim()} → ${remoteTarget}`, host, side: "source", remoteTarget, exec: false });
                      }
                      break;
                    }
                  }
                }
              }
            }

            // --- WinRM detection (exec flag separates execution from session/activity) ---
            if (!isNativePsExec && !isImpacket && (eid === "4688" || eid === "1")) {
              // Destination-side: wsmprovhost.exe — requires directional parent-child evidence
              if (text.includes("wsmprovhost.exe")) {
                const _winrmChildBins = ["cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe"];
                let childDesc = null;
                if (_parent && _image) {
                  // Structured fields: require ParentImage = wsmprovhost.exe, Image = child
                  const parentBin = _parent.split("\\").pop();
                  const imageBin = _image.split("\\").pop();
                  if (parentBin === "wsmprovhost.exe") {
                    for (const child of _winrmChildBins) {
                      if (imageBin === child) { childDesc = child; break; }
                    }
                    _winrmHits.push({ ts, eid, d: childDesc ? `wsmprovhost.exe \u2192 ${childDesc}` : "wsmprovhost.exe process execution", host, side: "dest", hasChild: !!childDesc, exec: !!childDesc, _blob: false });
                  }
                  // else: wsmprovhost.exe is Image, not parent — skip
                } else {
                  // Blob fallback: lower confidence co-occurrence
                  for (const child of _winrmChildBins) {
                    if (text.includes(child)) { childDesc = child; break; }
                  }
                  if (childDesc) {
                    _winrmHits.push({ ts, eid, d: `wsmprovhost.exe + ${childDesc} (blob match)`, host, side: "dest", hasChild: true, exec: true, _blob: true });
                  }
                }
              }
              // Source-side: winrs.exe — execution (runs commands remotely)
              else if (text.includes("winrs.exe")) {
                const rMatch = text.match(/\/r:\s*([^\s]+)/i) || text.match(/-r:\s*([^\s]+)/i);
                const remoteTarget = rMatch ? rMatch[1] : null;
                _winrmHits.push({ ts, eid, d: `winrs.exe remote shell${remoteTarget ? ` → ${remoteTarget}` : ""}`, host, side: "source", remoteTarget, exec: true });
              }
              // Source-side: PowerShell remoting — Invoke-Command is exec, session setup is activity
              else {
                if (text.includes("invoke-command")) {
                  const cnMatch = text.match(/-computername\s+["']?([^\s"',;]+)/i);
                  const remoteTarget = cnMatch ? cnMatch[1] : null;
                  _winrmHits.push({ ts, eid, d: `PowerShell remoting: Invoke-Command${remoteTarget ? ` → ${remoteTarget}` : ""}`, host, side: "source", remoteTarget, exec: true });
                } else {
                  const _psSession = ["enter-pssession", "new-pssession"];
                  for (const c of _psSession) {
                    if (text.includes(c)) {
                      const cnMatch = text.match(/-computername\s+["']?([^\s"',;]+)/i);
                      const remoteTarget = cnMatch ? cnMatch[1] : null;
                      _winrmHits.push({ ts, eid, d: `PowerShell remoting: ${c}${remoteTarget ? ` → ${remoteTarget}` : ""}`, host, side: "source", remoteTarget, exec: false });
                      break;
                    }
                  }
                }
              }
            }

            // --- RMM structured matching (exe name, service name, command line) ---
            {
              if (_isCortexCollector) {
                // Cortex XDR payload / offline collector is sanctioned security tooling, not RMM.
              } else {
              let _rmmMatch = null;
              let _rmmKind = null; // install | process | service | cmdline
              // 1. Executable name match (most precise)
              if (_image) {
                const basename = _image.includes("\\") ? _image.substring(_image.lastIndexOf("\\") + 1) : _image.includes("/") ? _image.substring(_image.lastIndexOf("/") + 1) : _image;
                if (_rmmByExe.has(basename)) {
                  _rmmMatch = _rmmByExe.get(basename);
                  _rmmKind = (eid === "7045" || eid === "4697") ? "install" : "process";
                }
              }
              // 2. Service name match on 7045/4697 — exact match after trim
              if (!_rmmMatch && _svc && (eid === "7045" || eid === "4697")) {
                const svcNorm = _svc.trim();
                if (_rmmBySvc.has(svcNorm)) { _rmmMatch = _rmmBySvc.get(svcNorm); _rmmKind = "install"; }
              }
              // 3. ImagePath in service install — check _alltext for exe names on 7045/4697
              if (!_rmmMatch && (eid === "7045" || eid === "4697")) {
                for (const [exeName, tool] of _rmmByExe) {
                  if (text.includes(exeName)) { _rmmMatch = tool; _rmmKind = "service"; break; }
                }
              }
              // 4. Command-line invocation (process events only)
              if (!_rmmMatch && _cmd && (eid === "4688" || eid === "1")) {
                for (const [exeName, tool] of _rmmByExe) {
                  if (_cmd.includes(exeName)) { _rmmMatch = tool; _rmmKind = "cmdline"; break; }
                }
              }
              if (_rmmMatch) {
                const parentBasename = _parent ? (_parent.includes("\\") ? _parent.substring(_parent.lastIndexOf("\\") + 1) : _parent) : null;
                _rmmHits.push({
                  tool: _rmmMatch.name, toolType: _rmmMatch.type,
                  host: host || "", ts, eid, kind: _rmmKind,
                  image: _image || "", parent: parentBasename || "",
                  cmd: (_cmd || "").substring(0, 300),
                  imagePath: _image || "",
                });
              }
              }
            }

            // --- Scheduled Task Remote Execution (4698) ---
            if (eid === "4698") {
              if (_isCortexCollector) continue;
              // Parse task content from the event text for suspicious actions
              const _suspBins = ["cmd.exe", "cmd /c", "cmd.exe /c", "%comspec%", "powershell", "pwsh", "rundll32", "mshta", "regsvr32", "cscript", "wscript", "certutil", "bitsadmin", "msiexec"];
              const _suspPaths = ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\public\\", "admin$", "\\perflogs\\", "\\programdata\\"];
              let taskAction = null;
              let taskName = null;
              let isSuspicious = false;
              let reason = "";
              // Extract task name: <URI> or TaskName: patterns
              const tnMatch = text.match(/<uri>\s*([^<]+)/i) || text.match(/taskname[:\s]+\\?([^\s|<]+)/i) || text.match(/\\([^\s\\|<]+)\s*$/m);
              if (tnMatch) taskName = tnMatch[1].replace(/^\\+/, "").trim();
              // Extract action/command from XML or flat text
              const actMatch = text.match(/<command>\s*([^<]+)/i) || text.match(/<exec>\s*([^<]+)/i) || text.match(/<arguments>\s*([^<]+)/i);
              if (actMatch) taskAction = actMatch[1].trim();
              // Check for suspicious binaries in action or full text
              for (const bin of _suspBins) {
                if (text.includes(bin)) { isSuspicious = true; reason = `Task action contains ${bin}`; break; }
              }
              // Check for suspicious paths
              if (!isSuspicious) {
                for (const sp of _suspPaths) {
                  if (text.includes(sp)) { isSuspicious = true; reason = `Task references suspicious path: ${sp.replace(/\\/g, "")}`; break; }
                }
              }
              // Check for encoded command / base64 patterns
              if (!isSuspicious) {
                const hasPsCtx = text.includes("powershell") || text.includes("pwsh");
                if (text.includes("-encodedcommand") || text.includes("-enc ") || (hasPsCtx && /\s-e\s+[A-Za-z0-9+/=]{20,}/.test(text))) {
                  isSuspicious = true; reason = "Task uses encoded PowerShell command";
                }
              }
              // Check for atexec.py signature (hardcoded StartBoundary or temp output redirect)
              if (!isSuspicious && (text.includes("2015-07-15t20:35:13") || (text.includes("\\temp\\") && text.includes("2>&1")))) {
                isSuspicious = true; reason = "atexec.py task signature";
              }
              // Check for very short/random task names (4-8 alpha chars, not common words)
              if (!isSuspicious && taskName) {
                const shortName = taskName.replace(/^.*\\/, "");
                if (/^[a-z]{4,8}$/i.test(shortName) && !COMMON_SVC.has(shortName.toLowerCase())) {
                  isSuspicious = true; reason = `Random task name: ${shortName}`;
                }
              }
              // FP controls: skip known enterprise management task patterns
              const _mgmtTaskPat = /^(microsoft|windows|google|adobe|mozilla|intel|dell|hp|lenovo|vmware|citrix|sophos|symantec|mcafee|crowdstrike|carbon|sentinel|defender|sccm|configmgr|intune|wsus|omsconfig|gathernetwork|user_feed|automate|patchmypc|nessus|qualys|rapid7|tenable)/i;
              if (isSuspicious && taskName && _mgmtTaskPat.test(taskName.replace(/^.*\\/, ""))) {
                isSuspicious = false; // known vendor/management task
              }
              // Additional FP control: Microsoft OneDrive/SharePoint/Office task action from expected path+binary.
              const _msTaskNamePat = /(?:onedrive|sharepoint|groove|office|microsoft)/i;
              const _msExpectedTaskAction = _isExpectedMicrosoftBinary(taskAction || "") || _isExpectedMicrosoftBinary(text);
              if (isSuspicious && _msExpectedTaskAction && (!taskName || _msTaskNamePat.test(taskName))) {
                isSuspicious = false;
              }
              if (isSuspicious) {
                _schedTaskHits.push({
                  ts, eid, host, side: "dest",
                  d: reason + (taskName ? ` (task: ${taskName})` : "") + (taskAction ? ` [${taskAction.slice(0, 80)}]` : ""),
                  taskName: taskName || "(unnamed)", taskAction,
                });
              }
            }

            // --- Source-side schtasks.exe with /create /s (4688/1) ---
            if ((eid === "4688" || eid === "1") && text.includes("schtasks") && text.includes("/create") && text.includes("/s ")) {
              if (_isCortexCollector) continue;
              const targetMatch = text.match(/\/s\s+["']?([^\s"',;]+)/i);
              const remoteTarget = targetMatch ? targetMatch[1] : null;
              if (remoteTarget && remoteTarget !== "localhost" && remoteTarget !== "127.0.0.1") {
                _schedTaskHits.push({
                  ts, eid, host, side: "source", remoteTarget,
                  d: `schtasks /create /s ${remoteTarget}`,
                  taskName: null, taskAction: null,
                });
              }
            }

            // === Cobalt Strike Detection (T1055 / T1569.002 / T1059.001) ===
            {
              // --- A) Named Pipe detection (Sysmon EID 17/18) ---
              // Default CS pipes: postex_*, MSSE-*-server, msagent_*, status_*, *-server
              if (eid === "17" || eid === "18") {
                const pipeField = text;
                // Default Cobalt Strike named pipes
                const _csPipePatterns = [
                  { re: /\\postex_/i, name: "postex_*", confidence: "high" },
                  { re: /\\postex_ssh_/i, name: "postex_ssh_*", confidence: "high" },
                  { re: /\\msagent_/i, name: "msagent_*", confidence: "high" },
                  { re: /\\MSSE-[0-9a-f]+-server/i, name: "MSSE-*-server", confidence: "high" },
                  { re: /\\status_[0-9a-f]+/i, name: "status_*", confidence: "medium" },
                  // CS 4.2+ default: random hex pipe names — match the {hex}-server pattern
                  { re: /\\[0-9a-f]{7,8}-server/i, name: "hex-server", confidence: "medium" },
                ];
                for (const p of _csPipePatterns) {
                  if (p.re.test(pipeField)) {
                    _csHits.push({ ts, eid, host, category: "named_pipe", detail: `Named pipe: ${p.name}`, confidence: p.confidence });
                    break;
                  }
                }
              }

              // --- B) GetSystem service pattern (7045/4697) ---
              // CS GetSystem creates a service that echoes a token to a named pipe:
              // cmd.exe /c echo XXXX > \\.\pipe\XXXX
              if ((eid === "7045" || eid === "4697") && /\\\\.\\pipe\\/i.test(text) && (text.includes("cmd") || text.includes("%comspec%")) && text.includes("echo")) {
                _csHits.push({ ts, eid, host, category: "getsystem", detail: "GetSystem: service with cmd.exe echo to named pipe", confidence: "high" });
              }

              // --- C) Default spawn-to abuse (4688/1) ---
              // CS default spawn-to: rundll32.exe with no arguments, or dllhost.exe with no arguments
              // These are process hollowing targets
              if ((eid === "4688" || eid === "1") && _image && _cmd) {
                const imageBin = _image.includes("\\") ? _image.substring(_image.lastIndexOf("\\") + 1) : _image;
                const cmdTrimmed = _cmd.trim().replace(/^"[^"]*"/, "").trim();
                const isDefaultSpawnTo = (imageBin === "rundll32.exe" || imageBin === "dllhost.exe");
                // No arguments = process hollowing container (CS injects beacon into it)
                if (isDefaultSpawnTo && cmdTrimmed.length === 0) {
                  // Verify it's not a normal rundll32/dllhost invocation by checking parent
                  const parentBin = _parent ? (_parent.includes("\\") ? _parent.substring(_parent.lastIndexOf("\\") + 1) : _parent) : null;
                  // Normal parents for rundll32/dllhost: svchost.exe, services.exe, explorer.exe
                  const _normalSpawnParents = new Set(["svchost.exe", "services.exe", "explorer.exe", "taskeng.exe", "taskhostw.exe", "dllhost.exe", "sihost.exe", "runtimebroker.exe"]);
                  if (!parentBin || !_normalSpawnParents.has(parentBin)) {
                    _csHits.push({ ts, eid, host, category: "spawn_to", detail: `${imageBin} launched with no arguments${parentBin ? ` (parent: ${parentBin})` : ""}`, confidence: "medium" });
                  }
                }
              }

              // --- D) CreateRemoteThread into LSASS or suspicious targets (Sysmon EID 8) ---
              if (eid === "8") {
                const isLsass = text.includes("lsass.exe");
                const isRuntimeBroker = text.includes("runtimebroker.exe");
                if (isLsass) {
                  _csHits.push({ ts, eid, host, category: "injection", detail: "CreateRemoteThread into lsass.exe (credential theft)", confidence: "high" });
                } else if (isRuntimeBroker) {
                  _csHits.push({ ts, eid, host, category: "injection", detail: "CreateRemoteThread into RuntimeBroker.exe", confidence: "medium" });
                }
              }

              // --- E) Encoded PowerShell beacon stager (4688/1) ---
              if ((eid === "4688" || eid === "1") && (text.includes("powershell") || text.includes("pwsh"))) {
                const hasEnc = text.includes("-encodedcommand") || text.includes("-enc ") || /\s-e\s+[A-Za-z0-9+/=]{40,}/.test(text) || /\s-ec\s+[A-Za-z0-9+/=]{40,}/.test(text);
                if (hasEnc) {
                  // Check for shellcode / download cradle indicators in the encoded payload
                  const hasShellcode = /frombase64string|virtualalloc|kernel32|memcpy|createthread|iex\s*\(|downloadstring|downloaddata|downloadfile|invoke-expression|net\.webclient|bitstransfer|start-bitstransfer/i.test(text);
                  const hasLongPayload = /[A-Za-z0-9+/=]{200,}/.test(text);
                  if (hasShellcode || hasLongPayload) {
                    _csHits.push({ ts, eid, host, category: "beacon_stager", detail: `Encoded PowerShell${hasShellcode ? " with shellcode/download cradle" : " with large payload"}`, confidence: hasShellcode ? "high" : "medium" });
                  }
                }
              }

              // --- F) CS service install pattern: %COMSPEC% /b /c start /b /min ... (7045/4697) ---
              if ((eid === "7045" || eid === "4697") && text.includes("%comspec%") && text.includes("/b") && text.includes("start")) {
                _csHits.push({ ts, eid, host, category: "service_beacon", detail: "Service with %COMSPEC% /b /c start pattern (CS lateral move)", confidence: "high" });
              }

              // --- G) PowerShell download cradle without encoding (4688/1) ---
              if ((eid === "4688" || eid === "1") && (text.includes("powershell") || text.includes("pwsh"))) {
                if (!text.includes("-encodedcommand") && !text.includes("-enc ")) {
                  const hasCradle = /iex\s*\(\s*\(?new-object\s+(?:net\.webclient|system\.net\.webclient)\)?\s*\.download(?:string|data|file)/i.test(text)
                    || /invoke-expression.*download/i.test(text)
                    || /\[system\.reflection\.assembly\]::load/i.test(text);
                  if (hasCradle) {
                    _csHits.push({ ts, eid, host, category: "beacon_stager", detail: "PowerShell download cradle (IEX/WebClient/Reflection)", confidence: "high" });
                  }
                }
              }
            }

          } } catch (_scanLoopErr) { warnings.push(`Scan loop error: ${_scanLoopErr.message}`); console.error("LM scan loop error:", _scanLoopErr); }

          // === Cobalt Strike Discovery Burst Detection ===
          // Detect rapid enumeration commands (net group, nltest, whoami, etc.) within 2-min windows
          // CS aggressor scripts run automated discovery on initial beacon
          try {
            const _discoveryBins = new Set(["whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "qprocess.exe", "qwinsta.exe", "klist.exe", "cmdkey.exe", "nslookup.exe"]);
            const _discoveryKw = ["net group", "net localgroup", "net user", "net view", "net session", "nltest /domain_trusts", "nltest /dclist", "whoami /priv", "whoami /groups", "whoami /all", "arp -a", "route print", "netstat -an"];
            const _discoveryHits = [];
            for (const row of _scanRows) {
              const eid = String(row._eid || "");
              if (eid !== "4688" && eid !== "1") continue;
              const text = (row._alltext || "").toLowerCase();
              const _image = row._image ? row._image.toString().toLowerCase() : null;
              const imageBin = _image ? (_image.includes("\\") ? _image.substring(_image.lastIndexOf("\\") + 1) : _image) : null;
              let isDiscovery = false;
              if (imageBin && _discoveryBins.has(imageBin)) isDiscovery = true;
              if (!isDiscovery) {
                for (const kw of _discoveryKw) { if (text.includes(kw)) { isDiscovery = true; break; } }
              }
              if (isDiscovery) {
                _discoveryHits.push({ ts: row._ts || "", host: (row._host || "").toString().trim().toUpperCase(), cmd: imageBin || text.substring(0, 80) });
              }
            }
            // Group by host, check for burst (5+ commands in 2 min)
            if (_discoveryHits.length > 0) {
              const _discByHost = new Map();
              for (const h of _discoveryHits) {
                if (!_discByHost.has(h.host)) _discByHost.set(h.host, []);
                _discByHost.get(h.host).push(h);
              }
              for (const [host, hits] of _discByHost) {
                hits.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
                // Sliding window: 5+ hits in 2 min
                for (let i = 0; i <= hits.length - 5; i++) {
                  const t0 = new Date(hits[i].ts).getTime();
                  const t4 = new Date(hits[i + 4].ts).getTime();
                  if (!isNaN(t0) && !isNaN(t4) && (t4 - t0) <= 120000) {
                    // Find full burst extent
                    let burstEnd = i + 4;
                    for (let j = burstEnd + 1; j < hits.length; j++) {
                      const tj = new Date(hits[j].ts).getTime();
                      if (!isNaN(tj) && (tj - t0) <= 120000) burstEnd = j;
                      else break;
                    }
                    const burstHits = hits.slice(i, burstEnd + 1);
                    const cmds = [...new Set(burstHits.map(h => h.cmd))];
                    _csHits.push({
                      ts: hits[i].ts, eid: "4688", host,
                      category: "discovery_burst",
                      detail: `${burstHits.length} enumeration commands in <2 min: ${cmds.slice(0, 8).join(", ")}${cmds.length > 8 ? ` +${cmds.length - 8} more` : ""}`,
                      confidence: cmds.length >= 8 ? "high" : "medium",
                      _burstCount: burstHits.length, _burstCmds: cmds,
                    });
                    break; // one burst finding per host
                  }
                }
              }
            }
          } catch (_discErr) { warnings.push(`Discovery burst detection failed: ${_discErr.message}`); }

          // === Cobalt Strike: Pass the Hash detection (Logon Type 9 = NewCredentials) ===
          // Type 9 is used by runas /netonly and CS pth command — rare in normal operations
          try {
            for (const evt of timeOrdered) {
              if (evt.eventId !== "4624" || evt.logonType !== "9") continue;
              // Skip SYSTEM/service accounts — Type 9 from SYSTEM is common for scheduled tasks
              const u = (evt.user || "").toUpperCase();
              if (u === "SYSTEM" || u === "LOCAL SERVICE" || u === "NETWORK SERVICE" || u.endsWith("$")) continue;
              _csHits.push({
                ts: evt.ts, eid: "4624", host: (evt.target || "").toUpperCase(),
                category: "pass_the_hash",
                detail: `Type 9 (NewCredentials) logon: ${evt.user || "(unknown)"} from ${(evt.source || "local").toUpperCase()}`,
                confidence: "high",
              });
            }
          } catch (_pthErr) { warnings.push(`Pass the Hash detection failed: ${_pthErr.message}`); }

          // === Emit Cobalt Strike findings ===
          try { if (_csHits.length > 0 && !_disabledSet.has("cobaltstrike")) {
            // Group by host, then by category
            const _csByHost = new Map();
            for (const h of _csHits) {
              const hk = h.host || "(unknown)";
              if (!_csByHost.has(hk)) _csByHost.set(hk, []);
              _csByHost.get(hk).push(h);
            }
            for (const [host, hostHits] of _csByHost) {
              // Group by category
              const _csByCat = new Map();
              for (const h of hostHits) {
                if (!_csByCat.has(h.category)) _csByCat.set(h.category, []);
                _csByCat.get(h.category).push(h);
              }
              const categories = [..._csByCat.keys()];
              const highConfCount = hostHits.filter(h => h.confidence === "high").length;
              const totalIndicators = hostHits.length;
              const uniqueCategories = categories.length;

              // Composite confidence: multiple categories or high-confidence hits = stronger signal
              // Single medium-confidence hit in isolation = suppress (too FP-prone)
              if (totalIndicators === 1 && hostHits[0].confidence === "medium") continue;

              let severity;
              if (uniqueCategories >= 4 || (uniqueCategories >= 3 && highConfCount >= 2)) severity = "critical";
              else if (uniqueCategories >= 3 || highConfCount >= 2) severity = "high";
              else if (uniqueCategories >= 2 || highConfCount >= 1) severity = "high";
              else severity = "medium";

              const allTs = hostHits.map(h => h.ts).filter(Boolean).sort();
              const pills = [];
              const _csCatLabels = {
                named_pipe: "CS named pipe",
                getsystem: "GetSystem",
                spawn_to: "spawn-to hollowing",
                injection: "process injection",
                beacon_stager: "beacon stager",
                service_beacon: "service-based beacon",
                discovery_burst: "automated discovery",
                pass_the_hash: "Pass the Hash",
              };
              for (const cat of categories) {
                const label = _csCatLabels[cat] || cat;
                const count = _csByCat.get(cat).length;
                pills.push({ text: `${label}${count > 1 ? ` (${count})` : ""}`, type: cat === "named_pipe" || cat === "getsystem" || cat === "service_beacon" ? "execution" : cat === "injection" || cat === "pass_the_hash" ? "credential" : cat === "discovery_burst" ? "context" : "execution" });
              }
              if (uniqueCategories >= 3) pills.push({ text: "multi-stage", type: "execution" });
              pills.push({ text: `${totalIndicators} indicator${totalIndicators > 1 ? "s" : ""}`, type: "context" });

              // Build description from category summaries
              const descParts = [];
              for (const [cat, hits] of _csByCat) {
                const label = _csCatLabels[cat] || cat;
                if (hits.length <= 2) {
                  descParts.push(hits.map(h => h.detail).join("; "));
                } else {
                  descParts.push(`${label}: ${hits.length} events (${hits.slice(0, 2).map(h => h.detail).join("; ")} +${hits.length - 2} more)`);
                }
              }

              findings.push({
                id: fid++, severity, category: "Cobalt Strike", mitre: "T1055",
                title: `Cobalt Strike indicators on ${host} (${uniqueCategories} categor${uniqueCategories > 1 ? "ies" : "y"})`,
                description: descParts.join(". "),
                source: "", target: host,
                filterHosts: [host],
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: totalIndicators,
                filterEids: [...new Set(hostHits.map(h => h.eid))],
                evidencePills: pills,
                users: [...new Set(hostHits.filter(h => h.category === "pass_the_hash").map(h => {
                  const m = h.detail.match(/:\s*(\S+)\s+from/); return m ? m[1] : null;
                }).filter(Boolean))],
              });
            }
          } } catch (_csErr) { warnings.push(`Cobalt Strike detector failed: ${_csErr.message}`); }

          // --- Emit Native PsExec findings ---
          try { if (_psexecNative.length > 0) {
            const destHosts = [...new Set(_psexecNative.filter(h => h.side === "dest" && h.host).map(h => h.host))];
            const srcHosts = [...new Set(_psexecNative.filter(h => h.side === "source" && h.host).map(h => h.host))];
            const allHosts = [...new Set([...destHosts, ...srcHosts])];
            const allTs = _psexecNative.map(h => h.ts).filter(Boolean).sort();
            const details = [...new Set(_psexecNative.map(h => h.d))];
            const eids = [...new Set(_psexecNative.map(h => h.eid))];
            const hostLabel = [];
            if (destHosts.length > 0) hostLabel.push(`target ${destHosts.slice(0, 3).join(", ")}${destHosts.length > 3 ? ` +${destHosts.length - 3} more` : ""}`);
            if (srcHosts.length > 0) hostLabel.push(`observed on ${srcHosts.slice(0, 3).join(", ")}${srcHosts.length > 3 ? ` +${srcHosts.length - 3} more` : ""}`);
            const _psPills = [{ text: "PSEXESVC service", type: "execution" }];
            if (destHosts.length > 0) _psPills.push({ text: `target ${destHosts.slice(0, 2).join(", ")}`, type: "target" });
            if (srcHosts.length > 0) _psPills.push({ text: `from ${srcHosts.slice(0, 2).join(", ")}`, type: "context" });
            findings.push({ id: fid++, severity: "critical", category: "PsExec Native", mitre: "T1569.002",
              title: `Sysinternals PsExec detected${hostLabel.length > 0 ? ` (${hostLabel.join("; ")})` : ""}`,
              description: `${_psexecNative.length} event(s): ${details.join("; ")}`,
              source: srcHosts.join(", "), target: destHosts.join(", "),
              filterHosts: allHosts,
              timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
              eventCount: _psexecNative.length, filterEids: eids, evidencePills: _psPills, users: [] });
          } } catch (_e) { warnings.push(`PsExec detector failed: ${_e.message}`); console.error("PsExec detector error:", _e); }

          // --- Emit Impacket findings: per-variant with confidence-scored severity ---
          try { if (_psexecImpacket.length > 0) {
            // Logon correlation: index Type 3 / 4648 logons by host for ±5min matching
            const _logonByHost = new Map();
            for (const evt of timeOrdered) {
              if (evt.eventId !== "4624" && evt.eventId !== "4648") continue;
              const h = (evt.target || "").toUpperCase();
              if (!h) continue;
              if (!_logonByHost.has(h)) _logonByHost.set(h, []);
              _logonByHost.get(h).push(evt);
            }
            const _hasCorrelatedLogon = (host, hitTs) => {
              if (!host || !hitTs) return false;
              const logons = _logonByHost.get(host.toUpperCase());
              if (!logons) return false;
              const tMs = new Date(hitTs.replace("T", " ").replace("Z", "")).getTime();
              if (isNaN(tMs)) return false;
              return logons.some(l => {
                if (l.logonType !== "3" && l.eventId !== "4648") return false;
                const lMs = new Date(l.ts.replace("T", " ").replace("Z", "")).getTime();
                return !isNaN(lMs) && Math.abs(lMs - tMs) <= 300000;
              });
            };

            // Cluster by (variant, targetHost, timeWindow) for per-hop findings
            // Assign target key: dest-side host IS the target; source-side uses remoteTarget if known
            const _parseTs = (s) => { const d = new Date((s || "").replace("T", " ").replace("Z", "")); return isNaN(d) ? 0 : d.getTime(); };
            for (const h of _psexecImpacket) {
              if (h.side === "dest") h._tgtKey = (h.host || "").toUpperCase();
              else h._tgtKey = (h.remoteTarget || "").toUpperCase(); // "" if unknown
            }
            // Group by (variant, targetKey)
            const _byVarTgt = new Map();
            for (const h of _psexecImpacket) {
              const k = `${h.v}\0${h._tgtKey}`;
              if (!_byVarTgt.has(k)) _byVarTgt.set(k, []);
              _byVarTgt.get(k).push(h);
            }
            // Within each group, sort by time and split into sub-clusters (>10 min gap)
            const _impClusters = [];
            for (const hits of _byVarTgt.values()) {
              hits.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
              let cur = [hits[0]];
              for (let i = 1; i < hits.length; i++) {
                const prevMs = _parseTs(cur[cur.length - 1].ts);
                const curMs = _parseTs(hits[i].ts);
                if (prevMs && curMs && curMs - prevMs > 600000) {
                  _impClusters.push(cur);
                  cur = [];
                }
                cur.push(hits[i]);
              }
              if (cur.length > 0) _impClusters.push(cur);
            }

            // Emit one finding per cluster
            for (const cluster of _impClusters) {
              const variant = cluster[0].v;
              const hasStrong = cluster.some(h => h.confidence === "strong");
              const hasMedium = cluster.some(h => h.confidence === "medium");
              const hasCorrelation = cluster.some(h => h.side === "dest" && _hasCorrelatedLogon(h.host, h.ts));
              let severity;
              if (hasStrong) severity = "critical";
              else if (hasMedium && hasCorrelation) severity = "high";
              else severity = "medium";

              const destHosts = [...new Set(cluster.filter(h => h.side === "dest" && h.host).map(h => h.host))];
              const srcHosts = [...new Set(cluster.filter(h => h.side === "source" && h.host).map(h => h.host))];
              const remoteTargets = [...new Set(cluster.map(h => h.remoteTarget).filter(Boolean))];
              const targetHosts = [...new Set([...destHosts, ...remoteTargets])];
              const allHosts = [...new Set([...targetHosts, ...srcHosts])];
              const allTs = cluster.map(h => h.ts).filter(Boolean).sort();
              const evidence = [...new Set(cluster.map(h => `[${h.confidence}] ${h.evidence}`))];
              const eids = [...new Set(cluster.map(h => h.eid))];

              // Build title: "Impacket wmiexec.py: WS01 → DC01" or "Impacket smbexec.py (target DC02)"
              let hopLabel = "";
              if (srcHosts.length > 0 && targetHosts.length > 0) {
                hopLabel = `: ${srcHosts[0]}${srcHosts.length > 1 ? ` +${srcHosts.length - 1}` : ""} \u2192 ${targetHosts[0]}${targetHosts.length > 1 ? ` +${targetHosts.length - 1}` : ""}`;
              } else if (targetHosts.length > 0) {
                hopLabel = ` (target ${targetHosts.slice(0, 3).join(", ")}${targetHosts.length > 3 ? ` +${targetHosts.length - 3} more` : ""})`;
              } else if (srcHosts.length > 0) {
                hopLabel = ` (from ${srcHosts.slice(0, 3).join(", ")}${srcHosts.length > 3 ? ` +${srcHosts.length - 3} more` : ""})`;
              }

              const _impPills = [{ text: `Impacket ${variant}`, type: "execution" }];
              if (hasStrong) _impPills.push({ text: "strong indicator", type: "execution" });
              else if (hasMedium) _impPills.push({ text: "medium indicator", type: "context" });
              if (hasCorrelation) _impPills.push({ text: "logon correlation", type: "correlation" });
              findings.push({ id: fid++, severity, category: "Impacket Execution", mitre: "T1569.002",
                title: `Impacket ${variant}${hopLabel}`,
                description: `${cluster.length} event(s): ${evidence.join("; ")}${hasCorrelation ? " [correlated Type 3 logon]" : ""}`,
                evidence, source: srcHosts.join(", "), target: targetHosts.join(", "),
                filterHosts: allHosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: cluster.length, filterEids: eids, evidencePills: _impPills, users: [] });
            }

            // Summary card when 2+ clusters
            if (_impClusters.length > 1) {
              const allVariants = [...new Set(_psexecImpacket.map(h => h.v))];
              const allHosts = [...new Set(_psexecImpacket.map(h => h.host).filter(Boolean))];
              const allTs = _psexecImpacket.map(h => h.ts).filter(Boolean).sort();
              findings.push({ id: fid++, severity: "low", category: "Impacket Summary", mitre: "T1569.002",
                title: `Impacket activity: ${allVariants.join(", ")} — ${_impClusters.length} clusters across ${allHosts.length} host(s)`,
                description: `${_psexecImpacket.length} total events across ${_impClusters.length} distinct source/target/time clusters. See individual findings.`,
                source: "", target: allHosts.join(", "),
                filterHosts: allHosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: _psexecImpacket.length, filterEids: [...new Set(_psexecImpacket.map(h => h.eid))],
                evidencePills: allVariants.map(v => ({ text: v, type: "execution" })), users: [] });
            }
          }

          // --- Emit Impacket Credential Access findings (secretsdump.py etc.) ---
          if (_impCredAccess.length > 0) {
            const hosts = [...new Set(_impCredAccess.map(h => h.host).filter(Boolean))];
            const allTs = _impCredAccess.map(h => h.ts).filter(Boolean).sort();
            const evidence = [...new Set(_impCredAccess.map(h => h.evidence))];
            const eids = [...new Set(_impCredAccess.map(h => h.eid))];
            findings.push({ id: fid++, severity: "critical", category: "Impacket Credential Access", mitre: "T1003",
              title: `Impacket credential dumping${hosts.length > 0 ? ` (observed on ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ` +${hosts.length - 3} more` : ""})` : ""}`,
              description: `${_impCredAccess.length} event(s): ${evidence.join("; ")}`,
              evidence, source: "", target: hosts.join(", "),
              filterHosts: hosts,
              timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
              eventCount: _impCredAccess.length, filterEids: eids,
              evidencePills: [{ text: "credential dumping", type: "execution" }, ...hosts.slice(0, 2).map(h => ({ text: h, type: "target" }))], users: [] });
          } } catch (_e) { warnings.push(`Impacket detector failed: ${_e.message}`); console.error("Impacket detector error:", _e); }

          // --- Emit Remote Service Execution findings (all destination-side service installs) ---
          try { if (_remoteSvcExec.length > 0) {
            const hosts = [...new Set(_remoteSvcExec.map(h => h.host).filter(Boolean))];
            const allTs = _remoteSvcExec.map(h => h.ts).filter(Boolean).sort();
            const eids = [...new Set(_remoteSvcExec.map(h => h.eid))];
            const _rsPills = [{ text: "suspicious service", type: "execution" }];
            if (hosts.length > 0) _rsPills.push({ text: `target ${hosts.slice(0, 2).join(", ")}`, type: "target" });
            // Group reasons by category for a compact description
            const _rsReasonGroups = new Map(); // category -> [specifics]
            for (const h of _remoteSvcExec) {
              const m = h.d.match(/^Random \d+-char service name: (.+)$/);
              if (m) {
                if (!_rsReasonGroups.has("random_name")) _rsReasonGroups.set("random_name", []);
                _rsReasonGroups.get("random_name").push(m[1]);
              } else {
                if (!_rsReasonGroups.has("other")) _rsReasonGroups.set("other", []);
                _rsReasonGroups.get("other").push(h.d);
              }
            }
            const _rsDescParts = [];
            const _rsRandomNames = _rsReasonGroups.get("random_name");
            if (_rsRandomNames && _rsRandomNames.length > 0) {
              const uniqueNames = [...new Set(_rsRandomNames)];
              _rsDescParts.push(`${uniqueNames.length} random service name${uniqueNames.length > 1 ? "s" : ""}: ${uniqueNames.join(", ")}`);
            }
            const _rsOther = _rsReasonGroups.get("other");
            if (_rsOther && _rsOther.length > 0) {
              _rsDescParts.push(...[...new Set(_rsOther)]);
            }
            findings.push({ id: fid++, severity: "high", category: "Remote Service Execution", mitre: "T1569.002",
              title: `Suspicious service-based execution${hosts.length > 0 ? ` (target ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ` +${hosts.length - 3} more` : ""})` : ""}`,
              description: `${_remoteSvcExec.length} suspicious service event(s). ${_rsDescParts.join("; ")}. Could indicate remote execution tools.`,
              source: "", target: hosts.join(", "),
              filterHosts: hosts,
              timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
              eventCount: _remoteSvcExec.length, filterEids: eids, evidencePills: _rsPills, users: [] });
          } } catch (_e) { warnings.push(`Remote Service detector failed: ${_e.message}`); console.error("Remote Service detector error:", _e); }

          // --- Helper: emit a remote-exec/activity finding from a hit list ---
          const _emitRemoteFinding = (hits, category, mitre, titlePrefix, severity, extraPills) => {
            if (hits.length === 0) return;
            const destHosts = [...new Set(hits.filter(h => h.side === "dest" && h.host).map(h => h.host))];
            const srcHosts = [...new Set(hits.filter(h => h.side === "source" && h.host).map(h => h.host))];
            const remoteTargets = [...new Set(hits.map(h => h.remoteTarget).filter(Boolean))];
            const targetHosts = [...new Set([...destHosts, ...remoteTargets])];
            const allHosts = [...new Set([...targetHosts, ...srcHosts])];
            const allTs = hits.map(h => h.ts).filter(Boolean).sort();
            const details = [...new Set(hits.map(h => h.d))];
            const eids = [...new Set(hits.map(h => h.eid))];
            const hostLabel = [];
            if (targetHosts.length > 0) hostLabel.push(`target ${targetHosts.slice(0, 3).join(", ")}${targetHosts.length > 3 ? ` +${targetHosts.length - 3} more` : ""}`);
            if (srcHosts.length > 0) hostLabel.push(`from ${srcHosts.slice(0, 3).join(", ")}${srcHosts.length > 3 ? ` +${srcHosts.length - 3} more` : ""}`);
            const _rfPills = [...(extraPills || [])];
            if (destHosts.length > 0) _rfPills.push({ text: "dest-side", type: "context" });
            if (srcHosts.length > 0) _rfPills.push({ text: "source-side", type: "context" });
            if (targetHosts.some(h => _DC_PAT.test(h))) _rfPills.push({ text: "DC target", type: "target" });
            else if (targetHosts.some(h => _SRV_PAT.test(h))) _rfPills.push({ text: "server target", type: "target" });
            findings.push({ id: fid++, severity, category, mitre,
              title: `${titlePrefix}${hostLabel.length > 0 ? ` (${hostLabel.join("; ")})` : ""}`,
              description: `${hits.length} event(s): ${details.join("; ")}`,
              source: srcHosts.join(", "), target: targetHosts.join(", "),
              filterHosts: allHosts,
              timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
              eventCount: hits.length, filterEids: eids, evidencePills: _rfPills, users: [] });
          };

          // --- Emit WMI/WinRM findings ---
          try {
          if (_wmiHits.length > 0) {
            const wmiExec = _wmiHits.filter(h => h.exec);
            const wmiActivity = _wmiHits.filter(h => !h.exec);
            const wmiExecHasDirectional = wmiExec.some(h => h.side === "dest" && !h._blob);
            const wmiExecHasBlobOnly = !wmiExecHasDirectional && wmiExec.some(h => h.side === "dest" && h._blob);
            const wmiSev = wmiExecHasDirectional ? "high" : wmiExecHasBlobOnly ? "medium" : "medium";
            const wmiPills = [{ text: "WMI execution", type: "execution" }];
            if (wmiExecHasBlobOnly) wmiPills.push({ text: "blob match (lower confidence)", type: "context" });
            if (wmiExec.length > 0) _emitRemoteFinding(wmiExec, "WMI Remote Execution", "T1047", "WMI remote execution", wmiSev, wmiPills);
            if (wmiActivity.length > 0) _emitRemoteFinding(wmiActivity, "WMI Remote Activity", "T1047", "WMI remote activity", "low", [{ text: "WMI activity", type: "context" }]);
          }
          if (_winrmHits.length > 0) {
            const winrmExec = _winrmHits.filter(h => h.exec);
            const winrmActivity = _winrmHits.filter(h => !h.exec);
            const winrmExecHasDirectional = winrmExec.some(h => h.side === "dest" && h.hasChild && !h._blob);
            const winrmExecHasBlobOnly = !winrmExecHasDirectional && winrmExec.some(h => h.side === "dest" && h._blob);
            const winrmSev = winrmExecHasDirectional ? "high" : winrmExecHasBlobOnly ? "medium" : "medium";
            const winrmPills = [{ text: "WinRM execution", type: "execution" }];
            if (winrmExecHasBlobOnly) winrmPills.push({ text: "blob match (lower confidence)", type: "context" });
            if (winrmExec.length > 0) _emitRemoteFinding(winrmExec, "WinRM Remote Execution", "T1021.006", "WinRM remote execution", winrmSev, winrmPills);
            if (winrmActivity.length > 0) _emitRemoteFinding(winrmActivity, "WinRM Remote Activity", "T1021.006", "WinRM remote activity", "low", [{ text: "WinRM activity", type: "context" }]);
          }
          } catch (_e) { warnings.push(`WMI/WinRM detector failed: ${_e.message}`); console.error("WMI/WinRM detector error:", _e); }

          // --- Emit RMM findings (clustered per tool+host, scored by context) ---
          try {
          if (_rmmHits.length > 0 && !_disabledSet.has("rmm")) {
            // Cluster by tool+host, then by 30-min time windows
            const _rmmClusters = new Map(); // "tool::HOST" -> [{hit, ...}, ...]
            for (const h of _rmmHits) {
              const key = `${h.tool}::${(h.host || "UNKNOWN").toUpperCase()}`;
              if (!_rmmClusters.has(key)) _rmmClusters.set(key, []);
              _rmmClusters.get(key).push(h);
            }
            for (const [clusterKey, hits] of _rmmClusters) {
              // Sort by timestamp within cluster
              hits.sort((a, b) => (a.ts || "") > (b.ts || "") ? 1 : -1);
              // Sub-cluster by 30-min time gaps
              const windows = [];
              let win = [hits[0]];
              for (let i = 1; i < hits.length; i++) {
                const prev = win[win.length - 1];
                const gap = prev.ts && hits[i].ts ? (new Date(hits[i].ts) - new Date(prev.ts)) / 60000 : 0;
                if (gap > 30) { windows.push(win); win = [hits[i]]; }
                else win.push(hits[i]);
              }
              windows.push(win);

              for (const winHits of windows) {
                const tool = winHits[0].tool;
                const toolType = winHits[0].toolType;
                const host = winHits[0].host.toUpperCase() || "UNKNOWN";

                // Determine kind hierarchy: process/cmdline > install/service > presence
                const hasProcess = winHits.some(h => h.kind === "process" || h.kind === "cmdline");
                const hasInstall = winHits.some(h => h.kind === "install" || h.kind === "service");

                // Context scoring
                const pills = [];
                let severity = "low";
                const reasons = [];

                // Unusual parent detection
                const susParentHits = winHits.filter(h => h.parent && _rmmSusParents.has(h.parent));
                const hasSusParent = susParentHits.length > 0;
                if (hasSusParent) {
                  const pNames = [...new Set(susParentHits.map(h => h.parent))];
                  pills.push({ text: `unusual parent: ${pNames.join(", ")}`, type: "execution" });
                  reasons.push("unusual parent");
                }

                // Suspicious path detection
                const susPathHits = winHits.filter(h => h.imagePath && _rmmSusPaths.test(h.imagePath));
                if (susPathHits.length > 0) {
                  pills.push({ text: "user-writable/temp path", type: "execution" });
                  reasons.push("suspicious path");
                }

                // DC/server target
                const isDC = _DC_PAT.test(host);
                const isSrv = !isDC && _SRV_PAT.test(host);
                if (isDC) { pills.push({ text: "DC target", type: "target" }); reasons.push("DC target"); }
                else if (isSrv) { pills.push({ text: "server target", type: "target" }); reasons.push("server target"); }

                // Outlier source — this host is unusual
                if (_outlierHosts.has(host)) { pills.push({ text: "outlier host", type: "correlation" }); reasons.push("outlier"); }

                // First-seen check — host never appeared in logon graph
                if (host !== "UNKNOWN" && !hostSet.has(host)) { pills.push({ text: "first-seen host", type: "correlation" }); reasons.push("first-seen"); }

                // Compute severity based on context
                if (toolType === "tunnel") {
                  // Tunnels: always medium for execution, low for install-only
                  severity = hasProcess ? "medium" : "low";
                  if (hasSusParent || susPathHits.length > 0) severity = "high";
                } else {
                  // RMM tools
                  if (hasSusParent || susPathHits.length > 0) {
                    severity = "high"; // suspicious execution context
                  } else if (hasProcess) {
                    severity = "medium"; // executed, but normal parent
                  } else if (hasInstall && (isDC || isSrv)) {
                    severity = "medium"; // installed on high-value target
                  } else {
                    severity = "low"; // installed/present only
                  }
                  // Boost: overlap with credential abuse or admin share on same host
                  const hasOverlap = findings.some(f => {
                    if (f.category !== "Credential Compromise" && f.category !== "Admin Share Access") return false;
                    const fTargets = (f.target || "").split(", ").map(t => t.trim().toUpperCase()).filter(Boolean);
                    return fTargets.includes(host);
                  });
                  if (hasOverlap && severity !== "high") {
                    severity = severity === "low" ? "medium" : "high";
                    pills.push({ text: "overlaps credential/share activity", type: "correlation" });
                  }
                }

                // Dampener: all hits have normal enterprise parents and no other suspicious context
                const allNormalParent = winHits.every(h => !h.parent || _rmmNormalParents.has(h.parent));
                if (allNormalParent && !hasSusParent && susPathHits.length === 0 && reasons.length === 0 && severity === "low") {
                  pills.push({ text: "expected enterprise pattern", type: "context" });
                }

                // Build category and title
                let category, title, desc;
                if (toolType === "tunnel") {
                  category = "Remote Access Tunnel";
                  title = `Remote tunnel: ${tool} on ${host}`;
                  desc = hasProcess ? `${tool} executed on ${host}` : `${tool} service installed on ${host}`;
                } else if (hasSusParent || susPathHits.length > 0) {
                  category = "RMM Suspicious Execution";
                  title = `Suspicious RMM execution: ${tool} on ${host}`;
                  desc = `${tool} launched${hasSusParent ? ` from ${[...new Set(susParentHits.map(h => h.parent))].join("/")}` : ""}${susPathHits.length > 0 ? " from user-writable path" : ""}`;
                } else if (hasProcess) {
                  category = "RMM Executed";
                  title = `RMM tool executed: ${tool} on ${host}`;
                  desc = `${tool} process execution detected on ${host}`;
                } else {
                  category = "RMM Installed";
                  title = `RMM tool installed: ${tool} on ${host}`;
                  desc = `${tool} service installation detected on ${host}`;
                }

                // Add kind/count pills
                pills.unshift({ text: tool, type: toolType === "tunnel" ? "context" : "execution" });
                const kindCounts = {};
                for (const h of winHits) kindCounts[h.kind] = (kindCounts[h.kind] || 0) + 1;
                for (const [k, c] of Object.entries(kindCounts)) {
                  pills.push({ text: `${c} ${k} event${c > 1 ? "s" : ""}`, type: "context" });
                }

                const eids = [...new Set(winHits.map(h => h.eid))].sort();
                const allTs = winHits.map(h => h.ts).filter(Boolean).sort();
                desc += `. ${winHits.length} event(s)${eids.length > 0 ? ` (EID ${eids.join(", ")})` : ""}`;

                // In suspicious-only mode, skip low/medium findings (RMM Installed, RMM Executed, tunnels without suspicious context)
                if (rmmMode === "suspicious" && category !== "RMM Suspicious Execution") continue;

                findings.push({
                  id: fid++, severity, category, mitre: "T1219",
                  title, description: desc,
                  source: "", target: host,
                  filterHosts: [host],
                  timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                  eventCount: winHits.length, filterEids: eids.length > 0 ? eids : null,
                  evidencePills: pills, users: [],
                });
              }
            }
          }
          } catch (_e) { warnings.push(`RMM detector failed: ${_e.message}`); console.error("RMM detector error:", _e); }

          // --- Emit Scheduled Task Remote Execution findings ---
          try { if (_schedTaskHits.length > 0 && !_disabledSet.has("schtask")) {
            const _logonByHostST = new Map();
            for (const evt of timeOrdered) {
              if (evt.eventId !== "4624" && evt.eventId !== "4648") continue;
              const h = (evt.target || "").toUpperCase();
              if (!h) continue;
              if (!_logonByHostST.has(h)) _logonByHostST.set(h, []);
              _logonByHostST.get(h).push(evt);
            }
            const _stHasLogon = (host, hitTs) => {
              if (!host || !hitTs) return null;
              const logons = _logonByHostST.get(host.toUpperCase());
              if (!logons) return null;
              const tMs = new Date(hitTs).getTime();
              if (isNaN(tMs)) return null;
              for (const l of logons) {
                if (l.logonType !== "3" && l.eventId !== "4648") continue;
                const lMs = new Date(l.ts).getTime();
                if (!isNaN(lMs) && Math.abs(lMs - tMs) <= 600000) {
                  return { source: l.source, user: l.user, eventId: l.eventId, logonType: l.logonType };
                }
              }
              return null;
            };
            _schedTaskHits.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
            const _stClusters = [];
            let _stCur = [_schedTaskHits[0]];
            for (let si = 1; si < _schedTaskHits.length; si++) {
              const prevMs = new Date(_stCur[_stCur.length - 1].ts).getTime();
              const curMs = new Date(_schedTaskHits[si].ts).getTime();
              const sameTarget = (_schedTaskHits[si].host || "").toUpperCase() === (_stCur[0].host || "").toUpperCase();
              if (sameTarget && !isNaN(prevMs) && !isNaN(curMs) && curMs - prevMs <= 600000) {
                _stCur.push(_schedTaskHits[si]);
              } else {
                _stClusters.push(_stCur);
                _stCur = [_schedTaskHits[si]];
              }
            }
            if (_stCur.length > 0) _stClusters.push(_stCur);

            for (const cluster of _stClusters) {
              const destHits = cluster.filter(h => h.side === "dest");
              const srcHits = cluster.filter(h => h.side === "source");
              const destHosts = [...new Set(destHits.map(h => h.host).filter(Boolean))];
              const srcHosts = [...new Set(srcHits.map(h => h.host).filter(Boolean))];
              const remoteTargets = [...new Set(srcHits.map(h => h.remoteTarget).filter(Boolean))];
              const targetHosts = [...new Set([...destHosts, ...remoteTargets])];
              const allHosts = [...new Set([...targetHosts, ...srcHosts])];
              const allTs = cluster.map(h => h.ts).filter(Boolean).sort();
              const details = [...new Set(cluster.map(h => h.d))];
              const taskNames = [...new Set(cluster.map(h => h.taskName).filter(Boolean))];
              let correlatedLogon = null;
              for (const dh of destHosts) {
                const match = _stHasLogon(dh, cluster[0].ts);
                if (match) { correlatedLogon = match; break; }
              }
              if (!correlatedLogon) {
                for (const rt of remoteTargets) {
                  const match = _stHasLogon(rt, cluster[0].ts);
                  if (match) { correlatedLogon = match; break; }
                }
              }
              if (correlatedLogon && correlatedLogon.source && !srcHosts.includes(correlatedLogon.source)) {
                srcHosts.push(correlatedLogon.source);
                allHosts.push(correlatedLogon.source);
              }
              const hasSuspAction = destHits.length > 0;
              const hasSrcCmd = srcHits.length > 0 && remoteTargets.length > 0;
              const hasCorrelation = !!correlatedLogon;
              let severity;
              if (hasSuspAction && (hasSrcCmd || hasCorrelation)) severity = "critical";
              else if (hasSuspAction) severity = "high";
              else if (hasSrcCmd && hasCorrelation) severity = "high";
              else if (hasSrcCmd) severity = "medium";
              else severity = "medium";
              const hostLabel = [];
              if (targetHosts.length > 0) hostLabel.push(`target ${targetHosts.slice(0, 3).join(", ")}${targetHosts.length > 3 ? ` +${targetHosts.length - 3} more` : ""}`);
              if (srcHosts.length > 0) hostLabel.push(`from ${srcHosts.slice(0, 3).join(", ")}${srcHosts.length > 3 ? ` +${srcHosts.length - 3} more` : ""}`);
              const corrDesc = correlatedLogon ? ` Correlated: ${correlatedLogon.eventId === "4648" ? "explicit creds" : "Type 3 logon"} from ${correlatedLogon.source || "?"} (${correlatedLogon.user || "?"}).` : "";
              const _stPills = [];
              if (hasSuspAction) _stPills.push({ text: "dest-side execution", type: "execution" });
              if (hasSrcCmd) _stPills.push({ text: "source-side schtasks", type: "execution" });
              if (hasCorrelation) _stPills.push({ text: "correlated logon", type: "correlation" });
              if (targetHosts.some(h => _DC_PAT.test(h))) _stPills.push({ text: "DC target", type: "target" });
              else if (targetHosts.some(h => _SRV_PAT.test(h))) _stPills.push({ text: "server target", type: "target" });
              findings.push({ id: fid++, severity, category: "Scheduled Task Remote Execution", mitre: "T1053.005",
                title: `Scheduled task remote execution${hostLabel.length > 0 ? ` (${hostLabel.join("; ")})` : ""}`,
                description: `${cluster.length} event(s): ${details.join("; ")}${taskNames.length > 0 ? ` Tasks: ${taskNames.join(", ")}` : ""}${corrDesc}`,
                source: srcHosts.join(", "), target: targetHosts.join(", "),
                filterHosts: allHosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: cluster.length, filterEids: ["4698"], evidencePills: _stPills, users: correlatedLogon?.user ? [correlatedLogon.user.toUpperCase()] : [] });
            }
          } } catch (_e) { warnings.push(`Scheduled Task detector failed: ${_e.message}`); console.error("Scheduled Task detector error:", _e); }
      }

      // === Admin Share Access (T1021.002) ===
      // Detect ADMIN$, C$, [A-Z]$ access from 5140/5145 events in timeOrdered
      const _adminShareHits = []; // {source, target, user, ts, shareName, shareType}
      const _ADMIN_SHARE_PAT = /^(ADMIN\$|C\$|[A-Z]\$)$/i;
      const _IPC_PAT = /^IPC\$$/i;
      for (const evt of timeOrdered) {
        if (evt.eventId !== "5140" && evt.eventId !== "5145") continue;
        if (!evt.shareName) continue;
        const sn = evt.shareName.replace(/^\\\\\*\\/, "").toUpperCase();
        if (_ADMIN_SHARE_PAT.test(sn)) {
          _adminShareHits.push({ source: evt.source, target: evt.target, user: evt.user, ts: evt.ts, shareName: sn, shareType: "admin" });
        } else if (_IPC_PAT.test(sn)) {
          _adminShareHits.push({ source: evt.source, target: evt.target, user: evt.user, ts: evt.ts, shareName: sn, shareType: "ipc" });
        }
      }
      if (_adminShareHits.length > 0) {
        // Cluster by source->target pair, 10-min window
        _adminShareHits.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
        const _asClusters = [];
        const _asGrouped = new Map(); // "src->tgt" => [hits]
        for (const h of _adminShareHits) {
          const gk = `${h.source}->${h.target}`;
          if (!_asGrouped.has(gk)) _asGrouped.set(gk, []);
          _asGrouped.get(gk).push(h);
        }
        for (const [, hits] of _asGrouped) {
          // Sub-cluster within each pair by 10-min gap
          hits.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
          let cur = [hits[0]];
          for (let hi = 1; hi < hits.length; hi++) {
            const prevMs = new Date(cur[cur.length - 1].ts).getTime();
            const curMs = new Date(hits[hi].ts).getTime();
            if (!isNaN(prevMs) && !isNaN(curMs) && curMs - prevMs <= 600000) {
              cur.push(hits[hi]);
            } else {
              _asClusters.push(cur);
              cur = [hits[hi]];
            }
          }
          if (cur.length > 0) _asClusters.push(cur);
        }
        // FP controls
        const _asMgmtSrcPat = /^(JUMP|JMP|PAM|BASTION|MGMT|MANAGE|SCCM|SCOM|WSUS|ANSIBLE|PUPPET|CHEF|SALT|ORCH)[\-_]|^ADMIN[\-_](JUMP|BASTION|PAM|MGMT|SRV|SERVER)/i;
        const _asSvcPat = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP)/i;
        for (const cluster of _asClusters) {
          const shares = [...new Set(cluster.map(h => h.shareName))];
          const hasAdmin = shares.some(s => /^(ADMIN\$|C\$|[A-Z]\$)$/i.test(s) && !/^IPC\$/i.test(s));
          const onlyIpc = shares.every(s => /^IPC\$/i.test(s));
          const sources = [...new Set(cluster.map(h => h.source).filter(Boolean))];
          const targets = [...new Set(cluster.map(h => h.target).filter(Boolean))];
          const users = [...new Set(cluster.map(h => h.user).filter(Boolean))];
          const allTs = cluster.map(h => h.ts).filter(Boolean).sort();
          const allHosts = [...new Set([...sources, ...targets])];
          // FP: skip if all users are service accounts and source is management host
          const allSvc = users.length > 0 && users.every(u => _asSvcPat.test(u) || u.endsWith("$"));
          const allMgmt = sources.length > 0 && sources.every(s => _asMgmtSrcPat.test(s));
          if (allSvc && allMgmt) continue;
          // IPC$-only: only flag if correlated with PsExec/Impacket findings on same pair
          if (onlyIpc) {
            // Check if there's a PsExec/Impacket finding overlapping this pair
            let hasToolCorrelation = false;
            for (const f of findings) {
              if (f.category !== "PsExec Native" && f.category !== "Impacket Execution" && f.category !== "Impacket Summary") continue;
              const fTargets = (f.target || "").split(", ");
              const fSources = (f.source || "").split(", ");
              if (targets.some(t => fTargets.includes(t)) && (sources.some(s => fSources.includes(s)) || !f.source)) {
                hasToolCorrelation = true; break;
              }
            }
            if (!hasToolCorrelation) continue; // skip bare IPC$ without tool correlation
          }
          // Severity tiers:
          //   critical: ADMIN$/C$ + correlated PsExec/Impacket finding on same pair
          //   high:     ADMIN$/C$ access (strong lateral movement indicator)
          //   medium:   IPC$ with PsExec/Impacket correlation (passed filter above)
          let severity;
          let hasToolCorrelation = false;
          for (const f of findings) {
            if (f.category !== "PsExec Native" && f.category !== "Impacket Execution" && f.category !== "Impacket Summary" && f.category !== "Remote Service Execution") continue;
            const fTargets = (f.target || "").split(", ");
            const fSources = (f.source || "").split(", ");
            // Require same source->target pair (or source-less finding matching target)
            if (targets.some(t => fTargets.includes(t)) && (sources.some(s => fSources.includes(s)) || !f.source)) { hasToolCorrelation = true; break; }
          }
          if (hasAdmin && hasToolCorrelation) severity = "critical";
          else if (hasAdmin) severity = "high";
          else severity = "medium"; // IPC$ with tool correlation
          // Dampener: management source reduces severity by one tier
          if (allMgmt && severity === "critical") severity = "high";
          else if (allMgmt && severity === "high") severity = "medium";
          const hostLabel = [];
          if (targets.length > 0) hostLabel.push(`target ${targets.slice(0, 3).join(", ")}${targets.length > 3 ? ` +${targets.length - 3} more` : ""}`);
          if (sources.length > 0) hostLabel.push(`from ${sources.slice(0, 3).join(", ")}${sources.length > 3 ? ` +${sources.length - 3} more` : ""}`);
          const corrLabel = hasToolCorrelation ? " Correlated with execution tool finding." : "";
          const _asPills = shares.map(s => ({ text: `${s} access`, type: hasAdmin && !/^IPC\$/i.test(s) ? "execution" : "context" }));
          if (hasToolCorrelation) _asPills.push({ text: "tool correlation", type: "correlation" });
          if (sources.some(s => _outlierHosts.has(s))) _asPills.push({ text: "outlier source", type: "context" });
          findings.push({ id: fid++, severity, category: "Admin Share Access", mitre: "T1021.002",
            title: `Admin share access: ${shares.join(", ")}${hostLabel.length > 0 ? ` (${hostLabel.join("; ")})` : ""}`,
            description: `${cluster.length} share access event(s) (${shares.join(", ")}) by ${users.join(", ") || "(unknown)"}.${corrLabel}`,
            source: sources.join(", "), target: targets.join(", "),
            filterHosts: allHosts,
            timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
            eventCount: cluster.length, filterEids: ["5140", "5145"], evidencePills: _asPills, users: users.map(u => u.toUpperCase()) });
        }
      }

      // Lateral Pivot findings deferred until after chain confidence scoring (below)

      // First Seen (T1021) — contextual signal, not standalone alert
      // Only emit a finding when the new pair has a corroborating suspicious signal:
      // outlier source, DC/server target, chain membership, admin share access, or tool-backed findings
      for (const edge of edgeMap.values()) {
        if (!edge.isFirstSeen) continue;
        const _fsOutlier = edge.source && _outlierHosts.has(edge.source);
        const _fsDC = edge.target && _DC_PAT.test(edge.target);
        const _fsSrv = edge.target && _SRV_PAT.test(edge.target);
        const _fsChain = chains.some(c => { for (let ci = 0; ci < c.path.length - 1; ci++) { if (c.path[ci] === edge.source && c.path[ci + 1] === edge.target) return true; } return false; });
        const _fsHasAdminShare = edge._adminShareCount > 0;
        const _fsToolCats = new Set(["PsExec Native", "Impacket Execution", "Impacket Credential Access", "Remote Service Execution", "WMI Remote Execution", "WinRM Remote Execution", "Scheduled Task Remote Execution", "Admin Share Access", "RMM Suspicious Execution", "RMM Executed"]);
        const _fsTool = findings.some(f => {
          if (!_fsToolCats.has(f.category)) return false;
          const ft = (f.target || "").split(", ");
          const fs = (f.source || "").split(", ");
          return ft.includes(edge.target) && fs.includes(edge.source);
        });
        if (!_fsOutlier && !_fsDC && !_fsSrv && !_fsChain && !_fsHasAdminShare && !_fsTool) continue;
        const _fsPills = [{ text: "new connection pair", type: "context" }];
        if (_fsOutlier) _fsPills.push({ text: "outlier source", type: "context" });
        if (_fsDC) _fsPills.push({ text: "DC target", type: "target" });
        else if (_fsSrv) _fsPills.push({ text: "server target", type: "target" });
        if (_fsChain) _fsPills.push({ text: "in lateral chain", type: "correlation" });
        if (_fsHasAdminShare) _fsPills.push({ text: "admin share access", type: "execution" });
        if (_fsTool) _fsPills.push({ text: "tool-backed", type: "correlation" });
        findings.push({ id: fid++, severity: "low", category: "First Seen", mitre: "T1021", title: `New connection: ${edge.source} \u2192 ${edge.target}`, description: `First observed connection at ${(edge.firstSeen || "").slice(0, 19)}`, source: edge.source, target: edge.target, timeRange: { from: edge.firstSeen, to: edge.firstSeen }, eventCount: 1, evidencePills: _fsPills, users: [...(edge.users || [])] });
      }

      // Credential Compromise severity boost: promote high→critical if post-success tool activity on same pair
      // Requires pair-specific match: both source AND target must match (no source-less fallback)
      const _ccBoostCats = new Set(["PsExec Native", "Impacket Execution", "Admin Share Access", "WMI Remote Execution", "WinRM Remote Execution", "Scheduled Task Remote Execution", "Concurrent RDP Sessions"]);
      for (const f of findings) {
        if (f.category !== "Credential Compromise" || f.severity !== "high") continue;
        const pair = f._ccPair; // "source->target"
        if (!pair) continue;
        const [cs, ct] = pair.split("->");
        const hasToolActivity = findings.some(of => {
          if (!_ccBoostCats.has(of.category)) return false;
          if (!of.source) return false; // require explicit source on the corroborating finding
          const ofTargets = (of.target || "").split(", ");
          const ofSources = (of.source || "").split(", ");
          return ofTargets.includes(ct) && ofSources.includes(cs);
        });
        if (hasToolActivity) {
          f.severity = "critical";
          f.description += ". Post-success tool activity detected on same pair";
          if (!f.evidencePills) f.evidencePills = [];
          f.evidencePills.push({ text: "post-success tool activity", type: "correlation" });
        }
      }

      // === _findingPairs: index findings by source->target pair ===
      const _findingPairs = new Map();
      for (const f of findings) {
        if (!f.source) continue;
        const targets = (f.target || "").split(", ").filter(Boolean);
        for (const t of targets) {
          const pk = `${(f.source || "").toUpperCase()}->${t.toUpperCase()}`;
          if (!_findingPairs.has(pk)) _findingPairs.set(pk, []);
          _findingPairs.get(pk).push(f.id);
        }
      }

      // === Related findings: other findings on same source->target pair ===
      for (const f of findings) {
        const related = new Set();
        const fTargets = (f.target || "").split(", ").filter(Boolean);
        for (const t of fTargets) {
          const pk = `${(f.source || "").toUpperCase()}->${t.toUpperCase()}`;
          for (const pid of (_findingPairs.get(pk) || [])) { if (pid !== f.id) related.add(pid); }
        }
        f.relatedFindingIds = [...related];
      }

      // === Chain edges set (for triage scoring + edge scoring) ===
      const _chainEdges = new Set();
      for (const chain of chains) {
        for (let ci = 0; ci < chain.path.length - 1; ci++) _chainEdges.add(`${chain.path[ci]}->${chain.path[ci + 1]}`);
      }

      // === Triage priority score ===
      const _sevBase = { critical: 40, high: 25, medium: 12, low: 3 };
      const _dsEnd = timeOrdered.length > 0 ? new Date(timeOrdered[timeOrdered.length - 1].ts) : null;
      for (const f of findings) {
        let ts = _sevBase[f.severity] || 0;
        // DC / server target bonus
        const fTargets = (f.target || "").split(", ").filter(Boolean);
        if (fTargets.some(t => _DC_PAT.test(t))) ts += 15;
        else if (fTargets.some(t => _SRV_PAT.test(t))) ts += 10;
        // Tool overlap on same pair
        if (f.relatedFindingIds.length > 0) ts += 10;
        // Concurrent RDP on same pair
        if (f.category === "Concurrent RDP Sessions") ts += 8;
        // Chain membership
        if (f.source && fTargets.some(t => _chainEdges.has(`${f.source}->${t}`))) ts += 5;
        // Outlier source
        if (f.source && _outlierHosts.has(f.source)) ts += 5;
        // Recency: last event within 1 hour of dataset end
        if (_dsEnd && f.timeRange && f.timeRange.to) {
          const fEnd = new Date(f.timeRange.to);
          if (!isNaN(fEnd) && (_dsEnd - fEnd) <= 3600000) ts += 5;
        }
        // Multiple hosts involved
        if (fTargets.length > 1 || ((f.source || "").split(", ").filter(Boolean).length > 1)) ts += 3;
        f.triageScore = ts;
      }

      // Sort by triage score descending, severity as tiebreaker
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      findings.sort((a, b) => (b.triageScore - a.triageScore) || ((sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)));

      // === Incident Clustering ===
      // Group pair-specific findings by normalized SOURCE->TARGET pair, merge within 30-min gaps, 2+ = incident.
      // Multi-target findings (comma-separated targets) are source-centric — they only join a pair's
      // incident when corroborated by a pair-specific finding already in that bucket.
      const _incByPair = new Map();
      const _multiTargetFindings = []; // deferred — join only if corroborated
      for (const f of findings) {
        if (!f.source) continue;
        const fTargets = (f.target || "").split(", ").filter(Boolean);
        if (fTargets.length <= 1) {
          // Single-target finding: direct pair assignment
          const pk = `${(f.source || "").toUpperCase()}->${(fTargets[0] || "").toUpperCase()}`;
          if (!_incByPair.has(pk)) _incByPair.set(pk, []);
          _incByPair.get(pk).push(f);
        } else {
          _multiTargetFindings.push(f);
        }
      }
      // Multi-target findings: only join a pair bucket if that bucket already has a pair-specific finding
      for (const f of _multiTargetFindings) {
        const fTargets = (f.target || "").split(", ").filter(Boolean);
        for (const t of fTargets) {
          const pk = `${(f.source || "").toUpperCase()}->${t.toUpperCase()}`;
          if (_incByPair.has(pk) && _incByPair.get(pk).length > 0) {
            _incByPair.get(pk).push(f);
          }
        }
      }
      const incidents = [];
      let _incId = 0;
      const _incUsedFids = new Set(); // prevent same finding appearing in multiple incidents
      for (const [pk, pFindings] of _incByPair) {
        if (pFindings.length < 2) continue;
        // Sort by timeRange.from
        pFindings.sort((a, b) => ((a.timeRange?.from) || "").localeCompare((b.timeRange?.from) || ""));
        // Merge within 30-min gaps
        const clusters = [];
        let cur = [pFindings[0]];
        for (let i = 1; i < pFindings.length; i++) {
          const prevEnd = new Date(cur[cur.length - 1].timeRange?.to || "");
          const nextStart = new Date(pFindings[i].timeRange?.from || "");
          if (!isNaN(prevEnd) && !isNaN(nextStart) && (nextStart - prevEnd) <= 1800000) {
            cur.push(pFindings[i]);
          } else {
            clusters.push(cur);
            cur = [pFindings[i]];
          }
        }
        clusters.push(cur);
        for (const cl of clusters) {
          if (cl.length < 2) continue;
          // Deduplicate: skip multi-target findings already claimed by a higher-scoring incident
          const dedupedCl = cl.filter(f => !_incUsedFids.has(f.id));
          if (dedupedCl.length < 2) continue;
          const [src, tgt] = pk.split("->");
          const memberIds = [...new Set(dedupedCl.map(f => f.id))];
          for (const mid of memberIds) _incUsedFids.add(mid);
          const allCategories = [...new Set(dedupedCl.map(f => f.category))];
          const allUsers = [...new Set(dedupedCl.flatMap(f => f.users || []))];
          const allTechniques = [...new Set(dedupedCl.map(f => f.mitre))];
          const incSeverity = dedupedCl.reduce((best, f) => (sevOrder[f.severity] ?? 4) < (sevOrder[best] ?? 4) ? f.severity : best, "low");
          const incTriageScore = Math.max(...dedupedCl.map(f => f.triageScore || 0)) + 5;
          const allTs = dedupedCl.flatMap(f => [f.timeRange?.from, f.timeRange?.to]).filter(Boolean).sort();
          const totalEvents = dedupedCl.reduce((s, f) => s + (f.eventCount || 0), 0);
          // Auto-generate narrative
          const chain = allCategories.join(" \u2192 ");
          let narrative = `${allCategories.length} related detections on ${src} \u2192 ${tgt}`;
          if (allUsers.length > 0) narrative += ` involving ${allUsers.slice(0, 3).join(", ")}`;
          narrative += `: ${chain}.`;
          if (allCategories.includes("Credential Compromise") && allCategories.some(c => c.includes("PsExec") || c.includes("Impacket") || c.includes("Admin Share"))) {
            narrative += " Credential compromise followed by execution tools — likely active intrusion.";
          }
          incidents.push({
            id: _incId++, severity: incSeverity, triageScore: incTriageScore,
            category: chain, findings: memberIds,
            source: src, target: tgt,
            users: allUsers, techniques: allTechniques,
            timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
            eventCount: totalEvents, narrative,
          });
        }
      }
      incidents.sort((a, b) => (b.triageScore - a.triageScore) || ((sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)));

      // === Edge Risk Scoring ===
      // Dampener patterns: known management/jump hosts, service accounts, high-frequency routine edges
      const _MGMT_SRC_PAT = /^(JUMP|JMP|PAM|BASTION|MGMT|MANAGE|SCCM|SCOM|WSUS|MONITOR|NAGIOS|ZABBIX|ANSIBLE|PUPPET|CHEF|SALT|ORCH)[\-_]|^ADMIN[\-_](JUMP|BASTION|PAM|MGMT|SRV|SERVER)/i;
      const _SVC_ACCT_PAT = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP|TASK[_\-]|SCH[_\-]|SA[_\-])/i;
      // Compute edge frequency percentile for recurring-edge dampener
      const _edgeCounts = [...edgeMap.values()].map(e => e.count).sort((a, b) => a - b);
      const _p90Count = _edgeCounts.length > 0 ? _edgeCounts[Math.floor(_edgeCounts.length * 0.9)] : Infinity;

      for (const edge of edgeMap.values()) {
        let score = 0;
        const eFlags = [];
        const ek = `${edge.source}->${edge.target}`;
        // Positive signals
        if (edge.source && detectOutlier(edge.source)) { score += 20; eFlags.push("Outlier source"); }
        if (edge.target && _DC_PAT.test(edge.target)) { score += 15; eFlags.push("Target is DC"); }
        else if (edge.target && _SRV_PAT.test(edge.target)) { score += 8; eFlags.push("Target is server"); }
        if (edge.logonTypes.has("8")) { score += 15; eFlags.push("Cleartext auth (Type 8)"); }
        if (edge.hasFailures) { score += 8; eFlags.push("Failed logons"); }
        if (edge.users.size > 1) { score += 5; eFlags.push(`${edge.users.size} users`); }
        if (edge.isFirstSeen) { score += 8; eFlags.push("First-seen pair"); }
        if (_chainEdges.has(ek)) { score += 10; eFlags.push("In lateral chain"); }
        const _efk = `${(edge.source || "").toUpperCase()}->${(edge.target || "").toUpperCase()}`;
        const eFids = _findingPairs.get(_efk) || [];
        if (eFids.length > 0) {
          score += 12;
          const eCats = [...new Set(eFids.map(fid => findings.find(f => f.id === fid)?.category).filter(Boolean))];
          eFlags.push(...eCats.map(c => `Finding: ${c}`));
        }
        if (edge._adminShareCount > 0) { score += 12; eFlags.push(`Admin share access (${edge._adminShareCount}x)`); }
        if (edge.sourceLabel === "unresolved") { score += 3; eFlags.push("Unresolved source"); }
        // Dampeners — reduce score for known benign patterns
        if (edge.source && _MGMT_SRC_PAT.test(edge.source)) { score = Math.max(0, score - 15); eFlags.push("Mgmt source (dampened)"); }
        const userArr = [...edge.users];
        const allSvcAccts = userArr.length > 0 && userArr.every(u => _SVC_ACCT_PAT.test(u));
        if (allSvcAccts) { score = Math.max(0, score - 10); eFlags.push("Service accounts (dampened)"); }
        if (edge.count >= _p90Count && _p90Count > 10 && !_chainEdges.has(ek)) { score = Math.max(0, score - 8); eFlags.push("Recurring edge (dampened)"); }
        edge.riskScore = score;
        edge.flags = eFlags;
        edge.findingIds = eFids;
      }

      // === Chain Hop Technique Enrichment + Confidence Scoring ===
      // Build findings-based technique map: "SOURCE->TARGET" => best technique label
      const _FINDING_TECH_MAP = {
        "PsExec Native": "PsExec", "Impacket Execution": "Impacket", "Impacket Summary": "Impacket",
        "Remote Service Execution": "Remote Service",
        "WMI Remote Execution": "WMI", "WMI Remote Activity": "WMI",
        "WinRM Remote Execution": "WinRM", "WinRM Remote Activity": "WinRM",
        "Scheduled Task Remote Execution": "Scheduled Task",
        "Admin Share Access": "Admin Share",
      };
      const _findingTechByPair = new Map(); // "SRC->TGT" => technique label
      for (const f of findings) {
        const techLabel = _FINDING_TECH_MAP[f.category];
        if (!techLabel) continue;
        if (!f.source) continue;
        const targets = (f.target || "").split(", ").filter(Boolean);
        for (const t of targets) {
          const pk = `${(f.source || "").toUpperCase()}->${t.toUpperCase()}`;
          // Keep highest-specificity technique (first match wins — PsExec/Impacket over generic)
          if (!_findingTechByPair.has(pk)) _findingTechByPair.set(pk, techLabel);
        }
      }
      // Enrich edge technique from findings when edge is "Network Logon" or "Unknown"
      for (const edge of edgeMap.values()) {
        if (edge.technique !== "Network Logon" && edge.technique !== "Unknown") continue;
        const ek = `${(edge.source || "").toUpperCase()}->${(edge.target || "").toUpperCase()}`;
        const ft = _findingTechByPair.get(ek);
        if (ft) {
          if (edge.technique !== "Unknown") edge.otherTechniques = [edge.technique, ...(edge.otherTechniques || [])];
          edge.technique = ft;
        }
      }

      // Enrich "Network Logon" hops from findings or edge technique
      for (const chain of chains) {
        for (const hop of chain._rawHops) {
          if (hop.technique !== "Network Logon") continue;
          const pk = `${hop.source.toUpperCase()}->${hop.target.toUpperCase()}`;
          // Priority 1: findings-based technique (PsExec, Impacket, WMI, Remote Service)
          const findingTech = _findingTechByPair.get(pk);
          if (findingTech) { hop.technique = findingTech; continue; }
          // Priority 2: edge primary technique if more specific
          const edge = edgeMap.get(`${hop.source}->${hop.target}`);
          if (edge && edge.technique && edge.technique !== "Unknown" && edge.technique !== "Network Logon") {
            hop.technique = edge.technique;
          }
        }
        // Rebuild techniques list and hopDetails after enrichment
        chain.techniques = [...new Set(chain._rawHops.map(h => h.technique).filter(Boolean))];
        chain.hopDetails = chain._rawHops.map(h => ({
          source: h.source, target: h.target, user: h.user, ts: h.ts,
          technique: h.technique, eventId: h.eventId, logonType: h.logonType,
        }));
      }

      for (const chain of chains) {
        const ch = chain._rawHops;
        let conf = 0;
        const confFlags = [];
        // Same user across all hops (+20)
        if (chain.users.length === 1 && chain.users[0] !== "(unknown)") { conf += 20; confFlags.push("Same user throughout"); }
        // Technique-backed hops (+5 each, max 20)
        const backedHops = ch.filter(h => h.technique && h.technique !== "Network Logon").length;
        if (backedHops > 0) { const boost = Math.min(20, backedHops * 5); conf += boost; confFlags.push(`${backedHops} technique-backed hop${backedHops > 1 ? "s" : ""}`); }
        // DC/server target on final hop (+10/+5)
        const finalTarget = ch[ch.length - 1].target;
        if (_DC_PAT.test(finalTarget)) { conf += 10; confFlags.push("Terminal target is DC"); }
        else if (_SRV_PAT.test(finalTarget)) { conf += 5; confFlags.push("Terminal target is server"); }
        // First-seen pair on any hop (+5)
        if (ch.some(h => { const e = edgeMap.get(`${h.source}->${h.target}`); return e && e.isFirstSeen; })) { conf += 5; confFlags.push("First-seen pair in chain"); }
        // Finding overlap (+10)
        const chainFindingIds = [];
        for (const h of ch) {
          const fk = `${h.source.toUpperCase()}->${h.target.toUpperCase()}`;
          const mf = _findingPairs.get(fk) || [];
          if (mf.length > 0) chainFindingIds.push(...mf);
        }
        if (chainFindingIds.length > 0) { conf += 10; confFlags.push("Finding overlap"); }
        // 3+ hops (+5)
        if (chain.hops >= 3) { conf += 5; confFlags.push(`${chain.hops} hops`); }
        // Penalties
        if (chain.users.length > 1) { conf = Math.max(0, conf - 5); confFlags.push("Mixed users (penalty)"); }
        if (chain.techniques.length === 1 && chain.techniques[0] === "Network Logon") { conf = Math.max(0, conf - 5); confFlags.push("Only generic logon (penalty)"); }
        let wideGaps = 0;
        for (let i = 1; i < ch.length; i++) {
          const gap = new Date(ch[i].ts) - new Date(ch[i - 1].ts);
          if (gap > 1800000) wideGaps++;
        }
        if (wideGaps > 0) { conf = Math.max(0, conf - wideGaps * 3); confFlags.push(`${wideGaps} wide gap${wideGaps > 1 ? "s" : ""} (penalty)`); }
        chain.confidence = conf >= 30 ? "high" : conf >= 15 ? "medium" : "low";
        chain.confidenceScore = conf;
        chain.confidenceFlags = confFlags;
        chain.findingIds = [...new Set(chainFindingIds)];
        delete chain._rawHops; // clean up internal field
      }
      chains.sort((a, b) => b.confidenceScore - a.confidenceScore || b.hops - a.hops);

      // === Lateral Pivot (T1021): middle hosts in chains ===
      // Severity derived from the best supporting chain's confidence
      const pivotHosts = new Map(); // host -> best chain
      for (const chain of chains) {
        for (let i = 1; i < chain.path.length - 1; i++) {
          const host = chain.path[i];
          const existing = pivotHosts.get(host);
          if (!existing || (chain.confidenceScore || 0) > (existing.confidenceScore || 0)) {
            pivotHosts.set(host, { chain, hopIdx: i });
          }
        }
      }
      for (const [host, { chain, hopIdx }] of pivotHosts) {
        const conf = chain.confidence || "low";
        const severity = conf === "high" ? "high" : conf === "medium" ? "medium" : "low";
        const pills = [{ text: `${chain.hops}-hop chain`, type: "correlation" }, { text: `pivot: ${host}`, type: "target" }];
        if (conf !== "high") pills.push({ text: `${conf} confidence`, type: "context" });
        findings.push({ id: fid++, severity, category: "Lateral Pivot", mitre: "T1021", title: `Pivot host: ${host}`, description: `Used as pivot in ${chain.hops}-hop chain: ${chain.path.join(" \u2192 ")} (${conf} confidence, score ${chain.confidenceScore || 0})`, source: chain.path[hopIdx - 1], target: chain.path[hopIdx + 1], timeRange: { from: chain.timestamps[hopIdx] || "", to: chain.timestamps[hopIdx + 1] || "" }, eventCount: chain.hops, evidencePills: pills, users: [] });
      }

      // === Episode Clustering per Edge ===
      // Split by user + phase (failed/success/reconnect) + technique family + 30-min gap
      const _evtsByEdge = new Map();
      for (const evt of timeOrdered) {
        const ek = `${evt.source}->${evt.target}`;
        if (!_evtsByEdge.has(ek)) _evtsByEdge.set(ek, []);
        _evtsByEdge.get(ek).push(evt);
      }
      const _FAIL_EIDS = new Set(["4625", "4771", "4776"]);
      const _RECON_EIDS = new Set(["25", "4778", "39", "40"]);
      const _RDP_LTS = new Set(["10", "12"]);
      const _epPhase = (evt) => {
        if (_FAIL_EIDS.has(evt.eventId)) return "failed";
        if (_RECON_EIDS.has(evt.eventId) || evt.logonType === "7") return "reconnect";
        return "success";
      };
      const _epTechFamily = (evt) => {
        if (_RDP_LTS.has(evt.logonType) || ["1149", "21", "22", "24", "25"].includes(evt.eventId)) return "RDP";
        if (evt.logonType === "3" && ["7045", "4697"].includes(evt.eventId)) return "ServiceExec";
        if ((evt.eventId === "5140" || evt.eventId === "5145") && evt.shareName) {
          const sn = (evt.shareName || "").replace(/^\\\\\*\\/, "").toUpperCase();
          if (/^(ADMIN\$|C\$|[A-Z]\$|IPC\$)$/.test(sn)) return "AdminShare";
        }
        if (evt.logonType === "3") return "Network";
        if (evt.logonType === "8") return "Cleartext";
        if (evt.logonType === "2") return "Interactive";
        return "Other";
      };
      const EPISODE_GAP_MS = 1800000; // 30 min
      for (const [ek, evts] of _evtsByEdge) {
        evts.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
        const episodes = [];
        let cur = null;
        for (const evt of evts) {
          const uk = (evt.user || "(unknown)").toUpperCase();
          const phase = _epPhase(evt);
          const techFam = _epTechFamily(evt);
          if (cur && cur._uk === uk && cur._phase === phase && cur._techFam === techFam) {
            const gap = new Date(evt.ts) - new Date(cur.lastTs);
            if (!isNaN(gap) && gap <= EPISODE_GAP_MS) {
              cur.count++;
              cur.lastTs = evt.ts;
              cur.eids.add(evt.eventId);
              if (evt.logonType) cur.lts.add(evt.logonType);
              continue;
            }
          }
          cur = { _uk: uk, _phase: phase, _techFam: techFam, user: evt.user || "(unknown)", phase, techFamily: techFam, count: 1, firstTs: evt.ts, lastTs: evt.ts, eids: new Set([evt.eventId]), lts: new Set(evt.logonType ? [evt.logonType] : []) };
          episodes.push(cur);
        }
        const edge = edgeMap.get(ek);
        if (edge) {
          edge.episodes = episodes.map(ep => ({ user: ep.user, phase: ep.phase, techFamily: ep.techFamily, count: ep.count, firstTs: ep.firstTs, lastTs: ep.lastTs, eventIds: [...ep.eids], logonTypes: [...ep.lts] }));
        }
      }
      for (const edge of edgeMap.values()) { if (!edge.episodes) edge.episodes = []; }

      // === RDP Session Suspicion Scoring ===
      const _pairFirst = new Map();
      for (const s of rdpSessions) {
        const pk = `${(s.source || "").toUpperCase()}->${(s.target || "").toUpperCase()}|${(s.user || "").toUpperCase()}`;
        const ex = _pairFirst.get(pk);
        if (!ex || (s.startTime && s.startTime < ex)) _pairFirst.set(pk, s.startTime);
      }
      for (const s of rdpSessions) {
        let score = 0;
        const flags = [];
        // Source is outlier
        if (s.source && _outlierHosts.has(s.source.toUpperCase())) { score += 20; flags.push("Source is outlier"); }
        // Target is DC or server
        if (s.target && _DC_PAT.test(s.target)) { score += 15; flags.push("Target is DC"); }
        else if (s.target && _SRV_PAT.test(s.target)) { score += 8; flags.push("Target is server"); }
        // Admin privileges
        if (s.hasAdmin) { score += 15; flags.push("Admin privileges (4672)"); }
        // Failures
        if (s.hasFailed && (s.attemptCount || 1) > 1) { score += 10; flags.push(`${s.attemptCount} failed attempts`); }
        else if (s.hasFailed) { score += 5; flags.push("Failed auth"); }
        // Explicit creds
        if (s.events.some(e => e.eventId === "4648")) { score += 10; flags.push("Explicit creds (4648)"); }
        // Missing expected events
        if (s.missingExpected && s.missingExpected.length > 0) { score += 5; flags.push(`Missing ${s.missingExpected.join(", ")}`); }
        // Low confidence
        if (s.confidence === "low") { score += 5; flags.push("Low confidence chain"); }
        // First-seen pair
        const _pk = `${(s.source || "").toUpperCase()}->${(s.target || "").toUpperCase()}|${(s.user || "").toUpperCase()}`;
        if (_pairFirst.get(_pk) === s.startTime) {
          const pairCount = rdpSessions.filter(x => `${(x.source || "").toUpperCase()}->${(x.target || "").toUpperCase()}|${(x.user || "").toUpperCase()}` === _pk).length;
          if (pairCount === 1) { score += 8; flags.push("First-seen pair"); }
        }
        // Finding overlap
        const _fk = `${(s.source || "").toUpperCase()}->${(s.target || "").toUpperCase()}`;
        const matchedFids = _findingPairs.get(_fk) || [];
        if (matchedFids.length > 0) {
          score += 12;
          const fCats = [...new Set(matchedFids.map(fid => findings.find(f => f.id === fid)?.category).filter(Boolean))];
          flags.push(...fCats.map(c => `Finding: ${c}`));
        }
        // Upgrade technique if suspicious enough
        if (score >= 25 && s.technique === "RDP") s.technique = "Suspicious RDP";
        s.suspicionScore = score;
        s.flags = flags;
        s.findingIds = matchedFids;
      }

      // === Concurrent RDP Session Detection (T1021.001) ===
      // Detect same user with overlapping RDP sessions on different targets
      {
        // Step 1: Collect eligible sessions (exclude failed, exclude incomplete junk)
        const _concSessions = [];
        for (const s of rdpSessions) {
          if (s.status === "failed" || s.status === "incomplete" || s.status === "connecting") continue;
          if (!s.user || !s.target || !s.startTime) continue;
          // Normalize end time: use endTime, else last event ts, else cap at start + 30min
          let effectiveEnd = s.endTime;
          if (!effectiveEnd || effectiveEnd <= s.startTime) {
            const lastEvtTs = s.events.length > 0 ? s.events[s.events.length - 1]?.ts : null;
            if (lastEvtTs && lastEvtTs > s.startTime) {
              effectiveEnd = lastEvtTs;
            } else {
              // Cap open-ended sessions at start + 30 min to avoid over-firing
              const startMs = new Date(s.startTime).getTime();
              if (!isNaN(startMs)) effectiveEnd = new Date(startMs + 1800000).toISOString();
              else continue;
            }
          }
          _concSessions.push({
            id: s.id, user: (s.user || "").toUpperCase(), target: (s.target || "").toUpperCase(),
            source: (s.source || "").toUpperCase(), start: s.startTime, end: effectiveEnd,
            confidence: s.confidence || "low", hasAdmin: !!s.hasAdmin,
            suspicionScore: s.suspicionScore || 0, technique: s.technique || "RDP",
            _session: s,
          });
        }
        // Step 2: Group by normalized user
        const _byUser = new Map();
        for (const cs of _concSessions) {
          if (!_byUser.has(cs.user)) _byUser.set(cs.user, []);
          _byUser.get(cs.user).push(cs);
        }
        // Step 3: For each user, find overlapping sessions on different targets
        const MIN_OVERLAP_MS = 60000; // 1 min minimum to avoid timestamp noise
        const _concGroups = []; // {user, sessions[], targets[], sources[], overlapStart, overlapEnd}
        for (const [user, sessions] of _byUser) {
          if (sessions.length < 2) continue;
          // Sort by start time
          sessions.sort((a, b) => a.start.localeCompare(b.start));
          // Find distinct-target overlaps via sweep
          // For each session, check forward for overlapping sessions on different targets
          const used = new Set(); // session ids already clustered
          for (let i = 0; i < sessions.length; i++) {
            if (used.has(sessions[i].id)) continue;
            const cluster = [sessions[i]];
            const clusterTargets = new Set([sessions[i].target]);
            // Track the intersection window — all members must be active during this range
            let intStart = sessions[i].start; // max(starts)
            let intEnd = sessions[i].end;     // min(ends)
            for (let j = i + 1; j < sessions.length; j++) {
              if (used.has(sessions[j].id)) continue;
              // Candidate intersection with existing cluster window
              const newIntStart = sessions[j].start > intStart ? sessions[j].start : intStart;
              const newIntEnd = sessions[j].end < intEnd ? sessions[j].end : intEnd;
              const overlapMs = new Date(newIntEnd) - new Date(newIntStart);
              if (isNaN(overlapMs) || overlapMs < MIN_OVERLAP_MS) continue;
              // Require different target to establish concurrency, or extend existing multi-target cluster
              if (clusterTargets.has(sessions[j].target) && clusterTargets.size < 2) continue;
              cluster.push(sessions[j]);
              clusterTargets.add(sessions[j].target);
              intStart = newIntStart;
              intEnd = newIntEnd;
            }
            // Only emit if we have 2+ different targets
            if (clusterTargets.size < 2) continue;
            // Mark used
            for (const cs of cluster) used.add(cs.id);
            _concGroups.push({
              user,
              sessions: cluster,
              targets: [...clusterTargets],
              sources: [...new Set(cluster.map(c => c.source).filter(Boolean))],
              overlapStart: intStart,
              overlapEnd: intEnd,
            });
          }
        }
        // Step 4: Emit findings with severity tiers + FP controls
        // Dampener patterns
        const _concSvcPat = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP|TASK[_\-]|SCH[_\-]|SA[_\-])/i;
        for (const grp of _concGroups) {
          const { user, sessions: cSessions, targets, sources, overlapStart, overlapEnd } = grp;
          const highConfCount = cSessions.filter(c => c.confidence === "high" || c.confidence === "medium").length;
          const adminTargets = targets.filter(t => _DC_PAT.test(t) || _SRV_PAT.test(t));
          const hasAdminPriv = cSessions.some(c => c.hasAdmin);
          const allHosts = [...new Set([...targets, ...sources])];
          const sessionIds = cSessions.map(c => c.id);
          // FP dampeners (applied as severity reduction, not exclusion)
          let isSvcAccount = _concSvcPat.test(user);
          let isMgmtSource = sources.length > 0 && sources.every(s => _MGMT_SRC_PAT.test(s));
          // Severity tiers
          let severity;
          if (targets.length >= 3 || (adminTargets.length > 0 && hasAdminPriv)) {
            severity = "critical";
          } else if (highConfCount >= 2) {
            severity = "high";
          } else {
            severity = "medium";
          }
          // Dampeners: reduce severity, never exclude
          if (isSvcAccount) {
            if (severity === "critical") severity = "high";
            else if (severity === "high") severity = "medium";
          }
          if (isMgmtSource) {
            if (severity === "critical") severity = "high";
            else if (severity === "high") severity = "medium";
          }
          // Check for very short overlap — further dampening
          const overlapMs = new Date(overlapEnd) - new Date(overlapStart);
          if (!isNaN(overlapMs) && overlapMs < 120000) { // < 2 min
            if (severity === "critical") severity = "high";
            else if (severity === "high") severity = "medium";
          }
          const targetLabel = targets.slice(0, 4).join(", ") + (targets.length > 4 ? ` +${targets.length - 4}` : "");
          const srcLabel = sources.length > 0 ? ` from ${sources.slice(0, 2).join(", ")}${sources.length > 2 ? ` +${sources.length - 2}` : ""}` : "";
          const adminLabel = adminTargets.length > 0 ? ` (includes ${adminTargets.slice(0, 2).join(", ")})` : "";
          const overlapLabel = overlapStart && overlapEnd ? ` Overlap: ${overlapStart.slice(0, 19)} \u2013 ${overlapEnd.slice(0, 19)}.` : "";
          const _rdpPills = [{ text: `${targets.length} concurrent targets`, type: "context" }];
          if (targets.some(t => _DC_PAT.test(t))) _rdpPills.push({ text: "DC target", type: "target" });
          else if (targets.some(t => _SRV_PAT.test(t))) _rdpPills.push({ text: "server target", type: "target" });
          if (hasAdminPriv) _rdpPills.push({ text: "admin privileges", type: "credential" });
          findings.push({
            id: fid++, severity, category: "Concurrent RDP Sessions", mitre: "T1021.001",
            title: `Concurrent RDP: ${user} on ${targets.length} targets (${targetLabel})`,
            description: `${user} has ${cSessions.length} overlapping RDP sessions on ${targets.length} targets${srcLabel}${adminLabel}.${overlapLabel} ${highConfCount}/${cSessions.length} sessions are medium/high confidence.${hasAdminPriv ? " Admin privileges detected." : ""}`,
            source: sources.join(", "), target: targets.join(", "),
            filterHosts: allHosts,
            timeRange: { from: overlapStart || "", to: overlapEnd || "" },
            eventCount: cSessions.reduce((s, c) => s + (c._session.events?.length || 0), 0),
            filterEids: ["4624", "1149", "21", "22"],
            _concurrentSessionIds: sessionIds,
            evidencePills: _rdpPills,
            users: [user.toUpperCase()],
          });
          // Flag the sessions themselves
          for (const cs of cSessions) {
            cs._session.isConcurrent = true;
            cs._session._concurrentTargets = targets.filter(t => t !== cs.target);
          }
        }
        // Re-sort findings by severity after adding concurrent findings
        findings.sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));
      }

      // === Kerberoasting Detection (T1558.003) ===
      // Detect 4769 events with RC4 encryption (0x17) which indicates Kerberoasting.
      // Normal Kerberos uses AES (0x11/0x12); RC4 requests for non-krbtgt SPNs are suspicious.
      try {
        const _krbEidCol = columns.eventId ? meta.colMap[columns.eventId] : null;
        const _krbTsCol = columns.ts ? meta.colMap[columns.ts] : null;
        const _krbHostCol = columns.target ? meta.colMap[columns.target] : null;
        const _krbUserCol = columns.user ? meta.colMap[columns.user] : null;
        // Detect encryption type and service name columns (dedicated or PayloadData)
        const _krbEncCol = columns.ticketEncryptionType ? meta.colMap[columns.ticketEncryptionType] : null;
        const _krbSvcCol = columns.serviceName ? meta.colMap[columns.serviceName] : null;
        // Also check PayloadData fields for EvtxECmd format
        const _krbPdCols = [columns._payloadData1, columns._payloadData2, columns._payloadData3, columns._payloadData4, columns._payloadData5]
          .filter(c => c && meta.colMap[c]).map(c => meta.colMap[c]);

        // Also detect ticketOptions column
        const _krbOptsCol = columns.ticketOptions ? meta.colMap[columns.ticketOptions] : null;

        if (_krbEidCol && (_krbEncCol || _krbPdCols.length > 0)) {
          const _krbSelParts = ["data.rowid as _rid"];
          if (_krbTsCol) _krbSelParts.push(`${_krbTsCol} as _ts`);
          if (_krbHostCol) _krbSelParts.push(`${_krbHostCol} as _host`);
          if (_krbUserCol) _krbSelParts.push(`${_krbUserCol} as _user`);
          if (_krbEncCol) _krbSelParts.push(`${_krbEncCol} as _enc`);
          if (_krbSvcCol) _krbSelParts.push(`${_krbSvcCol} as _svc`);
          if (_krbOptsCol) _krbSelParts.push(`${_krbOptsCol} as _opts`);
          for (let pi = 0; pi < _krbPdCols.length; pi++) _krbSelParts.push(`${_krbPdCols[pi]} as _pd${pi}`);

          const _krbSql = `SELECT ${_krbSelParts.join(", ")} FROM data WHERE ${_krbEidCol} = '4769' LIMIT 50000`;
          const _krbRows = db.prepare(_krbSql).all();

          const _krbHits = []; // {ts, host, user, serviceName, encType}
          let _krbTotalRows = 0; // total 4769 rows (all encryption types) for ratio check
          const _KRBTGT_PAT = /^krbtgt[\/$@]/i;
          const _MACHINE_SPN_PAT = /\$@/;
          // Common infrastructure SPNs that legitimately use RC4 in mixed environments
          const _COMMON_SPN_PREFIX = /^(HTTP|CIFS|HOST|LDAP|DNS|NFS|TERMSRV|RestrictedKrbHost|WSMAN|exchangeMDB|exchangeRFR|exchangeAB|SMTP|POP|IMAP)\//i;
          // Service account naming patterns (these accounts legitimately request RC4 tickets)
          const _SVC_ACCOUNT_PAT = /^(svc[_\-]|sql[_\-]|iis[_\-]|app[_\-]|bak[_\-]|msa[_\-]|gms[_\-]|task[_\-]|scan[_\-]|mon[_\-]|noc[_\-]|adm[_\-]|da[_\-]|SA[_\-])/i;

          for (const row of _krbRows) {
            _krbTotalRows++;
            let encType = null;
            let svcName = null;
            let status = null;

            // Try dedicated columns first
            if (row._enc) encType = row._enc.toString().trim();
            if (row._svc) svcName = row._svc.toString().trim();

            // EvtxECmd fallback: parse from PayloadData fields
            if (!encType || !svcName) {
              for (let pi = 0; pi < _krbPdCols.length; pi++) {
                const pd = (row[`_pd${pi}`] || "").toString();
                if (!encType) {
                  const encMatch = pd.match(/(?:Ticket\s*Encryption\s*Type|EncryptionType)[:\s]+(0x[0-9A-Fa-f]+|\d+)/i);
                  if (encMatch) encType = encMatch[1].trim();
                }
                if (!svcName) {
                  const svcMatch = pd.match(/(?:Service\s*Name|ServiceName|TargetServiceName)[:\s]+([^\s|,]+)/i);
                  if (svcMatch) svcName = svcMatch[1].trim();
                }
                // Parse status/result code from PayloadData
                if (!status) {
                  const stMatch = pd.match(/(?:Status|Result)[:\s]+(0x[0-9A-Fa-f]+)/i);
                  if (stMatch) status = stMatch[1].toUpperCase();
                }
              }
            }

            if (!encType) continue;
            // Normalize encryption type: 0x17 = 23 = RC4_HMAC_MD5
            const encNorm = encType.startsWith("0x") ? parseInt(encType, 16) : parseInt(encType, 10);
            if (encNorm !== 0x17) continue; // Only flag RC4

            // --- FP Control: skip failed ticket requests ---
            // Only successful requests (status 0x0) yield a ticket to crack offline
            // Failed requests are noise (permission denied, SPN not found, etc.)
            if (status && status !== "0X0") continue;

            // Skip krbtgt (normal TGT requests) and machine accounts
            if (svcName && (_KRBTGT_PAT.test(svcName) || _MACHINE_SPN_PAT.test(svcName))) continue;

            // Parse user from EvtxECmd PayloadData1 if needed
            let user = (row._user || "").trim();
            if (isEvtxECmd && user) {
              const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
              if (pdMatch) user = pdMatch[2].trim();
            }
            // Skip machine accounts requesting tickets (normal behavior)
            if (user && user.endsWith("$")) continue;

            // --- FP Control: skip self-referential SPN requests ---
            // When requester name appears in the SPN, it's the service requesting its own ticket
            if (svcName && user && user !== "(unknown)") {
              const userBase = user.split("@")[0].toLowerCase();
              const svcLower = svcName.toLowerCase();
              if (svcLower.includes(userBase) || svcLower.startsWith(userBase + "/")) continue;
            }

            _krbHits.push({
              ts: row._ts || "",
              host: (row._host || "").toString().trim().toUpperCase(),
              user: user || "(unknown)",
              serviceName: svcName || "(unknown)",
              encType: "RC4 (0x17)",
              isCommonSPN: svcName ? _COMMON_SPN_PREFIX.test(svcName) : false,
              isSvcAccount: user ? _SVC_ACCOUNT_PAT.test(user) : false,
            });
          }

          if (_krbHits.length > 0 && !_disabledSet.has("kerberoast")) {
            // --- FP Control: RC4 ratio check ---
            // If RC4 is >50% of all 4769 requests, it's likely a legacy/mixed environment
            // where RC4 is the default — dampen severity across the board
            const _krbRc4Ratio = _krbTotalRows > 0 ? _krbHits.length / _krbTotalRows : 1;
            const _krbIsLegacyEnv = _krbRc4Ratio > 0.5;

            // Cluster by user
            _krbHits.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
            const _krbByUser = new Map();
            for (const h of _krbHits) {
              const uk = h.user.toUpperCase();
              if (!_krbByUser.has(uk)) _krbByUser.set(uk, []);
              _krbByUser.get(uk).push(h);
            }

            for (const [userKey, hits] of _krbByUser) {
              const spns = [...new Set(hits.map(h => h.serviceName))];
              const hosts = [...new Set(hits.map(h => h.host).filter(Boolean))];
              const allTs = hits.map(h => h.ts).filter(Boolean).sort();
              const user = hits[0].user;

              // --- FP Control: require minimum 3 unique SPNs ---
              // Single or two RC4 requests are common legitimate fallback
              if (spns.length < 3) continue;

              // --- FP Control: time-window burst detection ---
              // Kerberoasting tools request many tickets in rapid succession
              // Require at least 3 requests within a 10-minute window
              let hasBurst = false;
              if (allTs.length >= 3) {
                for (let i = 0; i <= allTs.length - 3; i++) {
                  const t0 = new Date(allTs[i]).getTime();
                  const t2 = new Date(allTs[i + 2]).getTime();
                  if (!isNaN(t0) && !isNaN(t2) && (t2 - t0) <= 600000) { // 10 min
                    hasBurst = true;
                    break;
                  }
                }
              }
              // No burst detected — these are spread-out individual requests, likely normal
              if (!hasBurst) continue;

              // --- FP Control: common SPN ratio ---
              // If most targeted SPNs are common infrastructure (HTTP/, CIFS/, HOST/),
              // this is less likely targeted Kerberoasting
              const commonCount = hits.filter(h => h.isCommonSPN).length;
              const commonRatio = hits.length > 0 ? commonCount / hits.length : 0;

              // --- FP Control: service account requester ---
              // Service accounts (svc_*, sql_*, etc.) legitimately request RC4 tickets
              const isSvcAcct = hits[0].isSvcAccount;

              // Severity: base on SPN count, then dampen for legacy env or common SPNs
              let severity;
              if (spns.length >= 10) severity = "critical";
              else if (spns.length >= 5) severity = "high";
              else severity = "medium"; // 3-4 SPNs

              // Dampen severity for legacy RC4 environments
              if (_krbIsLegacyEnv) {
                if (severity === "critical") severity = "high";
                else if (severity === "high") severity = "medium";
                else severity = "low";
              }
              // Dampen if >80% common infrastructure SPNs
              if (commonRatio > 0.8) {
                if (severity === "critical") severity = "high";
                else if (severity === "high") severity = "medium";
                else severity = "low";
              }
              // Dampen if requester is a service account
              if (isSvcAcct) {
                if (severity === "critical") severity = "high";
                else if (severity === "high") severity = "medium";
                else severity = "low";
              }
              // Skip low-severity findings entirely (too noisy)
              if (severity === "low") continue;

              const _krbPills = [{ text: "RC4 ticket request", type: "credential" }];
              _krbPills.push({ text: `${spns.length} SPN${spns.length > 1 ? "s" : ""}`, type: "context" });
              if (spns.length >= 10) _krbPills.push({ text: "mass Kerberoasting", type: "execution" });
              if (hasBurst) _krbPills.push({ text: "burst pattern", type: "execution" });
              if (hosts.some(h => _DC_PAT.test(h))) _krbPills.push({ text: "DC target", type: "target" });
              if (_krbIsLegacyEnv) _krbPills.push({ text: "legacy RC4 env", type: "context" });
              if (commonRatio > 0.8) _krbPills.push({ text: `${Math.round(commonRatio * 100)}% common SPNs`, type: "context" });
              if (isSvcAcct) _krbPills.push({ text: "service account", type: "context" });

              findings.push({
                id: fid++, severity, category: "Kerberoasting", mitre: "T1558.003",
                title: `Kerberoasting: ${user} requested ${spns.length} RC4 service ticket${spns.length > 1 ? "s" : ""}`,
                description: `${hits.length} Kerberos service ticket request(s) with RC4 encryption (0x17) by ${user} in a ${allTs.length >= 2 ? "burst" : "short"} pattern. SPNs: ${spns.slice(0, 10).join(", ")}${spns.length > 10 ? ` +${spns.length - 10} more` : ""}. Normal Kerberos uses AES (0x11/0x12); RC4 requests in rapid succession indicate potential Kerberoasting.`,
                source: "", target: hosts.join(", "),
                filterHosts: hosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: hits.length, filterEids: ["4769"],
                evidencePills: _krbPills, users: [user],
              });
            }
          }
        }
      } catch (_krbErr) { warnings.push(`Kerberoasting detector failed: ${_krbErr.message}`); }

      // === Session Grouping (Map-based, not adjacency-dependent) ===
      const _groupMap = new Map();
      for (const s of rdpSessions) {
        const gk = `${s.source}|${s.target}|${s.user}|${s.technique || s.status}`;
        let g = _groupMap.get(gk);
        if (!g) {
          g = { sessions: [], count: 0, status: s.status, source: s.source, target: s.target, user: s.user, timeRange: { from: s.startTime || "", to: s.endTime || s.startTime || "" }, representativeSession: s };
          _groupMap.set(gk, g);
        }
        g.sessions.push(s);
        g.count++;
        if (s.startTime && s.startTime < g.timeRange.from) g.timeRange.from = s.startTime;
        const et = s.endTime || s.startTime;
        if (et && et > g.timeRange.to) g.timeRange.to = et;
      }
      const groupedSessions = [..._groupMap.values()];
      groupedSessions.forEach(g => g.sessions.sort((a, b) => (a.startTime || "").localeCompare(b.startTime || "")));

      return {
        nodes: [...hostSet.entries()].map(([id, info]) => {
          const outlierReason = detectOutlier(id);
          return {
            id, label: id, eventCount: info.eventCount,
            isSource: info.isSource, isTarget: info.isTarget,
            isBoth: info.isSource && info.isTarget,
            isOutlier: !!outlierReason, outlierReason: outlierReason || "",
          };
        }),
        edges: [...edgeMap.values()].map((e) => ({
          ...e, users: [...e.users], logonTypes: [...e.logonTypes], clientNames: [...e.clientNames], clientAddresses: [...e.clientAddresses],
          eventBreakdown: Object.fromEntries(e.eventBreakdown), shareNames: [...(e.shareNames || [])],
        })),
        chains,
        rdpSessions,
        groupedSessions,
        findings,
        incidents,
        stats: {
          totalEvents: timeOrdered.length, uniqueHosts: hostSet.size,
          uniqueUsers: new Set(timeOrdered.map((e) => e.user).filter(Boolean)).size,
          uniqueConnections: edgeMap.size,
          failedLogons: [...edgeMap.values()].reduce((s, e) => s + (e.hasFailures ? 1 : 0), 0),
          longestChain: chains.length > 0 ? chains[0].hops : 0,
          chainCount: chains.length,
          rdpSessionCount: rdpSessions.length,
          adminSessions: rdpSessions.filter((s) => s.hasAdmin).length,
          suspiciousSessions: rdpSessions.filter((s) => (s.suspicionScore || 0) >= 25).length,
          findingsCount: findings.length,
          criticalFindings: findings.filter((f) => f.severity === "critical").length,
          incidentCount: incidents.length,
          datasetEnd: timeOrdered.length > 0 ? timeOrdered[timeOrdered.length - 1].ts : null,
        },
        warnings, scanStats,
        columns, error: null,
      };
    } catch (e) {
      return { nodes: [], edges: [], chains: [], findings: [], incidents: [], groupedSessions: [], stats: {}, warnings: [], scanStats: {}, columns, error: e.message };
    }
  }

  /**
   * Lightweight persistence preview — event counts + column quality for the config screen
   */
  previewPersistenceAnalysis(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { eventCounts: {}, columnQuality: {}, error: "No database" };
    const { mode = "auto", columns: userCols = {} } = options;
    const { db, headers } = meta;
    const detect = (pats) => { for (const p of pats) { const f = headers.find(h => p.test(h)); if (f) return f; } return null; };

    const isChainsaw = this._isChainsawDataset(meta);
    const hasEventId = detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]);
    const hasKeyPath = detect([/^KeyPath$/i, /^Key ?Path$/i]);
    const hasValueName = detect([/^ValueName$/i, /^Value ?Name$/i]);
    const isHayabusa = this._isHayabusaDataset(meta);
    let detectedMode = mode;
    if (detectedMode === "auto") detectedMode = (hasKeyPath && hasValueName) ? "registry" : hasEventId ? "evtx" : null;

    try {
      // Build WHERE clause from active filters (mirrors the real analyzer's scope)
      const params = [];
      const whereConditions = [];
      this._applyStandardFilters(options, meta, whereConditions, params);
      const wc = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

      const eventCounts = {};
      let trackedEvents = 0;
      const columnQuality = {};

      if (detectedMode === "evtx") {
        // Resolve columns
        const cols = {
          eventId: userCols.eventId || detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]),
          channel: userCols.channel || detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
          ts: userCols.ts || detect([/^TimeCreated$/i, /^datetime$/i, /^UtcTime$/i, /^Timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
          computer: userCols.computer || detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
          user: userCols.user || detect([/^UserName$/i, /^User$/i, ...(isChainsaw ? [/^target_username$/i] : [])]) || (isHayabusa ? detect([/^ExtraFieldInfo$/i, /^Details$/i]) : null),
          payload: detect([/^PayloadData1$/i]),
          execInfo: detect([/^ExecutableInfo$/i]),
          details: detect([/^Details$/i, ...(isChainsaw ? [/^Event\.EventData\.Details$/i] : [])]),
          extra: detect([/^ExtraFieldInfo$/i]),
        };

        // Event counts for persistence-relevant EIDs
        if (cols.eventId && meta.colMap[cols.eventId]) {
          const eidSafe = meta.colMap[cols.eventId];
          const uiEids = ["7045","4697","4698","4699","106","129","140","200","141","118","119","5861","19","20","21","13","12","14","11","7","6","25","4720","4728","4732","4756","4724","4738","5136","5137","5141","4104","4657","7040","4702"];
          const eidWhere = wc ? `${wc} AND` : "WHERE";
          const rows = db.prepare(`SELECT ${eidSafe} as eid, COUNT(*) as cnt FROM data ${eidWhere} ${eidSafe} IN (${uiEids.map(() => "?").join(",")}) GROUP BY ${eidSafe}`).all(...params, ...uiEids);
          for (const r of rows) { if (r.eid != null) { const k = String(r.eid).trim(); eventCounts[k] = r.cnt; trackedEvents += r.cnt; } }
        }

        // Column quality — batched on 2000-row sample
        const mappedCols = Object.entries(cols).filter(([, cn]) => cn && meta.colMap[cn]);
        if (mappedCols.length > 0) {
          const caseParts = mappedCols.map(([key, cn]) => `SUM(CASE WHEN ${meta.colMap[cn]} IS NULL OR TRIM(${meta.colMap[cn]}) = '' OR ${meta.colMap[cn]} = '-' THEN 1 ELSE 0 END) as null_${key}`);
          const qr = db.prepare(`SELECT COUNT(*) as total, ${caseParts.join(", ")} FROM (SELECT * FROM data ${wc} LIMIT 2000)`).get(...params);
          const sampleTotal = qr ? qr.total : 0;
          for (const [key] of mappedCols) {
            const nulls = qr ? (qr[`null_${key}`] || 0) : 0;
            columnQuality[key] = { mapped: true, nullRate: sampleTotal > 0 ? Math.round((nulls / sampleTotal) * 100) : 0 };
          }
          for (const [key, cn] of Object.entries(cols)) { if (!cn || !meta.colMap[cn]) columnQuality[key] = { mapped: false }; }
        }

        return { eventCounts, trackedEvents, columnQuality, detectedMode, resolvedColumns: cols, isHayabusa, isChainsaw };

      } else if (detectedMode === "registry") {
        const cols = {
          keyPath: userCols.keyPath || detect([/^KeyPath$/i, /^Key ?Path$/i]),
          valueName: userCols.valueName || detect([/^ValueName$/i, /^Value ?Name$/i]),
          valueData: userCols.valueData || detect([/^ValueData$/i, /^Value ?Data$/i]),
          hivePath: detect([/^HivePath$/i, /^Hive ?Path$/i]),
          ts: userCols.ts || detect([/^LastWriteTimestamp$/i, /^Timestamp$/i, /^datetime$/i, /^TimeCreated$/i]),
        };

        // Registry coverage: count rows per group + deduplicated total via single query
        const regGroups = [
          { label: "Run Keys", pattern: "%\\\\Run%" },
          { label: "Services", pattern: "%\\\\Services\\\\%" },
          { label: "Winlogon", pattern: "%\\\\Winlogon%" },
          { label: "IFEO", pattern: "%Image File Execution%" },
          { label: "COM Objects", pattern: "%InprocServer32%" },
          { label: "Scheduled Tasks", pattern: "%TaskCache%" },
          { label: "Boot Execute", pattern: "%Session Manager%" },
          { label: "LSA", pattern: "%\\\\Lsa%" },
          { label: "Shell Extensions", pattern: "%ShellEx%" },
          { label: "AppInit DLLs", pattern: "%AppInit_DLLs%" },
          { label: "Print Monitors", pattern: "%Print\\\\Monitors%" },
          { label: "Active Setup", pattern: "%Active Setup%" },
          { label: "BHO", pattern: "%Browser Helper%" },
          { label: "Network Providers", pattern: "%NetworkProvider%" },
        ];
        if (cols.keyPath && meta.colMap[cols.keyPath]) {
          const kpSafe = meta.colMap[cols.keyPath];
          const wcAnd = wc ? `${wc} AND` : "WHERE";
          // Per-group counts
          for (const g of regGroups) {
            const r = db.prepare(`SELECT COUNT(*) as cnt FROM data ${wcAnd} ${kpSafe} LIKE ?`).get(...params, g.pattern);
            eventCounts[g.label] = r ? r.cnt : 0;
          }
          // Deduplicated total: count rows matching ANY persistence pattern
          const anyMatch = regGroups.map(() => `${kpSafe} LIKE ?`).join(" OR ");
          const totalR = db.prepare(`SELECT COUNT(*) as cnt FROM data ${wcAnd} (${anyMatch})`).get(...params, ...regGroups.map(g => g.pattern));
          trackedEvents = totalR ? totalR.cnt : 0;
        }

        // Column quality
        const mappedCols = Object.entries(cols).filter(([, cn]) => cn && meta.colMap[cn]);
        if (mappedCols.length > 0) {
          const caseParts = mappedCols.map(([key, cn]) => `SUM(CASE WHEN ${meta.colMap[cn]} IS NULL OR TRIM(${meta.colMap[cn]}) = '' OR ${meta.colMap[cn]} = '-' THEN 1 ELSE 0 END) as null_${key}`);
          const qr = db.prepare(`SELECT COUNT(*) as total, ${caseParts.join(", ")} FROM (SELECT * FROM data ${wc} LIMIT 2000)`).get(...params);
          const sampleTotal = qr ? qr.total : 0;
          for (const [key] of mappedCols) {
            const nulls = qr ? (qr[`null_${key}`] || 0) : 0;
            columnQuality[key] = { mapped: true, nullRate: sampleTotal > 0 ? Math.round((nulls / sampleTotal) * 100) : 0 };
          }
          for (const [key, cn] of Object.entries(cols)) { if (!cn || !meta.colMap[cn]) columnQuality[key] = { mapped: false }; }
        }

        return { eventCounts, trackedEvents, columnQuality, detectedMode, resolvedColumns: cols, isHayabusa, isChainsaw };
      }

      return { eventCounts: {}, trackedEvents: 0, columnQuality: {}, detectedMode: null, error: "Cannot detect data type" };
    } catch (e) {
      return { eventCounts: {}, columnQuality: {}, error: e.message };
    }
  }

  /**
   * Persistence Analyzer — scans EVTX or registry data for persistence mechanisms
   */
  getPersistenceAnalysis(tabId, options = {}) {
    const meta = this.databases.get(tabId);
    if (!meta) return { items: [], stats: {}, error: "Tab not found" };
    const { db, headers } = meta;
    const detect = (pats) => { for (const p of pats) { const f = headers.find(h => p.test(h)); if (f) return f; } return null; };

    // Auto-detect data mode
    const isChainsaw = this._isChainsawDataset(meta);
    const hasEventId = detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]);
    const hasKeyPath = detect([/^KeyPath$/i, /^Key ?Path$/i]);
    const hasValueName = detect([/^ValueName$/i, /^Value ?Name$/i]);
    const isHayabusa = this._isHayabusaDataset(meta);

    let mode = options.mode || "auto";
    if (mode === "auto") {
      mode = (hasKeyPath && hasValueName) ? "registry" : hasEventId ? "evtx" : null;
    }
    if (!mode) return { items: [], stats: {}, error: "Cannot detect data type. Need EventID column (EVTX) or KeyPath column (Registry)." };

    // --- Detection rules ---
    // Regex helper: match "Key: Value" in EvtxECmd PayloadData (pipe-delimited haystack)
    // EvtxECmd formats vary: "Name: Svc", "Task: \Path", "ServiceName: Svc", "Image: C:\..."
    const P = (key) => new RegExp(key + ":\\s*(.+?)(?:\\s*$|\\s*\\|)", "i"); // match until end or pipe
    const EVTX_RULES = [
      // --- Services ---
      { category: "Services", name: "Service Installed", eventIds: ["7045"], channels: ["system"], severity: "high",
        // EvtxECmd 7045 (System): PD2="Name: SvcName", PD3="StartType:", PD4="Account:", ExecutableInfo=ImagePath
        extractors: { serviceName: [P("Name"), P("ServiceName")], imagePath: [P("ImagePath"), P("Path"), P("ServiceFileName")], startType: [P("StartType")], account: [P("Account"), P("AccountName")] },
        topFields: ["serviceName", "imagePath", "account"], useExecInfo: "imagePath", payloadFilter: null },
      { category: "Services", name: "Service Installed", eventIds: ["4697"], channels: ["security"], severity: "high",
        extractors: { serviceName: [P("ServiceName")], serviceFile: [P("ServiceFileName")], serviceType: [P("ServiceType")], startType: [P("ServiceStartType")], account: [P("ServiceAccount")] },
        topFields: ["serviceName", "serviceFile", "account"], payloadFilter: null },
      // --- Scheduled Tasks ---
      { category: "Scheduled Tasks", name: "Scheduled Task Created", eventIds: ["4698"], channels: ["security"], severity: "high",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Task Name")], command: [P("Command"), P("Arguments"), P("Actions")] },
        topFields: ["taskName", "command", "executable"], useExecInfo: "executable", payloadFilter: null },
      { category: "Scheduled Tasks", name: "Scheduled Task Deleted", eventIds: ["4699"], channels: ["security"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Task Name")] },
        topFields: ["taskName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Task Registered", eventIds: ["106"], channels: ["taskscheduler"], severity: "medium",
        // EvtxECmd 106 (TaskScheduler/Operational): PD2="Task: \Name", ExecutableInfo=empty for this event
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
        topFields: ["taskName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Task Updated", eventIds: ["140"], channels: ["taskscheduler"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
        topFields: ["taskName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Task Process Created", eventIds: ["129"], channels: ["taskscheduler"], severity: "high",
        // EvtxECmd 129 (TaskScheduler/Operational): PD2="Task: \Name", PD3="ProcessID:", ExecutableInfo=exe path
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], processId: [P("ProcessID"), P("ProcessId")] },
        topFields: ["taskName", "executable", "processId"], useExecInfo: "executable", payloadFilter: null },
      { category: "Scheduled Tasks", name: "Task Action Started", eventIds: ["200"], channels: ["taskscheduler"], severity: "medium",
        // EvtxECmd 200 (TaskScheduler/Operational): PD2="Task: \Name", ExecutableInfo=action/handler name
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], instanceId: [P("Instance Id"), P("TaskInstanceId")] },
        topFields: ["taskName", "executable"], useExecInfo: "executable", payloadFilter: null },
      // --- WMI ---
      { category: "WMI Persistence", name: "WMI Event Subscription", eventIds: ["5861"], channels: ["wmi-activity"], severity: "critical",
        extractors: { namespace: [P("Namespace")], operation: [P("Operation")], query: [P("Query")], consumer: [P("Consumer")], poss_command: [P("PossibleCause"), P("Command")] },
        topFields: ["operation", "query", "consumer"], payloadFilter: null },
      { category: "WMI Persistence", name: "WMI EventFilter Created", eventIds: ["19"], channels: ["sysmon"], severity: "critical",
        extractors: { name: [P("Name")], query: [P("Query")], eventNamespace: [P("EventNamespace")], operation: [P("Operation")] },
        topFields: ["name", "query", "operation"], payloadFilter: null },
      { category: "WMI Persistence", name: "WMI EventConsumer Created", eventIds: ["20"], channels: ["sysmon"], severity: "critical",
        extractors: { name: [P("Name")], type: [P("Type")], destination: [P("Destination")], operation: [P("Operation")] },
        topFields: ["name", "destination", "type"], payloadFilter: null },
      { category: "WMI Persistence", name: "WMI Binding Created", eventIds: ["21"], channels: ["sysmon"], severity: "critical",
        extractors: { consumer: [P("Consumer")], filter: [P("Filter")], operation: [P("Operation")] },
        topFields: ["consumer", "filter"], payloadFilter: null },
      // --- Registry (Sysmon) ---
      { category: "Registry Autorun", name: "Registry Value Set", eventIds: ["13"], channels: ["sysmon"], severity: "high",
        extractors: { targetObject: [P("TargetObject"), P("TgtObj")], details: [P("Details")], image: [P("Image")] },
        topFields: ["targetObject", "details", "image"],
        payloadFilter: /\\(?:Run|RunOnce|RunServices|Services\\[^\\]*\\(?:ImagePath|Parameters)|Winlogon\\(?:Shell|Userinit|Notify|Taskman|VmApplet|AppSetup)|AppInit_DLLs|Image File Execution Options\\[^\\]*\\Debugger|CurrentVersion\\Explorer\\(?:Shell|User Shell)|Session Manager\\(?:BootExecute|SetupExecute|AppCertDlls)|InprocServer32|LocalServer32|ShellIconOverlay|ShellServiceObjectDelayLoad|ContextMenuHandler|Browser Helper|Active Setup|Print\\Monitors|NetworkProvider|Lsa\\|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunOnceEx)|SilentProcessExit\\|Environment\\(?:$|\\)|Credential Provid|PLAP Providers\\|Command Processor\\|Microsoft\\Netsh)/i },
      { category: "Registry Modification", name: "Registry Key Created/Deleted", eventIds: ["12"], channels: ["sysmon"], severity: "medium",
        extractors: { targetObject: [P("TargetObject"), P("TgtObj")], eventType: [P("EventType")], image: [P("Image")] },
        topFields: ["eventType", "targetObject", "image"],
        payloadFilter: /\\(?:Run|RunOnce|Services\\|Winlogon|AppInit_DLLs|Image File Execution Options|Session Manager\\(?:BootExecute|AppCertDlls)|Active Setup|Print\\Monitors|NetworkProvider|Lsa\\|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)|SilentProcessExit\\|Credential Provid|PLAP Providers\\|ShellServiceObjectDelayLoad|Command Processor\\|Microsoft\\Netsh)/i },
      { category: "Registry Rename", name: "Registry Key/Value Renamed", eventIds: ["14"], channels: ["sysmon"], severity: "medium",
        extractors: { targetObject: [P("TargetObject")], newName: [P("NewName")], eventType: [P("EventType")] },
        topFields: ["targetObject", "newName"],
        payloadFilter: /\\(?:Run|RunOnce|Services\\|Winlogon|Image File Execution Options|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)|SilentProcessExit\\|AppCertDlls|Credential Provid|PLAP Providers\\|ShellServiceObjectDelayLoad|Command Processor\\|Microsoft\\Netsh)/i },
      // --- File system (Sysmon) ---
      { category: "Startup Folder", name: "File Created in Startup", eventIds: ["11"], channels: ["sysmon"], severity: "high",
        extractors: { targetFilename: [P("TargetFilename")], image: [P("Image")], creationTime: [P("CreationUtcTime")] },
        topFields: ["targetFilename", "image"],
        payloadFilter: /Start Menu\\Programs\\Startup|ProgramData\\Microsoft\\Windows\\Start Menu|\\Startup\\[^\\]*\.(exe|dll|bat|cmd|ps1|vbs|js|lnk|url)$/i },
      { category: "DLL Hijacking", name: "Unsigned DLL Loaded", eventIds: ["7"], channels: ["sysmon"], severity: "medium",
        extractors: { imageLoaded: [P("ImageLoaded")], signed: [P("Signed")], signatureStatus: [P("SignatureStatus")], image: [P("Image")] },
        topFields: ["imageLoaded", "image", "signatureStatus"],
        payloadFilter: /Signed:\s*false/i },
      { category: "Driver Loading", name: "Suspicious Driver Loaded", eventIds: ["6"], channels: ["sysmon"], severity: "critical",
        extractors: { imageLoaded: [P("ImageLoaded")], signed: [P("Signed")], signatureStatus: [P("SignatureStatus")], signer: [P("Signer")] },
        topFields: ["imageLoaded", "signatureStatus", "signer"],
        payloadFilter: /Signed:\s*false|SignatureStatus:\s*(?:Expired|Revoked|Invalid|Unavailable)/i },
      { category: "Process Tampering", name: "Process Tampering Detected", eventIds: ["25"], channels: ["sysmon"], severity: "critical",
        extractors: { type: [P("Type")], image: [P("Image")] },
        topFields: ["image", "type"], payloadFilter: null },
      // --- Task Scheduler lifecycle (anti-forensics / trigger tracking) ---
      { category: "Scheduled Tasks", name: "Task Deleted", eventIds: ["141"], channels: ["taskscheduler"], severity: "high",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], userName: [P("UserName"), P("User")] },
        topFields: ["taskName", "userName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Boot Trigger Fired", eventIds: ["118"], channels: ["taskscheduler"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")] },
        topFields: ["taskName"], payloadFilter: null },
      { category: "Scheduled Tasks", name: "Logon Trigger Fired", eventIds: ["119"], channels: ["taskscheduler"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Name")], userName: [P("UserName"), P("User")] },
        topFields: ["taskName", "userName"], payloadFilter: null },
      // --- Account Persistence (DFIR report-derived: 7/11 reports) ---
      { category: "Account Persistence", name: "User Account Created", eventIds: ["4720"], channels: ["security"], severity: "high",
        extractors: { targetUser: [P("TargetUserName"), P("Target_User_Name")], subjectUser: [P("SubjectUserName")], samAccountName: [P("SamAccountName"), P("SAMAccountName")] },
        topFields: ["targetUser", "subjectUser", "samAccountName"], payloadFilter: null },
      { category: "Account Persistence", name: "Member Added to Global Security Group", eventIds: ["4728"], channels: ["security"], severity: "critical",
        extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName"), P("Member_Name")], subjectUser: [P("SubjectUserName")] },
        topFields: ["groupName", "memberName", "subjectUser"], payloadFilter: null },
      { category: "Account Persistence", name: "Member Added to Local Security Group", eventIds: ["4732"], channels: ["security"], severity: "high",
        extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName")], subjectUser: [P("SubjectUserName")] },
        topFields: ["groupName", "memberName", "subjectUser"], payloadFilter: null },
      { category: "Account Persistence", name: "Member Added to Universal Security Group", eventIds: ["4756"], channels: ["security"], severity: "critical",
        extractors: { groupName: [P("TargetUserName")], memberName: [P("MemberName")], subjectUser: [P("SubjectUserName")] },
        topFields: ["groupName", "memberName", "subjectUser"], payloadFilter: null },
      { category: "Account Persistence", name: "User Password Reset", eventIds: ["4724"], channels: ["security"], severity: "medium",
        extractors: { targetUser: [P("TargetUserName")], subjectUser: [P("SubjectUserName")] },
        topFields: ["targetUser", "subjectUser"], payloadFilter: null },
      { category: "Account Persistence", name: "User Account Changed", eventIds: ["4738"], channels: ["security"], severity: "high",
        extractors: {
          targetUser: [P("TargetUserName"), P("Target_User_Name")],
          subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
          samAccountName: [P("SamAccountName"), P("SAMAccountName")],
          scriptPath: [P("ScriptPath"), P("Script_Path")],
          userAccountControl: [P("UserAccountControl"), P("User_Account_Control"), P("NewUacValue")],
          homeDirectory: [P("HomeDirectory"), P("Home_Directory")],
          profilePath: [P("ProfilePath"), P("Profile_Path")],
          userParameters: [P("UserParameters"), P("User_Parameters")],
          primaryGroupId: [P("PrimaryGroupId"), P("Primary_Group_Id")],
          allowedToDelegateTo: [P("AllowedToDelegateTo"), P("Allowed_To_Delegate_To")],
        },
        topFields: ["targetUser", "subjectUser", "scriptPath", "userAccountControl"],
        payloadFilter: null },
      // --- Domain Persistence (AD object changes: 5136/5137/5141) ---
      { category: "Domain Persistence", name: "AD Object Modified", eventIds: ["5136"], channels: ["security"], severity: "high",
        extractors: {
          objectDN: [P("ObjectDN"), P("Object_DN")],
          objectClass: [P("ObjectClass"), P("Object_Class")],
          attributeName: [P("AttributeLDAPDisplayName"), P("Attribute_LDAP_Display_Name"), P("AttributeName")],
          attributeValue: [P("AttributeValue"), P("Attribute_Value")],
          operationType: [P("OperationType"), P("Operation_Type")],
          subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
        },
        topFields: ["objectDN", "attributeName", "attributeValue", "subjectUser"],
        payloadFilter: /(?:AdminSDHolder|CN=Policies|scriptPath|servicePrincipalName|userAccountControl|adminCount|member(?:Of)?|gPCFileSysPath|gPCMachineExtensionNames|gPCUserExtensionNames|msDS-AllowedToDelegateTo|msDS-KeyCredentialLink|SIDHistory|nTSecurityDescriptor)/i },
      { category: "Domain Persistence", name: "AD Object Created", eventIds: ["5137"], channels: ["security"], severity: "medium",
        extractors: {
          objectDN: [P("ObjectDN"), P("Object_DN")],
          objectClass: [P("ObjectClass"), P("Object_Class")],
          subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
        },
        topFields: ["objectDN", "objectClass", "subjectUser"],
        payloadFilter: /(?:AdminSDHolder|CN=Policies|groupPolicyContainer|trustedDomain|msDS-ManagedServiceAccount|msDS-GroupManagedServiceAccount)/i },
      { category: "Domain Persistence", name: "AD Object Deleted", eventIds: ["5141"], channels: ["security"], severity: "high",
        extractors: {
          objectDN: [P("ObjectDN"), P("Object_DN")],
          objectClass: [P("ObjectClass"), P("Object_Class")],
          subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
        },
        topFields: ["objectDN", "objectClass", "subjectUser"],
        payloadFilter: /(?:AdminSDHolder|CN=Policies|groupPolicyContainer|trustedDomain)/i },
      // --- Service start type change (7040): detect auto-start flipping ---
      { category: "Services", name: "Service StartType Changed", eventIds: ["7040"], channels: ["system"], severity: "high",
        extractors: { serviceName: [P("param1"), P("ServiceName"), P("Name")], oldStartType: [P("param2"), P("OldStartType")], newStartType: [P("param3"), P("NewStartType")] },
        topFields: ["serviceName", "oldStartType", "newStartType"], payloadFilter: null },
      // --- Security 4702: Scheduled task updated (Security log fallback for 140) ---
      { category: "Scheduled Tasks", name: "Task Updated (Security)", eventIds: ["4702"], channels: ["security"], severity: "medium",
        extractors: { taskName: [P("Task"), P("TaskName"), P("Task Name")], command: [P("Command"), P("Actions")] },
        topFields: ["taskName", "command"], payloadFilter: null },
      // --- Security 4657: Registry audit fallback when Sysmon 12/13/14 are absent ---
      { category: "Registry Autorun", name: "Registry Value Modified (4657)", eventIds: ["4657"], channels: ["security"], severity: "high",
        extractors: {
          targetObject: [P("ObjectName"), P("Object Name")],
          valueName: [P("ObjectValueName"), P("Object Value Name")],
          newValue: [P("NewValue"), P("New Value")],
          oldValue: [P("OldValue"), P("Old Value")],
          image: [P("ProcessName"), P("Process Name"), P("SubjectProcessName")],
          subjectUser: [P("SubjectUserName"), P("Subject_User_Name")],
        },
        topFields: ["targetObject", "valueName", "newValue", "image"],
        payloadFilter: /\\(?:Run|RunOnce|RunServices|Services\\[^\\]*\\(?:ImagePath|Parameters|ServiceDll|FailureCommand)|Winlogon\\(?:Shell|Userinit|Notify|Taskman|VmApplet|AppSetup)|AppInit_DLLs|LoadAppInit_DLLs|Image File Execution Options\\[^\\]*\\Debugger|CurrentVersion\\Explorer\\(?:Shell|User Shell)|Session Manager\\(?:BootExecute|SetupExecute|AppCertDlls)|InprocServer32|LocalServer32|ShellIconOverlay|ShellServiceObjectDelayLoad|ContextMenuHandler|Browser Helper|Active Setup|Print\\Monitors|NetworkProvider|Lsa\\|WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|RunOnceEx)|SilentProcessExit\\|Environment\\(?:$|\\)|Credential Provid|PLAP Providers\\|Command Processor\\|Microsoft\\Netsh)/i },
    ];

    const REGISTRY_RULES = [
      { category: "Run Keys", name: "Run/RunOnce Autostart", severity: "high", description: "Standard autorun registry key",
        keyPathPattern: /\\(?:Software|SOFTWARE)\\(?:Microsoft\\Windows\\CurrentVersion|WOW6432Node\\Microsoft\\Windows\\CurrentVersion)\\(?:Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Policies\\Explorer\\Run)(?:\\|$)/i, valueNameFilter: null },
      { category: "Services", name: "Service ImagePath/ServiceDll", severity: "high", description: "Service executable or DLL path",
        keyPathPattern: /\\(?:SYSTEM|System)\\(?:CurrentControlSet|ControlSet\d+)\\Services\\[^\\]+(?:\\Parameters)?$/i,
        valueNameFilter: /^(ImagePath|ServiceDll|FailureCommand)$/i },
      { category: "Winlogon", name: "Winlogon Shell/Userinit", severity: "critical", description: "Login-triggered execution via Winlogon",
        keyPathPattern: /\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon$/i, valueNameFilter: /^(Shell|Userinit|Notify|VmApplet|AppSetup|Taskman)$/i },
      { category: "AppInit DLLs", name: "AppInit_DLLs", severity: "critical", description: "DLL injection on every user-mode process",
        keyPathPattern: /\\Microsoft\\Windows NT\\CurrentVersion\\Windows$/i, valueNameFilter: /^(AppInit_DLLs|LoadAppInit_DLLs)$/i },
      { category: "IFEO", name: "Image File Execution Options Debugger", severity: "critical", description: "Debugger hijacking of executable launch",
        keyPathPattern: /\\Image File Execution Options\\[^\\]+$/i, valueNameFilter: /^(Debugger|GlobalFlag)$/i },
      { category: "COM Hijacking", name: "COM Object Server", severity: "high", description: "COM object DLL/executable hijacking",
        keyPathPattern: /\\(?:InprocServer32|LocalServer32|InprocHandler32)$/i, valueNameFilter: null },
      { category: "Shell Extensions", name: "Shell Extension Handler", severity: "medium", description: "Explorer shell extension persistence",
        keyPathPattern: /\\(?:ShellIconOverlayIdentifiers|ContextMenuHandlers|PropertySheetHandlers|ColumnHandlers|CopyHookHandlers|DragDropHandlers|ShellExecuteHooks)\\[^\\]+$/i, valueNameFilter: null },
      { category: "Boot Execute", name: "Session Manager BootExecute", severity: "critical", description: "Pre-boot execution before Windows starts",
        keyPathPattern: /\\(?:Session Manager)$/i, valueNameFilter: /^(BootExecute|SetupExecute|Execute)$/i },
      { category: "BHO", name: "Browser Helper Object", severity: "medium", description: "Browser helper object (IE/Edge extension)",
        keyPathPattern: /\\Browser Helper Objects\\{[0-9a-fA-F-]+}$/i, valueNameFilter: null },
      { category: "LSA", name: "LSA Security/Auth Packages", severity: "critical", description: "Credential interception via LSA packages",
        keyPathPattern: /\\(?:Control\\)?Lsa(?:\\OSConfig)?$/i, valueNameFilter: /^(Security Packages|Authentication Packages|Notification Packages)$/i },
      { category: "Print Monitors", name: "Print Monitor DLL", severity: "high", description: "Spooler-based persistence via print monitor",
        keyPathPattern: /\\Print\\Monitors\\[^\\]+$/i, valueNameFilter: /^Driver$/i },
      { category: "Active Setup", name: "Active Setup StubPath", severity: "high", description: "Per-user execution on first login",
        keyPathPattern: /\\Active Setup\\Installed Components\\{[0-9a-fA-F-]+}$/i, valueNameFilter: /^StubPath$/i },
      { category: "Startup Folder", name: "Startup Folder Registry Path", severity: "high", description: "Startup folder path redirection",
        keyPathPattern: /\\Explorer\\(?:User Shell Folders|Shell Folders)$/i, valueNameFilter: /Startup/i },
      { category: "Scheduled Tasks (Reg)", name: "Scheduled Task in Registry", severity: "medium", description: "Task definition stored in registry",
        keyPathPattern: /\\Schedule\\TaskCache\\(?:Tasks|Tree)\\?/i, valueNameFilter: null },
      { category: "Network Providers", name: "Network Provider Order", severity: "high", description: "Network login interception via custom provider",
        keyPathPattern: /\\NetworkProvider\\Order$/i, valueNameFilter: /^ProviderOrder$/i },
      { category: "Logon Script", name: "User Logon Script (Environment)", severity: "high", description: "Per-user logon script via Environment key",
        keyPathPattern: /\\Environment$/i, valueNameFilter: /^UserInitMprLogonScript$/i },
      { category: "AppCert DLLs", name: "AppCert DLL", severity: "critical", description: "DLL loaded into every process that calls Win32 API CreateProcess",
        keyPathPattern: /\\Session Manager\\AppCertDlls$/i, valueNameFilter: null },
      { category: "Silent Process Exit", name: "Silent Process Exit Monitor", severity: "critical", description: "Execution triggered by monitored process termination",
        keyPathPattern: /\\SilentProcessExit\\[^\\]+$/i, valueNameFilter: /^(MonitorProcess|ReportingMode|IgnoreSelfExits)$/i },
      { category: "Credential Providers", name: "Credential Provider Registration", severity: "high", description: "Custom credential provider DLL for login interception",
        keyPathPattern: /\\Authentication\\(?:Credential Providers|Credential Provider Filters|PLAP Providers)\\{[0-9a-fA-F-]+}$/i, valueNameFilter: null },
      { category: "Command Processor", name: "Command Processor AutoRun", severity: "high", description: "cmd.exe startup command persistence",
        keyPathPattern: /\\Command Processor$/i, valueNameFilter: /^AutoRun$/i },
      { category: "Explorer Autoruns", name: "ShellServiceObjectDelayLoad", severity: "high", description: "Explorer-triggered DLL persistence via ShellServiceObjectDelayLoad",
        keyPathPattern: /\\ShellServiceObjectDelayLoad$/i, valueNameFilter: null },
      { category: "Netsh Helper DLLs", name: "Netsh Helper DLL", severity: "high", description: "Netsh helper DLL persistence",
        keyPathPattern: /\\Microsoft\\Netsh$/i, valueNameFilter: null },
    ];

    // --- Apply user rule customization ---
    const disabledRules = new Set(options.disabledRules || []);
    let activeEvtxRules = EVTX_RULES.filter((_, i) => !disabledRules.has(`evtx-${i}`));
    let activeRegRules = REGISTRY_RULES.filter((_, i) => !disabledRules.has(`reg-${i}`));

    if (options.customRules?.length) {
      for (const cr of options.customRules) {
        if (cr.type === "evtx") {
          activeEvtxRules.push({
            category: cr.category || "Custom",
            name: cr.name || "Custom Rule",
            eventIds: (cr.eventIds || "").split(",").map(s => s.trim()).filter(Boolean),
            channels: (cr.channels || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean),
            severity: cr.severity || "medium",
            extractors: {},
            topFields: [],
            payloadFilter: cr.payloadFilter ? new RegExp(cr.payloadFilter, "i") : null,
          });
        } else if (cr.type === "registry") {
          activeRegRules.push({
            category: cr.category || "Custom",
            name: cr.name || "Custom Rule",
            severity: cr.severity || "medium",
            description: cr.description || "User-defined rule",
            keyPathPattern: new RegExp(cr.keyPathPattern || ".*", "i"),
            valueNameFilter: cr.valueNameFilter ? new RegExp(cr.valueNameFilter, "i") : null,
          });
        }
      }
    }

    // --- Column mapping ---
    const userCols = options.columns || {};
    let columns;
    if (mode === "evtx") {
      columns = {
        eventId: userCols.eventId || detect([/^EventI[dD]$/i, /^event_id$/i, ...(isChainsaw ? [/^id$/i] : [])]),
        channel: userCols.channel || detect([/^Channel$/i, /^SourceName$/i, /^Provider$/i]),
        ts: userCols.ts || detect([/^TimeCreated$/i, /^datetime$/i, /^UtcTime$/i, /^Timestamp$/i, ...(isChainsaw ? [/^system_time$/i] : [])]),
        computer: userCols.computer || detect([/^Computer$/i, /^ComputerName$/i, /^Hostname$/i, ...(isChainsaw ? [/^computer_name$/i] : [])]),
        payload: detect([/^PayloadData1$/i]),
        payload2: detect([/^PayloadData2$/i]),
        payload3: detect([/^PayloadData3$/i]),
        payload4: detect([/^PayloadData4$/i]),
        payload5: detect([/^PayloadData5$/i]),
        payload6: detect([/^PayloadData6$/i]),
        mapDesc: detect([/^MapDescription$/i]),
        execInfo: detect([/^ExecutableInfo$/i]),
        details: detect([/^Details$/i, ...(isChainsaw ? [/^Event\.EventData\.Details$/i] : [])]),
        extra: detect([/^ExtraFieldInfo$/i]),
        ruleTitle: detect([/^RuleTitle$/i, ...(isChainsaw ? [/^detection_rules$/i] : [])]),
        user: userCols.user || detect([/^UserName$/i, /^User$/i, ...(isChainsaw ? [/^target_username$/i] : [])]) || (isHayabusa ? detect([/^ExtraFieldInfo$/i, /^Details$/i]) : null),
        targetObject: detect([/^TargetObject$/i, /^target_object$/i, /^Event\.EventData\.TargetObject$/i]),
        targetFilename: detect([/^TargetFilename$/i, /^Event\.EventData\.TargetFilename$/i]),
        image: detect([/^Image$/i, /^process_name$/i, /^Event\.EventData\.Image$/i, /^image$/i]),
        cmdLine: detect([/^CommandLine$/i, /^command_line$/i, /^Event\.EventData\.CommandLine$/i]),
        workstation: detect([/^WorkstationName$/i, /^workstation_name$/i]),
        source: detect([/^IpAddress$/i, /^SourceNetworkAddress$/i, /^SourceAddress$/i, /^source_ip$/i]),
        logonType: detect([/^LogonType$/i, /^logon_type$/i]),
      };
    } else {
      columns = {
        keyPath: userCols.keyPath || detect([/^KeyPath$/i, /^Key ?Path$/i]),
        valueName: userCols.valueName || detect([/^ValueName$/i, /^Value ?Name$/i]),
        valueData: userCols.valueData || detect([/^ValueData$/i, /^Value ?Data$/i]),
        valueData2: detect([/^ValueData2$/i]),
        valueData3: detect([/^ValueData3$/i]),
        valueType: detect([/^ValueType$/i, /^Value ?Type$/i]),
        hivePath: detect([/^HivePath$/i, /^Hive ?Path$/i]),
        ts: userCols.ts || detect([/^LastWriteTimestamp$/i, /^Timestamp$/i, /^datetime$/i, /^TimeCreated$/i]),
      };
    }

    // --- Build SQL query ---
    const params = [];
    const whereConditions = [];

    // EVTX pre-filter: only relevant Event IDs
    const ALL_EVTX_EIDS = [...new Set(activeEvtxRules.flatMap(r => r.eventIds))];
    if (mode === "evtx" && columns.eventId) {
      const safeEid = meta.colMap[columns.eventId];
      if (safeEid) {
        whereConditions.push(`${safeEid} IN (${ALL_EVTX_EIDS.map(() => "?").join(",")})`);
        params.push(...ALL_EVTX_EIDS);
      }
    }

    // Apply standard filters
    this._applyStandardFilters(options, meta, whereConditions, params);

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

    // Non-EID scope filters (column, checkbox, date, bookmark, search, advanced) — reused by correlation queries
    // The first condition may be an EID IN(...) pre-filter when mode=evtx; skip it to get only analyst scope filters
    const _eidCondCount = (mode === "evtx" && columns.eventId && meta.colMap[columns.eventId]) ? 1 : 0;
    const scopeConditions = whereConditions.slice(_eidCondCount);
    const scopeParams = params.slice(_eidCondCount ? ALL_EVTX_EIDS.length : 0);

    const selectParts = ["data.rowid as _rowid"];
    for (const [key, colName] of Object.entries(columns)) {
      if (colName && meta.colMap[colName]) selectParts.push(`${meta.colMap[colName]} as [${key}]`);
    }

    const orderCol = columns.ts ? meta.colMap[columns.ts] : null;
    const orderClause = orderCol ? `ORDER BY ${orderCol} ASC` : "ORDER BY data.rowid ASC";

    // --- Normalization helpers for correlation ---
    const _normSvcName = (s) => (s || "").replace(/"/g, "").trim().toLowerCase();
    // Well-known Windows service name ↔ display name aliases (7036 uses display name, 7045 uses service name)
    const SVC_DISPLAY_ALIASES = {
      "termservice": "remote desktop services", "remote desktop services": "termservice",
      "mpssvc": "windows defender firewall", "windows defender firewall": "mpssvc",
      "windefend": "microsoft defender antivirus service", "microsoft defender antivirus service": "windefend",
      "wuauserv": "windows update", "windows update": "wuauserv",
      "bits": "background intelligent transfer service", "background intelligent transfer service": "bits",
      "spooler": "print spooler", "print spooler": "spooler",
      "winmgmt": "windows management instrumentation", "windows management instrumentation": "winmgmt",
      "schedule": "task scheduler", "task scheduler": "schedule",
      "eventlog": "windows event log", "windows event log": "eventlog",
      "lanmanserver": "server", "lanmanworkstation": "workstation",
      "server": "lanmanserver", "workstation": "lanmanworkstation",
      "w32time": "windows time", "windows time": "w32time",
      "dnscache": "dns client", "dns client": "dnscache",
      "cryptsvc": "cryptographic services", "cryptographic services": "cryptsvc",
      "samss": "security accounts manager", "security accounts manager": "samss",
      "netlogon": "netlogon", "lmhosts": "tcp/ip netbios helper", "tcp/ip netbios helper": "lmhosts",
      "winsock": "winsock", "rpcss": "remote procedure call (rpc)", "remote procedure call (rpc)": "rpcss",
      "plugplay": "plug and play", "plug and play": "plugplay",
      "themes": "themes", "appinfo": "application information", "application information": "appinfo",
    };
    const _parseExePath = (cmd) => {
      if (!cmd) return null;
      const c = cmd.replace(/^"|"$/g, "").trim();
      if (!c) return null;
      const quoted = cmd.match(/^"([^"]+)"/);
      const imagePath = (quoted ? quoted[1] : c.split(/\s+/)[0]).trim();
      const imageBase = imagePath.split("\\").pop().toLowerCase();
      return { fullCmd: c, imagePath: imagePath.toLowerCase(), imageBase };
    };
    const COMMON_SYSTEM_BINS = new Set([
      "svchost.exe", "rundll32.exe", "dllhost.exe", "msiexec.exe",
      "taskhostw.exe", "conhost.exe", "lsass.exe", "csrss.exe",
      "smss.exe", "services.exe", "winlogon.exe", "explorer.exe",
      "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
      "cscript.exe", "mshta.exe", "regsvr32.exe", "wuauclt.exe",
      "spoolsv.exe", "searchindexer.exe", "wmiprvse.exe",
    ]);
    const CORR_WINDOW = 3600000;       // 60 min
    const CORR_WINDOW_EXT = 43200000;  // 12 hours (lower confidence)
    const _withinWindow = (ts1, ts2, window) => {
      const d1 = new Date(ts1), d2 = new Date(ts2);
      if (isNaN(d1) || isNaN(d2)) return false;
      const diff = d2 - d1;
      return diff >= 0 && diff <= window;
    };
    const _withinWindowBidi = (ts1, ts2, window) => _withinWindow(ts1, ts2, window) || _withinWindow(ts2, ts1, window);
    const _corrHost = (value) => this._cleanWrappedField(value).toUpperCase();
    const _corrUser = (value) => this._cleanWrappedField(value);

    // --- PowerShell 4104 Script Block persistence patterns ---
    const PS_4104_PATTERNS = [
      { category: "Scheduled Tasks", name: "PS Task Creation",
        pattern: /(?:Register-ScheduledTask|New-ScheduledTask|schtasks\s*(?:\.exe)?\s*\/create)/i,
        extractName: /(?:Register-ScheduledTask|New-ScheduledTask)\s[^|]*?(?:-TaskName|-tn)\s+["']?([^\s"'|]+)/i },
      { category: "Services", name: "PS Service Creation",
        pattern: /(?:New-Service|sc(?:\.exe)?\s+create|Set-Service|Set-ItemProperty\s[^|]*?\\Services\\)/i,
        extractName: /(?:New-Service\s[^|]*?-Name\s+["']?([^\s"'|]+)|sc(?:\.exe)?\s+create\s+["']?([^\s"'|]+))/i },
      { category: "Registry Autorun", name: "PS Registry Autorun",
        pattern: /(?:Set-ItemProperty|New-ItemProperty|reg\s+add)\s[^|]*?\\(?:Run|RunOnce)(?:\\|["'\s]|$)/i,
        extractName: /\\(Run(?:Once)?)/i },
      { category: "WMI Persistence", name: "PS WMI Persistence",
        pattern: /(?:Register-WmiEvent|Set-WmiInstance|Register-CimIndicationEvent|__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding)/i,
        extractName: /(?:-Name\s+["']?([^\s"'|]+)|__EventFilter.*?Name\s*=\s*["']?([^\s"'|]+))/i },
      { category: "Startup Folder", name: "PS Startup Folder Write",
        pattern: /(?:Copy-Item|Move-Item|Out-File|Set-Content|Add-Content|New-Item)\s[^|]*?(?:Start\s*Menu\\Programs\\Startup|\\Startup\\)/i,
        extractName: null },
      { category: "IFEO", name: "PS IFEO/AppInit Modification",
        pattern: /(?:Image\s+File\s+Execution\s+Options|AppInit_DLLs)/i,
        extractName: /Image\s+File\s+Execution\s+Options\\([^\s"'\\]+)/i },
    ];
    const PS_4104_SUSPICIOUS_INDICATORS = [
      { pattern: /-(?:Encoded)?Command\s|-[eE]nc?\s|-[eE]\s/i, label: "EncodedCommand" },
      { pattern: /\[Convert\]::FromBase64String|FromBase64/i, label: "FromBase64String" },
      { pattern: /Invoke-Expression|\.Invoke\(|iex\s/i, label: "Invoke-Expression" },
      { pattern: /DownloadString|DownloadFile|DownloadData/i, label: "DownloadString" },
      { pattern: /Net\.WebClient|System\.Net\.WebClient|New-Object\s+Net\.WebClient/i, label: "Net.WebClient" },
      { pattern: /Start-BitsTransfer|BitsTransfer/i, label: "Start-BitsTransfer" },
      { pattern: /Invoke-WebRequest|wget\s|curl\s|iwr\s/i, label: "Web download" },
      { pattern: /\[Reflection\.Assembly\]::Load|Assembly\.Load/i, label: "Assembly loading" },
      { pattern: /Add-MpPreference\s[^|]*?-ExclusionPath/i, label: "Defender exclusion" },
      { pattern: /Set-MpPreference\s[^|]*?-DisableRealtimeMonitoring/i, label: "Defender disable" },
    ];
    const PS_4104_ALLOWLIST_PATHS = /(?:Microsoft\\Configuration\s*Manager|SCCM|CCM\\|Intune\\|Microsoft\s+Intune|sysvol\\|Group\s*Policy|\\Policies\\|Windows\s*Defender\\|MpCmdRun|AMSI|Sophos\\|CrowdStrike\\|SentinelOne\\|CarbonBlack\\|Cortex\s*XDR)/i;
    const PS_4104_ALLOWLIST_SCRIPTS = /(?:(?:Microsoft|Windows)\\(?:Azure|Intune|SCCM|ConfigMgr)|(?:chocolatey|nuget|pester|psake|platyPS|PSReadLine|PackageManagement|PowerShellGet)\\)/i;

    try {
      const maxRows = 500000;
      const sql = `SELECT ${selectParts.join(", ")} FROM data ${whereClause} ${orderClause} LIMIT ${maxRows}`;
      const rows = db.prepare(sql).all(...params);

      let items = [];
      const warnings = [];
      let ps4104CorrelatedCount = 0;
      const ps4104Reassembled = [];
      const ps4104ByTask = {}, ps4104BySvc = {}, ps4104ByRegKey = {}, ps4104ByWmi = {};

      if (mode === "evtx") {
        // Build EID→rules lookup map for O(1) rule dispatch per row
        // instead of iterating all ~30 rules for every row
        const eidRuleMap = new Map();
        for (const rule of activeEvtxRules) {
          for (const eid of rule.eventIds) {
            if (!eidRuleMap.has(eid)) eidRuleMap.set(eid, []);
            eidRuleMap.get(eid).push(rule);
          }
        }

        // Pre-hoist constant regex (avoid re-creation per row)
        const RMM_PATTERNS = /anydesk|splashtop|rustdesk|atera|screenconnect|teamviewer|supremo|connectwise|bomgar|logmein/i;

        for (const row of rows) {
          const eid = String(row.eventId || "").trim();
          // O(1) lookup: skip rows whose EID has no matching rules
          const rulesForEid = eidRuleMap.get(eid);
          if (!rulesForEid) continue;

          const haystack = this._buildEvtxHaystack(row);
          const compact = this._parseCompactKeyValues(row.details, row.extra);
          const rowChannel = this._resolveEventChannel(row);
          const eventUser = (() => {
            const rawUser = row.user || this._compactGet(compact, "SubjectUserName", "TargetUserName", "TgtUser", "User", "SrcUser");
            const cleaned = rawUser && rawUser.includes("\\") ? rawUser.split("\\").pop() : rawUser;
            return this._cleanWrappedField(cleaned);
          })();
          for (const rule of rulesForEid) {
            // Channel filter: rule.channels contains substrings to match (e.g., "system", "security", "taskscheduler", "sysmon")
            if (rule.channels && !this._evtxChannelMatches(rowChannel, rule.channels)) continue;
            if (rule.payloadFilter && !rule.payloadFilter.test(haystack)) continue;

            const details = {};
            for (const [field, patterns] of Object.entries(rule.extractors || {})) {
              for (const pat of patterns) {
                const m = haystack.match(pat);
                if (m) { details[field] = m[1].trim(); break; }
              }
            }

            // Pull ExecutableInfo column directly into named field as fallback
            // useExecInfo can be true (maps to "executable") or a string (specific field name)
            if (rule.useExecInfo && row.execInfo) {
              const targetField = typeof rule.useExecInfo === "string" ? rule.useExecInfo : "executable";
              if (!details[targetField]) {
                details[targetField] = row.execInfo.trim();
              }
            }

            // Build summary from topFields (most relevant info first), fall back to raw payload
            let detailsSummary = "";
            const topFields = rule.topFields || Object.keys(rule.extractors || {});
            const topParts = topFields.map((f) => details[f] ? `${f}: ${details[f]}` : null).filter(Boolean);
            if (topParts.length > 0) {
              detailsSummary = topParts.join(" | ");
            } else {
              // No extractors matched — show raw payload data for context
              detailsSummary = haystack;
            }

            // RMM tool detection for service installs (seen in 7/11 DFIR reports)
            const rmmMatch = (eid === "7045" || eid === "4697") && (RMM_PATTERNS.test(details.serviceName || "") || RMM_PATTERNS.test(details.imagePath || "") || RMM_PATTERNS.test(row.execInfo || ""));
            const tags = rmmMatch ? ["RMM Tool"] : [];

            // Preserve raw payload for task items that need deep XML parsing (4698/4702/140)
            if ((eid === "4698" || eid === "4702" || eid === "140") && rule.category === "Scheduled Tasks") {
              details._rawPayload = haystack;
            }

            items.push({
              rowid: row._rowid,
              category: rule.category,
              name: rule.name,
              severity: rule.severity,
              description: rule.description,
              timestamp: this._cleanWrappedField(row.ts || ""),
              computer: this._cleanWrappedField(row.computer || ""),
              user: eventUser || "",
              source: `EventID ${eid}`,
              details,
              detailsSummary: detailsSummary.substring(0, 400),
              mode: "evtx",
              tags,
              rmmTool: rmmMatch,
            });
          }
        }
        // --- Post-process 4657 items: re-categorize by key path, set confidence ---
        for (const item of items) {
          if (item.name !== "Registry Value Modified (4657)") continue;
          const obj = item.details.targetObject || "";
          const vn = (item.details.valueName || "").toLowerCase();
          const nv = item.details.newValue || "";
          // If key path is missing or looks like a value name (no backslash), mark lower confidence
          if (!obj || !obj.includes("\\")) {
            item.confidence = "present";
            item.severity = "low";
            item.details._is4657Fallback = true;
            item.details._4657NoKeyPath = true;
            if (nv) item.command = nv;
            continue;
          }
          // Re-categorize based on actual key path
          if (/Image File Execution Options/i.test(obj)) {
            item.category = "IFEO"; item.severity = "critical";
          } else if (/AppInit_DLLs|LoadAppInit_DLLs/i.test(obj) || /^appinit_dlls$/i.test(vn)) {
            item.category = "AppInit DLLs"; item.severity = "critical";
          } else if (/\\Winlogon\\(?:Shell|Userinit|Notify)/i.test(obj)) {
            item.category = "Winlogon"; item.severity = "critical";
          } else if (/Session Manager\\(?:BootExecute|SetupExecute)/i.test(obj)) {
            item.category = "Boot Execute"; item.severity = "critical";
          } else if (/\\Services\\[^\\]+\\(?:ImagePath|Parameters|ServiceDll|FailureCommand)/i.test(obj)) {
            item.category = "Services"; item.severity = "high";
          } else if (/(?:InprocServer32|LocalServer32)/i.test(obj)) {
            item.category = "COM Hijacking"; item.severity = "high";
          } else if (/Print\\Monitors/i.test(obj)) {
            item.category = "Print Monitors"; item.severity = "high";
          } else if (/\\Lsa\\?$/i.test(obj)) {
            item.category = "LSA"; item.severity = "critical";
          } else if (/Active Setup/i.test(obj)) {
            item.category = "Active Setup"; item.severity = "high";
          } else if (/NetworkProvider/i.test(obj)) {
            item.category = "Network Providers"; item.severity = "high";
          } else if (/Browser Helper Objects/i.test(obj)) {
            item.category = "BHO"; item.severity = "medium";
          } else if (/SilentProcessExit\\/i.test(obj)) {
            item.category = "Silent Process Exit"; item.severity = "critical";
          } else if (/\\Environment/i.test(obj) && /UserInitMprLogonScript/i.test(vn)) {
            item.category = "Logon Script"; item.severity = "high";
          } else if (/AppCertDlls/i.test(obj)) {
            item.category = "AppCert DLLs"; item.severity = "critical";
          } else if (/Credential Provid/i.test(obj) || /PLAP Providers\\/i.test(obj)) {
            item.category = "Credential Providers"; item.severity = "high";
          } else if (/\\Command Processor/i.test(obj) && /^autorun$/i.test(vn)) {
            item.category = "Command Processor"; item.severity = "high";
          } else if (/ShellServiceObjectDelayLoad/i.test(obj)) {
            item.category = "Explorer Autoruns"; item.severity = "high";
          } else if (/\\Microsoft\\Netsh/i.test(obj)) {
            item.category = "Netsh Helper DLLs"; item.severity = "high";
          }
          // Set baseline confidence (lower than Sysmon 13)
          item.confidence = "likely";
          item.details._is4657Fallback = true;
          // Upgrade confidence on strong semantics
          const _nvHasLolbin = LOLBIN_PAT.test(nv);
          const _nvHasEncoded = /(?:base64|frombase64|-enc\s|-e\s|iex|invoke-expression|downloadstring|downloadfile|webclient|bitstransfer)/i.test(nv);
          if (_nvHasLolbin || _nvHasEncoded) item.confidence = "confirmed";
          if (/^debugger$/i.test(vn) && item.category === "IFEO") item.confidence = "confirmed";
          if (/^(appinit_dlls|loadappinit_dlls)$/i.test(vn)) item.confidence = "confirmed";
          if (/^(shell|userinit)$/i.test(vn) && item.category === "Winlogon") item.confidence = "confirmed";
          if (/^monitorprocess$/i.test(vn) && item.category === "Silent Process Exit") item.confidence = "confirmed";
          if (/^userinitmprologonscript$/i.test(vn) && item.category === "Logon Script") item.confidence = "confirmed";
          if (item.category === "AppCert DLLs" && nv) item.confidence = "confirmed";
          if (/^autorun$/i.test(vn) && item.category === "Command Processor") item.confidence = "confirmed";
          if (item.category === "Netsh Helper DLLs" && nv) item.confidence = "confirmed";
          // Map targetObject to artifact field for consistent display
          if (!item.artifact) item.artifact = obj;
          if (!item.command && nv) item.command = nv;
        }
      } else {
        // Registry mode
        // Helper: derive user and hive scope from hivePath
        const _hiveContext = (hp) => {
          if (!hp) return { user: "", hiveScope: "" };
          const h = hp.replace(/\\/g, "/");
          // NTUSER.DAT / UsrClass.dat → HKCU, extract username from path
          const userM = h.match(/[/\\]Users[/\\]([^/\\]+)[/\\]/i);
          if (/ntuser\.dat/i.test(h) || /usrclass\.dat/i.test(h)) {
            return { user: userM ? userM[1] : "", hiveScope: "HKCU" };
          }
          // SYSTEM hive
          if (/[/\\]config[/\\]SYSTEM$/i.test(h) || /[/\\]SYSTEM$/i.test(h)) return { user: "", hiveScope: "HKLM\\SYSTEM" };
          // SOFTWARE hive
          if (/[/\\]config[/\\]SOFTWARE$/i.test(h) || /[/\\]SOFTWARE$/i.test(h)) return { user: "", hiveScope: "HKLM\\SOFTWARE" };
          // SAM hive
          if (/[/\\]config[/\\]SAM$/i.test(h)) return { user: "", hiveScope: "HKLM\\SAM" };
          // SECURITY hive
          if (/[/\\]config[/\\]SECURITY$/i.test(h)) return { user: "", hiveScope: "HKLM\\SECURITY" };
          // DEFAULT hive
          if (/[/\\]config[/\\]DEFAULT$/i.test(h)) return { user: "", hiveScope: "HKU\\.DEFAULT" };
          // Amcache
          if (/amcache/i.test(h)) return { user: "", hiveScope: "Amcache" };
          return { user: userM ? userM[1] : "", hiveScope: "" };
        };
        for (const row of rows) {
          const kp = row.keyPath || "";
          const vn = row.valueName || "";
          const vd = [row.valueData, row.valueData2, row.valueData3].filter(Boolean).join(" ");
          const hiveCtx = _hiveContext(row.hivePath);

          for (const rule of activeRegRules) {
            if (!rule.keyPathPattern.test(kp)) continue;
            if (rule.valueNameFilter && !rule.valueNameFilter.test(vn)) continue;

            items.push({
              rowid: row._rowid,
              category: rule.category,
              name: rule.name,
              severity: rule.severity,
              description: rule.description,
              timestamp: row.ts || "",
              computer: "",
              user: hiveCtx.user,
              source: "Registry",
              details: { keyPath: kp, valueName: vn, valueData: vd, hivePath: row.hivePath || "", hiveScope: hiveCtx.hiveScope },
              detailsSummary: `${vn}: ${vd}`.substring(0, 300),
              mode: "registry",
            });
          }
        }
      }

      // --- Cross-event correlation: enrich Task Registered/Updated with executable from Task Process Created/Action Started ---
      if (mode === "evtx") {
        const taskExecMap = {};
        for (const item of items) {
          if ((item.name === "Task Process Created" || item.name === "Task Action Started") && item.details.executable && item.details.taskName) {
            const tn = item.details.taskName;
            if (!taskExecMap[tn] || item.name === "Task Process Created") taskExecMap[tn] = item.details.executable;
          }
        }
        for (const item of items) {
          if ((item.name === "Task Registered" || item.name === "Task Updated" || item.name === "Task Updated (Security)") && !item.details.executable && item.details.taskName) {
            const exec = taskExecMap[item.details.taskName];
            if (exec) {
              item.details.executable = exec;
              // Rebuild summary with executable
              const topParts = ["taskName", "executable"].map((f) => item.details[f] ? `${f}: ${item.details[f]}` : null).filter(Boolean);
              if (topParts.length > 0) item.detailsSummary = topParts.join(" | ").substring(0, 400);
            }
          }
        }

        // --- Deep task XML semantics: parse hidden flag, run level, COM handler, trigger types ---
        // Works on 4698 (Task Created), 4702 (Task Updated Security), 140 (Task Updated Operational)
        for (const item of items) {
          if (item.category !== "Scheduled Tasks") continue;
          if (item.name !== "Scheduled Task Created" && item.name !== "Task Updated (Security)" && item.name !== "Task Updated") continue;
          // Prefer raw payload (full event text) over reduced summary for XML field extraction
          const raw = item.details._rawPayload || "";
          const fallback = (item.detailsSummary || "") + " " + JSON.stringify(item.details || {});
          const blob = raw || fallback;
          const hasRaw = !!raw;
          // Hidden flag: <Hidden>true</Hidden> or Hidden: true
          if (/<hidden>\s*true/i.test(blob) || /Hidden:\s*true/i.test(blob)) {
            item.details._taskHidden = true;
          }
          // Run level: <RunLevel>HighestAvailable</RunLevel> or RunLevel: HighestAvailable/LeastPrivilege
          const rlM = blob.match(/<RunLevel>\s*(\w+)/i) || blob.match(/RunLevel:\s*(\w+)/i);
          if (rlM) {
            item.details._taskRunLevel = rlM[1];
            if (/highest/i.test(rlM[1])) item.details._taskElevated = true;
          }
          // COM handler: <ComHandler> or ClassId: {GUID}
          if (/<ComHandler>/i.test(blob) || /ClassId:\s*\{[0-9a-f-]+\}/i.test(blob)) {
            item.details._taskComHandler = true;
          }
          // Trigger types: extract from <Triggers> block or flattened fields
          const triggers = [];
          if (/<BootTrigger>/i.test(blob) || /BootTrigger/i.test(blob))                   triggers.push("boot");
          if (/<LogonTrigger>/i.test(blob) || /LogonTrigger/i.test(blob))                 triggers.push("logon");
          if (/<RegistrationTrigger>/i.test(blob) || /RegistrationTrigger/i.test(blob))   triggers.push("registration");
          if (/<TimeTrigger>/i.test(blob) || /TimeTrigger/i.test(blob))                   triggers.push("time");
          if (/<CalendarTrigger>/i.test(blob) || /CalendarTrigger/i.test(blob))           triggers.push("calendar");
          if (/<IdleTrigger>/i.test(blob) || /IdleTrigger/i.test(blob))                   triggers.push("idle");
          if (/<EventTrigger>/i.test(blob) || /EventTrigger/i.test(blob))                 triggers.push("event");
          if (/<SessionStateChangeTrigger>/i.test(blob))                                   triggers.push("session");
          if (triggers.length > 0) item.details._taskTriggers = triggers;
          // Principal: extract UserId/GroupId if present
          const princM = blob.match(/<UserId>\s*([^<]+)/i) || blob.match(/UserId:\s*(\S+)/i);
          if (princM) item.details._taskPrincipal = princM[1].trim();
          // Extract action command from XML/flattened task content when the event payload includes task XML.
          const cmdM = blob.match(/<Command>\s*([^<]+)/i) || blob.match(/Command:\s*(.+?)(?:\s*\||\s*$)/i);
          const argM = blob.match(/<Arguments>\s*([^<]+)/i) || blob.match(/Arguments:\s*(.+?)(?:\s*\||\s*$)/i);
          if (cmdM) {
            const cmd = cmdM[1].trim();
            const args = argM ? argM[1].trim() : "";
            if (!item.details.executable) item.details.executable = cmd;
            if (!item.details.command) item.details.command = args ? `${cmd} ${args}`.trim() : cmd;
          }
          // Track whether we parsed from raw payload or partial text
          const anyFound = item.details._taskHidden || item.details._taskElevated || item.details._taskComHandler || (triggers.length > 0) || item.details._taskPrincipal || item.details.command || item.details.executable;
          if (anyFound && !hasRaw) item.details._taskXmlPartial = true;
          if (item.details.taskName && (item.details.command || item.details.executable)) {
            const topParts = ["taskName", "command", "executable"].map((f) => item.details[f] ? `${f}: ${item.details[f]}` : null).filter(Boolean);
            if (topParts.length > 0) item.detailsSummary = topParts.join(" | ").substring(0, 400);
          }
          // Clean up raw payload to avoid it leaking to frontend detail panel
          delete item.details._rawPayload;
        }

        // --- Correlation query: fetch EID 7036/7035 (service state), Sysmon 1 (proc create), 4688 (proc create) ---
        const svcStartEvents = [];
        const svcControlEvents = []; // 7035: service control manager requests (start/stop)
        const procStartEvents = [];
        const CORR_EIDS = ["7036", "7035", "1", "4688"];
        if (columns.eventId && meta.colMap[columns.eventId]) {
          const safeEidCol = meta.colMap[columns.eventId];
          const corrWhere = [`${safeEidCol} IN (${CORR_EIDS.map(() => "?").join(",")})`, ...scopeConditions];
          const corrParams = [...CORR_EIDS, ...scopeParams];
          const corrSql = `SELECT ${selectParts.join(", ")} FROM data WHERE ${corrWhere.join(" AND ")} ${orderClause} LIMIT 200000`;
          try {
            const corrRows = db.prepare(corrSql).all(...corrParams);
            for (const row of corrRows) {
              const eid = String(row.eventId || "").trim();
              const ch = this._resolveEventChannel(row);
              const haystack = this._buildEvtxHaystack(row);
              // System 7036: service entered running state
              if (eid === "7036" && this._evtxChannelMatches(ch, ["system"])) {
                const m = haystack.match(/(?:param1|ServiceName|Service Name):\s*(.+?)(?:\s*$|\s*\|)/i);
                const isRunning = /running/i.test(haystack);
                if (m && isRunning) {
                  const rawName = _normSvcName(m[1]);
                  const aliasName = SVC_DISPLAY_ALIASES[rawName] || null;
                  svcStartEvents.push({ svcName: rawName, aliasName, timestamp: row.ts || "", computer: _corrHost(row.computer || "") });
                }
              }
              // System 7035: service control request (start/stop/pause)
              if (eid === "7035" && this._evtxChannelMatches(ch, ["system"])) {
                const m = haystack.match(/(?:param1|ServiceName|Service Name):\s*(.+?)(?:\s*$|\s*\|)/i);
                const ctrlM = haystack.match(/(?:param2|Control):\s*(.+?)(?:\s*$|\s*\|)/i);
                if (m) {
                  const rawName = _normSvcName(m[1]);
                  const aliasName = SVC_DISPLAY_ALIASES[rawName] || null;
                  const controlType = (ctrlM ? ctrlM[1].trim().toLowerCase() : "");
                  svcControlEvents.push({ svcName: rawName, aliasName, controlType, timestamp: row.ts || "", computer: _corrHost(row.computer || "") });
                }
              }
              // Sysmon 1: process creation
              if (eid === "1" && this._evtxChannelMatches(ch, ["sysmon"])) {
                const imgM = haystack.match(/Image:\s*(.+?)(?:\s*$|\s*\|)/i);
                const parM = haystack.match(/ParentImage:\s*(.+?)(?:\s*$|\s*\|)/i);
                if (imgM) {
                  const p = _parseExePath(imgM[1]);
                  const pp = parM ? _parseExePath(parM[1]) : null;
                  if (p) procStartEvents.push({ ...p, parentImage: pp?.imagePath || "", parentBase: pp?.imageBase || "", timestamp: row.ts || "", computer: _corrHost(row.computer || "") });
                }
              }
              // Security 4688: process creation
              if (eid === "4688" && this._evtxChannelMatches(ch, ["security"])) {
                const imgM = haystack.match(/(?:NewProcessName|Process Name|New Process Name):\s*(.+?)(?:\s*$|\s*\|)/i);
                const parM = haystack.match(/(?:ParentProcessName|Creator Process Name):\s*(.+?)(?:\s*$|\s*\|)/i);
                if (imgM) {
                  const p = _parseExePath(imgM[1]);
                  const pp = parM ? _parseExePath(parM[1]) : null;
                  if (p) procStartEvents.push({ ...p, parentImage: pp?.imagePath || "", parentBase: pp?.imageBase || "", timestamp: row.ts || "", computer: _corrHost(row.computer || "") });
                }
              }
            }
          } catch (_corrErr) { /* correlation query may fail on non-EVTX datasets — silently skip */ }
        }

        // --- PowerShell 4104 Script Block Logging: separate query + fragment reassembly ---
        const ps4104Fragments = [];
        if (columns.eventId && meta.colMap[columns.eventId]) {
          const safeEidCol = meta.colMap[columns.eventId];
          const ps4104Where = [`${safeEidCol} IN (?)`, ...scopeConditions];
          const ps4104Params = ["4104", ...scopeParams];
          const ps4104MaxRows = Math.max(10000, Math.min(Number(options.ps4104MaxRows) || 250000, 1000000));
          const ps4104PageSize = Math.max(1000, Math.min(Number(options.ps4104PageSize) || 20000, 100000));
          try {
            let lastRid = 0;
            let fetched = 0;
            while (fetched < ps4104MaxRows) {
              const chunk = Math.min(ps4104PageSize, ps4104MaxRows - fetched);
              const ps4104Sql = `SELECT ${selectParts.join(", ")} FROM data WHERE ${ps4104Where.join(" AND ")} AND data.rowid > ? ORDER BY data.rowid ASC LIMIT ${chunk}`;
              const ps4104Rows = db.prepare(ps4104Sql).all(...ps4104Params, lastRid);
              if (ps4104Rows.length === 0) break;
              for (const row of ps4104Rows) {
                const ch = this._resolveEventChannel(row);
                if (!this._evtxChannelMatches(ch, ["powershell"])) continue;
                const haystack = this._buildEvtxHaystack(row);
                const scriptTextM = haystack.match(/ScriptBlockText:\s*(.+?)(?:\s*\||\s*$)/i);
                const scriptIdM = haystack.match(/ScriptBlockId:\s*([0-9a-f-]+)/i);
                const msgNumM = haystack.match(/MessageNumber:\s*(\d+)/i);
                const msgTotalM = haystack.match(/MessageTotal:\s*(\d+)/i);
                const pathM = haystack.match(/Path:\s*(.+?)(?:\s*\||\s*$)/i);
                const hostAppM = haystack.match(/HostApplication:\s*(.+?)(?:\s*\||\s*$)/i);
                ps4104Fragments.push({
                  rowid: row._rowid, scriptBlockId: scriptIdM ? scriptIdM[1].toLowerCase() : `orphan-${row._rowid}`,
                  messageNumber: msgNumM ? parseInt(msgNumM[1], 10) : 1, messageTotal: msgTotalM ? parseInt(msgTotalM[1], 10) : 1,
                  scriptText: scriptTextM ? scriptTextM[1] : "", path: pathM ? pathM[1].trim() : "",
                  hostApplication: hostAppM ? hostAppM[1].trim() : (row.execInfo || "").trim(),
                  timestamp: row.ts || "", computer: _corrHost(row.computer || ""), user: _corrUser(row.user || ""),
                });
              }
              fetched += ps4104Rows.length;
              lastRid = Number(ps4104Rows[ps4104Rows.length - 1]._rowid || lastRid);
              if (ps4104Rows.length < chunk) break;
            }
            if (fetched >= ps4104MaxRows) warnings.push(`PowerShell 4104 scan hit configured limit ${ps4104MaxRows} — increase options.ps4104MaxRows for fuller coverage.`);
          } catch (_ps4104Err) { warnings.push("PowerShell 4104 query failed: " + _ps4104Err.message); }
        }

        // --- 4104 Fragment Reassembly ---
        {
          const PS4104_TIME_GAP = 300000; // 5 min — separate executions of the same script block
          const fragGroups = {};
          for (const frag of ps4104Fragments) {
            const gk = `${frag.scriptBlockId}|${frag.computer}|${frag.user}`;
            if (!fragGroups[gk]) fragGroups[gk] = [];
            fragGroups[gk].push(frag);
          }
          // Helper: process a single run of fragments into a reassembled object (or skip)
          const _processRun = (frags) => {
            frags.sort((a, b) => a.messageNumber - b.messageNumber);
            const fullText = frags.map(f => f.scriptText).join("");
            const first = frags[0];
            const path = frags.find(f => f.path)?.path || "";
            const hostApp = frags.find(f => f.hostApplication)?.hostApplication || "";
            const matchedPatterns = [];
            let matchedCategory = null, matchedName = null, extractedArtifactName = null;
            for (const pat of PS_4104_PATTERNS) {
              if (pat.pattern.test(fullText)) {
                matchedPatterns.push(pat.name);
                if (!matchedCategory) { matchedCategory = pat.category; matchedName = pat.name; }
                if (pat.extractName) { const nameM = fullText.match(pat.extractName); if (nameM) extractedArtifactName = (nameM[1] || nameM[2] || "").trim(); }
              }
            }
            if (matchedPatterns.length === 0) return;
            const suspiciousIndicators = [];
            for (const ind of PS_4104_SUSPICIOUS_INDICATORS) { if (ind.pattern.test(fullText)) suspiciousIndicators.push(ind.label); }
            const isMgmtAllowlisted = PS_4104_ALLOWLIST_PATHS.test(path) || PS_4104_ALLOWLIST_PATHS.test(hostApp) || PS_4104_ALLOWLIST_SCRIPTS.test(path);
            // Keep allowlisted management scripts only when they still carry suspicious indicators.
            if (isMgmtAllowlisted && suspiciousIndicators.length === 0) return;
            ps4104Reassembled.push({
              scriptBlockId: first.scriptBlockId, computer: first.computer, user: first.user,
              timestamp: first.timestamp, path, hostApplication: hostApp, fullText,
              fragmentCount: frags.length, firstRowid: first.rowid,
              matchedCategory: matchedCategory || "PowerShell Persistence", matchedName: matchedName || "PowerShell Script Block",
              matchedPatterns, extractedArtifactName, suspiciousIndicators, mgmtAllowlisted: isMgmtAllowlisted,
            });
          };
          for (const [, frags] of Object.entries(fragGroups)) {
            // Sub-split by time gap: same scriptBlockId can represent repeated executions
            frags.sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0) || a.messageNumber - b.messageNumber);
            const runs = [[]];
            for (const frag of frags) {
              const curRun = runs[runs.length - 1];
              if (curRun.length > 0) {
                const prev = curRun[curRun.length - 1];
                const prevTs = new Date(prev.timestamp).getTime();
                const curTs = new Date(frag.timestamp).getTime();
                const hasTimeGap = !isNaN(prevTs) && !isNaN(curTs) && Math.abs(curTs - prevTs) > PS4104_TIME_GAP;
                // Only split on time gap if the current run is complete or the new fragment restarts at 1
                const runComplete = prev.messageNumber >= prev.messageTotal;
                const seqRestart = frag.messageNumber === 1;
                if (hasTimeGap && (runComplete || seqRestart)) {
                  runs.push([]);
                }
              }
              runs[runs.length - 1].push(frag);
            }
            for (const run of runs) _processRun(run);
          }
        }
        if (ps4104Fragments.length === 0 && columns.eventId) {
          warnings.push("No PowerShell 4104 (ScriptBlock) events found — PowerShell-based persistence detection unavailable.");
        }

        // --- Build 4104 correlation indexes ---
        for (const rs of ps4104Reassembled) {
          const host = rs.computer;
          if (rs.matchedCategory === "Scheduled Tasks" && rs.extractedArtifactName) {
            const key = rs.extractedArtifactName.replace(/^\\+/, "").toLowerCase();
            if (!ps4104ByTask[host]) ps4104ByTask[host] = {};
            if (!ps4104ByTask[host][key]) ps4104ByTask[host][key] = [];
            ps4104ByTask[host][key].push(rs);
          }
          if (rs.matchedCategory === "Services" && rs.extractedArtifactName) {
            const key = _normSvcName(rs.extractedArtifactName);
            if (!ps4104BySvc[host]) ps4104BySvc[host] = {};
            if (!ps4104BySvc[host][key]) ps4104BySvc[host][key] = [];
            ps4104BySvc[host][key].push(rs);
          }
          if (rs.matchedCategory === "Registry Autorun") {
            if (!ps4104ByRegKey[host]) ps4104ByRegKey[host] = [];
            ps4104ByRegKey[host].push(rs);
          }
          if (rs.matchedCategory === "WMI Persistence" && rs.extractedArtifactName) {
            const key = rs.extractedArtifactName.toLowerCase().trim();
            if (!ps4104ByWmi[host]) ps4104ByWmi[host] = {};
            if (!ps4104ByWmi[host][key]) ps4104ByWmi[host][key] = [];
            ps4104ByWmi[host][key].push(rs);
          }
        }

        // --- Build correlation indexes ---
        const svcStartByName = {};
        for (const ev of svcStartEvents) {
          if (!svcStartByName[ev.svcName]) svcStartByName[ev.svcName] = [];
          svcStartByName[ev.svcName].push(ev);
          if (ev.aliasName) {
            if (!svcStartByName[ev.aliasName]) svcStartByName[ev.aliasName] = [];
            svcStartByName[ev.aliasName].push(ev);
          }
        }
        const svcControlByName = {};
        for (const ev of svcControlEvents) {
          if (!svcControlByName[ev.svcName]) svcControlByName[ev.svcName] = [];
          svcControlByName[ev.svcName].push(ev);
          if (ev.aliasName) {
            if (!svcControlByName[ev.aliasName]) svcControlByName[ev.aliasName] = [];
            svcControlByName[ev.aliasName].push(ev);
          }
        }
        const procStartByPath = {};
        const procStartByBase = {};
        for (const ev of procStartEvents) {
          if (ev.imagePath) { if (!procStartByPath[ev.imagePath]) procStartByPath[ev.imagePath] = []; procStartByPath[ev.imagePath].push(ev); }
          if (ev.imageBase && !COMMON_SYSTEM_BINS.has(ev.imageBase)) { if (!procStartByBase[ev.imageBase]) procStartByBase[ev.imageBase] = []; procStartByBase[ev.imageBase].push(ev); }
        }

        // --- Collect existing evidence from persistence items ---
        const loadedDlls = new Set();
        for (const item of items) {
          if (item.name === "Unsigned DLL Loaded" && item.details.imageLoaded) {
            loadedDlls.add(item.details.imageLoaded.toLowerCase().replace(/"/g, "").trim());
          }
        }
        const svcRegMods = new Set();
        for (const item of items) {
          if (item.name === "Registry Value Set" && item.details.targetObject) {
            const m = item.details.targetObject.match(/\\Services\\([^\\]+)/i);
            if (m) svcRegMods.add(m[1].toLowerCase());
          }
        }

        // --- Service execution correlation: multi-source (7036 + 7035 + Sysmon 1 + 4688 + DLL + registry) ---
        for (const item of items) {
          if (item.category !== "Services" || (item.name !== "Service Installed" && item.name !== "Service StartType Changed")) continue;
          const sn = _normSvcName(item.details.serviceName);
          const exe = _parseExePath(item.details.imagePath || item.details.serviceFile);
          const host = (item.computer || "").toUpperCase();
          const ts = item.timestamp;

          // 1. Service start (7036 running) — same host, within time window
          //    Try direct name first, then display-name alias fallback
          let starts = (svcStartByName[sn] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
          let _svcDisplayNameMatch = false;
          if (starts.length === 0 && sn) {
            const alias = SVC_DISPLAY_ALIASES[sn];
            if (alias) {
              starts = (svcStartByName[alias] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
              if (starts.length > 0) _svcDisplayNameMatch = true;
            }
          }
          let startsExt = [];
          if (starts.length === 0) {
            startsExt = (svcStartByName[sn] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW_EXT));
            if (startsExt.length === 0 && sn) {
              const alias = SVC_DISPLAY_ALIASES[sn];
              if (alias) {
                startsExt = (svcStartByName[alias] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW_EXT));
                if (startsExt.length > 0) _svcDisplayNameMatch = true;
              }
            }
          }

          // 2. Process start (Sysmon 1 / 4688) — full path first, basename fallback
          let procMatches = [];
          if (exe) {
            procMatches = (procStartByPath[exe.imagePath] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
            if (procMatches.length === 0 && exe.imageBase && !COMMON_SYSTEM_BINS.has(exe.imageBase)) {
              procMatches = (procStartByBase[exe.imageBase] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
            }
          }

          // 3. Existing evidence (registry tamper, DLL loads)
          const regMatch = sn && svcRegMods.has(sn);
          const dllMatch = exe?.imagePath && loadedDlls.has(exe.imagePath);

          // Assign confidence tier + enrichment
          const bestProc = procMatches[0];
          const parentIsServices = bestProc?.parentBase === "services.exe";
          const parentSuspicious = bestProc && !parentIsServices && bestProc.parentBase && bestProc.parentBase !== "";

          if (starts.length > 0) {
            item.confidence = _svcDisplayNameMatch ? "likely" : "confirmed";
            item.details._serviceStarted = true;
            item.details._serviceStartTs = starts[0].timestamp;
            if (_svcDisplayNameMatch) item.details._svcDisplayNameMatch = true;
          } else if (startsExt.length > 0) {
            item.confidence = "likely";
            item.details._serviceStarted = true;
            item.details._serviceStartTs = startsExt[0].timestamp;
            if (_svcDisplayNameMatch) item.details._svcDisplayNameMatch = true;
          } else if (bestProc && parentIsServices) {
            item.confidence = "confirmed";
            item.details._serviceProcessStarted = true;
            item.details._serviceProcessTs = bestProc.timestamp;
            item.details._serviceProcessParent = bestProc.parentImage;
          } else if (bestProc) {
            item.confidence = "likely";
            item.details._serviceProcessStarted = true;
            item.details._serviceProcessTs = bestProc.timestamp;
            item.details._serviceProcessParent = bestProc.parentImage;
            if (parentSuspicious) item.details._serviceProcessParentSuspicious = true;
          } else if (regMatch || dllMatch) {
            item.confidence = "likely";
            item.details._serviceExecSeen = true;
          } else {
            item.confidence = "present";
          }
          // 7035: supplementary service control correlation (only start-like controls strengthen confidence)
          const ctrlHits = (svcControlByName[sn] || []).filter(e => e.computer === host && _withinWindowBidi(ts, e.timestamp, CORR_WINDOW));
          if (ctrlHits.length > 0) {
            const startLike = ctrlHits.filter(e => /start/i.test(e.controlType));
            const stopLike = ctrlHits.filter(e => /stop|pause|disabled/i.test(e.controlType));
            if (startLike.length > 0) {
              item.details._svcControlSeen = true;
              item.details._svcControlType = startLike[0].controlType;
              // Upgrade "present" → "likely" only when a start request corroborates
              if (item.confidence === "present") item.confidence = "likely";
            }
            if (stopLike.length > 0) {
              item.details._svcControlStopSeen = true;
            }
          }
        }

        // --- WMI field normalization: parse raw CIM blobs into clean analyst-readable fields ---
        {
          const _parseCimBlob = (raw) => {
            if (!raw) return {};
            const out = {};
            // CIM instance type: "instance of CommandLineEventConsumer"
            const typeM = raw.match(/instance\s+of\s+(\w+)/i);
            if (typeM) out.type = typeM[1];
            // Name property
            const nameM = raw.match(/Name\s*=\s*"([^"]+)"/i);
            if (nameM) out.name = nameM[1];
            // CommandLineEventConsumer fields
            const cmdM = raw.match(/CommandLineTemplate\s*=\s*"([^"]+)"/i);
            if (cmdM) out.command = cmdM[1];
            const exeM = raw.match(/ExecutablePath\s*=\s*"([^"]+)"/i);
            if (exeM) out.command = out.command ? `${exeM[1]} ${out.command}` : exeM[1];
            // ActiveScriptEventConsumer fields
            const scriptFileM = raw.match(/ScriptFileName\s*=\s*"([^"]+)"/i);
            if (scriptFileM) out.command = scriptFileM[1];
            const scriptTextM = raw.match(/ScriptText\s*=\s*"([^"]+)"/i);
            if (scriptTextM) out.command = out.command || scriptTextM[1].substring(0, 300);
            return out;
          };
          // Parse WMI object path format: "TypeName.Name=\"value\""
          const _parseWmiObjPath = (raw) => {
            if (!raw) return {};
            const m = raw.match(/(\w+)\.Name\s*=\s*"([^"]+)"/i);
            return m ? { type: m[1], name: m[2] } : {};
          };

          for (const item of items) {
            if (item.category !== "WMI Persistence") continue;
            const d = item.details;

            if (item.name === "WMI Event Subscription") {
              // EID 5861: consumer field has full CIM blob
              const parsed = _parseCimBlob(d.consumer || "");
              if (parsed.type) d._wmiType = parsed.type;
              if (parsed.name) d._wmiName = parsed.name;
              if (parsed.command) d._wmiCommand = parsed.command;
              if (d.query && !d._wmiQuery) d._wmiQuery = d.query;
            } else if (item.name === "WMI EventFilter Created") {
              // Sysmon 19: name is already clean
              d._wmiType = "__EventFilter";
              if (d.name) d._wmiName = d.name;
              if (d.query) d._wmiQuery = d.query;
            } else if (item.name === "WMI EventConsumer Created") {
              // Sysmon 20: name/type/destination are clean
              if (d.type) d._wmiType = d.type;
              if (d.name) d._wmiName = d.name;
              if (d.destination) d._wmiCommand = d.destination;
            } else if (item.name === "WMI Binding Created") {
              // Sysmon 21: consumer/filter in WMI object path format
              const cParsed = _parseWmiObjPath(d.consumer);
              const fParsed = _parseWmiObjPath(d.filter);
              d._wmiType = "Binding";
              d._wmiName = cParsed.name || fParsed.name || "";
              if (cParsed.type) d._wmiConsumerType = cParsed.type;
              if (fParsed.name) d._wmiFilterName = fParsed.name;
            }
          }
        }

        // --- WMI subscription correlation: link Sysmon EID 19 (Filter), 20 (Consumer), 21 (Binding) ---
        {
          const wmiMap = {}; // normalized name → { filter: bool, consumer: bool, binding: bool, destination: string }
          const _normWmi = (s) => (s || "").replace(/"/g, "").trim().toLowerCase();
          for (const item of items) {
            if (item.category !== "WMI Persistence") continue;
            let compName = null;
            if (item.name === "WMI EventFilter Created") {
              compName = _normWmi(item.details._wmiName);
              if (compName) { if (!wmiMap[compName]) wmiMap[compName] = {}; wmiMap[compName].filter = true; }
            } else if (item.name === "WMI EventConsumer Created") {
              compName = _normWmi(item.details._wmiName);
              if (compName) {
                if (!wmiMap[compName]) wmiMap[compName] = {};
                wmiMap[compName].consumer = true;
                if (item.details._wmiCommand) wmiMap[compName].destination = item.details._wmiCommand;
              }
            } else if (item.name === "WMI Binding Created") {
              // Binding: use normalized names from parsed object paths
              const cName = _normWmi(item.details._wmiName);
              const fName = _normWmi(item.details._wmiFilterName);
              for (const n of [cName, fName]) {
                if (n) { if (!wmiMap[n]) wmiMap[n] = {}; wmiMap[n].binding = true; }
              }
            }
          }
          // Enrich WMI items with completeness info
          for (const item of items) {
            if (item.category !== "WMI Persistence") continue;
            const compName = _normWmi(item.details._wmiName || "");
            const info = compName ? wmiMap[compName] : null;
            if (info) {
              const hasAll = !!(info.filter && info.consumer && info.binding);
              item.details._wmiComplete = hasAll;
              item.details._wmiPartial = !hasAll;
              if (info.destination) item.details._wmiLinkedCommand = info.destination;
              item.confidence = hasAll ? "confirmed" : "likely";
            }
          }
        }

        // --- Registry autorun execution correlation: check if autorun value-data executables appear elsewhere ---
        {
          // Build set of all observed executable paths from item details
          const execPaths = new Set();
          const _normPath = (p) => { const parsed = _parseExePath(p); return parsed ? parsed.imagePath : ""; };
          for (const item of items) {
            const d = item.details;
            for (const f of [d.executable, d.command, d.serviceFile, d.imagePath, d.image, d.imageLoaded, d.targetFilename]) {
              const np = _normPath(f);
              if (np && np.length > 3) execPaths.add(np);
            }
          }
          // Check Registry Autorun (EID 13) value data against execPaths + process start events
          for (const item of items) {
            if (item.category === "Registry Autorun" && item.details.details) {
              const vd = _normPath(item.details.details);
              const host = (item.computer || "").toUpperCase();
              if (vd && (execPaths.has(vd) || (procStartByPath[vd] || []).some(e => e.computer === host))) {
                item.details._execSeen = true;
                item.confidence = "confirmed";
              }
            }
          }
        }
      }

      // --- 4104 Correlation: enrich existing items + create standalone items ---
      const _correlated4104Ids = new Set();
      if (ps4104Reassembled.length > 0) {
        // 5a. Enrich Scheduled Task items
        for (const item of items) {
          if (item.category !== "Scheduled Tasks" || (item.name !== "Task Registered" && item.name !== "Scheduled Task Created")) continue;
          const tn = (item.details.taskName || "").replace(/^\\+/, "").toLowerCase();
          if (!tn) continue;
          const host = (item.computer || "").toUpperCase();
          const candidates = (ps4104ByTask[host] || {})[tn]
            || Object.values(ps4104ByTask[host] || {}).find(arr => arr[0] && tn.endsWith(arr[0].extractedArtifactName?.replace(/^\\+/, "").toLowerCase() || "__"))
            || [];
          const match = (Array.isArray(candidates) ? candidates : []).find(rs => _withinWindow(item.timestamp, rs.timestamp, CORR_WINDOW_EXT) || _withinWindow(rs.timestamp, item.timestamp, CORR_WINDOW_EXT));
          if (match) {
            item.details._ps4104Seen = true;
            item.details._ps4104ScriptPath = match.path;
            item.details._ps4104ScriptBlockId = match.scriptBlockId;
            item.details._ps4104SuspiciousIndicators = match.suspiciousIndicators;
            item.confidence = "confirmed";
            _correlated4104Ids.add(match.scriptBlockId);
          }
        }
        // 5b. Enrich Service Installed items
        for (const item of items) {
          if (item.category !== "Services" || item.name !== "Service Installed") continue;
          const sn = _normSvcName(item.details.serviceName);
          if (!sn) continue;
          const host = (item.computer || "").toUpperCase();
          const candidates = (ps4104BySvc[host] || {})[sn] || [];
          const match = candidates.find(rs => _withinWindow(item.timestamp, rs.timestamp, CORR_WINDOW_EXT) || _withinWindow(rs.timestamp, item.timestamp, CORR_WINDOW_EXT));
          if (match) {
            item.details._ps4104Seen = true;
            item.details._ps4104ScriptPath = match.path;
            item.details._ps4104ScriptBlockId = match.scriptBlockId;
            item.details._ps4104SuspiciousIndicators = match.suspiciousIndicators;
            if (item.confidence !== "confirmed") item.confidence = "likely";
            _correlated4104Ids.add(match.scriptBlockId);
          }
        }
        // 5c. Enrich WMI Persistence items
        for (const item of items) {
          if (item.category !== "WMI Persistence") continue;
          const wn = (item.details.name || item.details.consumer || item.details.filter || "").toLowerCase().trim();
          if (!wn) continue;
          const host = (item.computer || "").toUpperCase();
          const candidates = (ps4104ByWmi[host] || {})[wn] || [];
          const match = candidates.find(rs => _withinWindow(item.timestamp, rs.timestamp, CORR_WINDOW_EXT) || _withinWindow(rs.timestamp, item.timestamp, CORR_WINDOW_EXT));
          if (match) {
            item.details._ps4104Seen = true;
            item.details._ps4104ScriptPath = match.path;
            item.details._ps4104ScriptBlockId = match.scriptBlockId;
            item.details._ps4104SuspiciousIndicators = match.suspiciousIndicators;
            if (item.confidence !== "confirmed") item.confidence = "likely";
            _correlated4104Ids.add(match.scriptBlockId);
          }
        }
        // 5d. Enrich Registry Autorun items (key-family-aware: match Run↔Run, RunOnce↔RunOnce, IFEO↔IFEO, etc.)
        const _regKeyFamily = (targetObj) => {
          if (!targetObj) return null;
          const m = targetObj.match(/\\(Run(?:Once)?|RunServices|AppInit_DLLs|Image File Execution Options(?:\\[^\\]+)?|Winlogon\\(?:Shell|Userinit|Notify)|Session Manager\\(?:BootExecute|SetupExecute)|Active Setup|Print\\Monitors|NetworkProvider)(?:\\|$)/i);
          return m ? m[1].toLowerCase().replace(/\\.+$/, "") : null;
        };
        for (const item of items) {
          if (item.category !== "Registry Autorun") continue;
          const host = (item.computer || "").toUpperCase();
          const candidates = ps4104ByRegKey[host] || [];
          const itemKeyFamily = _regKeyFamily(item.details.targetObject);
          const match = candidates.find(rs => {
            if (!(_withinWindow(item.timestamp, rs.timestamp, CORR_WINDOW_EXT) || _withinWindow(rs.timestamp, item.timestamp, CORR_WINDOW_EXT))) return false;
            // Key family check: script's extractedArtifactName (Run/RunOnce) or fullText must reference the same key family
            if (!itemKeyFamily) return true; // no key family extractable → allow loose match
            const scriptKeyRef = (rs.extractedArtifactName || "").toLowerCase();
            if (scriptKeyRef && itemKeyFamily.startsWith(scriptKeyRef)) return true;
            // Fallback: check if the script's full text mentions the target key family
            return new RegExp(itemKeyFamily.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(rs.fullText);
          });
          if (match) {
            item.details._ps4104Seen = true;
            item.details._ps4104ScriptPath = match.path;
            item.details._ps4104ScriptBlockId = match.scriptBlockId;
            item.details._ps4104SuspiciousIndicators = match.suspiciousIndicators;
            if (item.confidence !== "confirmed") item.confidence = "likely";
            _correlated4104Ids.add(match.scriptBlockId);
          }
        }
        // 5e. Standalone items for uncorrelated scripts
        for (const rs of ps4104Reassembled) {
          if (_correlated4104Ids.has(rs.scriptBlockId)) continue;
          const indSet = new Set(rs.suspiciousIndicators || []);
          const strongPs4104 = indSet.size >= 2
            || rs.matchedPatterns.length >= 2
            || indSet.has("Defender exclusion")
            || indSet.has("Defender disable")
            || (indSet.has("EncodedCommand") && (indSet.has("DownloadString") || indSet.has("Net.WebClient") || indSet.has("Web download")));
          if (!strongPs4104 && indSet.size === 0) continue;
          const scriptPreview = rs.fullText.substring(0, 500);
          items.push({
            category: rs.matchedCategory,
            name: rs.matchedName,
            severity: strongPs4104 ? "critical" : "high",
            source: "EventID 4104",
            confidence: strongPs4104 ? "confirmed" : "likely",
            timestamp: rs.timestamp,
            computer: rs.computer,
            user: rs.user,
            artifact: rs.extractedArtifactName || rs.path || rs.hostApplication || "(inline script)",
            command: scriptPreview,
            detailsSummary: (rs.matchedPatterns.join(", ") + (rs.path ? " | " + rs.path : "")).substring(0, 400),
            mode: "evtx",
            details: {
              scriptPath: rs.path,
              hostApplication: rs.hostApplication,
              scriptBlockId: rs.scriptBlockId,
              fragmentCount: rs.fragmentCount,
              matchedPatterns: rs.matchedPatterns,
              scriptPreview,
              extractedArtifactName: rs.extractedArtifactName,
              _ps4104Standalone: true,
              _ps4104Strong: strongPs4104,
              _ps4104SuspiciousIndicators: rs.suspiciousIndicators,
            },
          });
        }
        ps4104CorrelatedCount = _correlated4104Ids.size;
      }

      const BUILTIN_ACCOUNT_PAT = /^(?:system|local service|network service|anonymous logon|defaultaccount|wdagutilityaccount|dwm-\d+|umfd-\d+)$/i;
      const MACHINE_ACCOUNT_PAT = /\$$/;

      // --- Account persistence cross-event correlation: chain 4720→4738→4728/4732/4756→4724 ---
      {
        // Build per-user timeline of account events
        const acctTimeline = {}; // user (lowercase) → [item, ...]
        const ACCT_NAMES = new Set(["User Account Created", "User Account Changed", "User Password Reset",
          "Member Added to Global Security Group", "Member Added to Local Security Group", "Member Added to Universal Security Group"]);
        for (const item of items) {
          if (item.category !== "Account Persistence" || !ACCT_NAMES.has(item.name)) continue;
          const tgt = (item.details?.targetUser || item.details?.memberName || item.details?.samAccountName || "").toLowerCase();
          if (!tgt || BUILTIN_ACCOUNT_PAT.test(tgt) || MACHINE_ACCOUNT_PAT.test(tgt)) continue;
          if (!acctTimeline[tgt]) acctTimeline[tgt] = [];
          acctTimeline[tgt].push(item);
        }
        // For each user with multiple events, check for chained activity
        for (const [, events] of Object.entries(acctTimeline)) {
          if (events.length < 2) continue;
          const hasCreate = events.some(e => e.name === "User Account Created");
          const hasModify = events.some(e => e.name === "User Account Changed");
          const hasGroupAdd = events.some(e => /Member Added/.test(e.name));
          const hasReset = events.some(e => e.name === "User Password Reset");
          const chainLen = [hasCreate, hasModify, hasGroupAdd, hasReset].filter(Boolean).length;
          if (chainLen >= 2) {
            for (const item of events) {
              item.details._acctChainLen = chainLen;
              item.details._acctChainEvents = [
                hasCreate && "created", hasModify && "modified", hasGroupAdd && "group-add", hasReset && "pw-reset"
              ].filter(Boolean);
              if (item.confidence !== "confirmed") item.confidence = "likely";
            }
          }
        }
      }

      // --- Cross-technique correlation: account event → persistence mechanism by same user ---
      {
        const ACCT_PERSIST_WINDOW = 3600000; // 60 min
        const PERSIST_CATS = new Set(["Services", "Scheduled Tasks", "WMI Persistence", "Registry Autorun",
          "Winlogon", "IFEO", "AppInit DLLs", "Domain Persistence", "Run Keys", "Startup Folder"]);
        // Build index of account events by subjectUser|computer
        const acctEventsByActor = {}; // "user|host" → [item, ...]
        for (const item of items) {
          if (item.category !== "Account Persistence") continue;
          const actor = (item.details?.subjectUser || "").toLowerCase();
          const host = (item.computer || "").toUpperCase();
          if (!actor || BUILTIN_ACCOUNT_PAT.test(actor) || MACHINE_ACCOUNT_PAT.test(actor)) continue;
          const key = `${actor}|${host}`;
          if (!acctEventsByActor[key]) acctEventsByActor[key] = [];
          acctEventsByActor[key].push(item);
        }
        // For each persistence item, check if same user had a recent account event
        for (const item of items) {
          if (!PERSIST_CATS.has(item.category)) continue;
          // Get the user who performed the persistence action
          const actor = (item.user || item.details?.subjectUser || "").toLowerCase();
          const host = (item.computer || "").toUpperCase();
          if (!actor) continue;
          const key = `${actor}|${host}`;
          const acctEvents = acctEventsByActor[key];
          if (!acctEvents || acctEvents.length === 0) continue;
          const itemTs = new Date(item.timestamp).getTime();
          if (isNaN(itemTs)) continue;
          // Find account events within window (account event before or shortly after persistence)
          const matched = acctEvents.filter(ae => {
            const aeTs = new Date(ae.timestamp).getTime();
            return !isNaN(aeTs) && Math.abs(itemTs - aeTs) <= ACCT_PERSIST_WINDOW;
          });
          if (matched.length > 0) {
            const acctTypes = [...new Set(matched.map(ae => ae.name.replace(/^Member Added to \w+ Security Group$/, "group-add")
              .replace("User Account Created", "acct-created").replace("User Password Reset", "pw-reset")
              .replace("User Account Changed", "acct-changed")))];
            item.details._acctToPersistenceSeen = true;
            item.details._acctToPersistenceTypes = acctTypes;
            // Also mark the account events
            for (const ae of matched) {
              ae.details._acctToPersistenceSeen = true;
              ae.details._acctToPersistenceTechnique = item.category;
            }
          }
        }
      }

      // Normalize 4738 account-change fields to avoid key/value bleed-over from loose payload formats.
      const _normalizeAcctField = (v) => {
        let s = String(v || "").trim();
        if (!s) return "";
        // If extractor over-captured multiple fields ("... ScriptPath: X ProfilePath: Y"), keep first field value only.
        s = s.replace(/\s+[A-Za-z][A-Za-z0-9_ ]{1,30}:\s*.*$/, "").trim();
        return s;
      };
      const _isUnsetAcctField = (v) => {
        const s = _normalizeAcctField(v);
        return !s || s === "-" || /^%%\d+$/.test(s) || /^(?:null|n\/a|not\s+set|<not\s+set>)$/i.test(s);
      };
      const _isMeaningfulScriptPath = (v) => {
        const s = _normalizeAcctField(v);
        if (_isUnsetAcctField(s)) return false;
        return /^(?:[a-z]:\\|\\\\)/i.test(s) || /\.(?:bat|cmd|ps1|vbs|js|exe|com)$/i.test(s);
      };
      const _isMeaningfulDelegation = (v) => {
        const s = _normalizeAcctField(v);
        if (_isUnsetAcctField(s)) return false;
        return /[a-z0-9._-]+\/[a-z0-9._-]+/i.test(s);
      };

      // --- Compute artifact + command columns from details ---
      for (const item of items) {
        const d = item.details;
        if (d._ps4104Standalone) {
          item.artifact = d.extractedArtifactName || d.scriptPath || "(inline script)";
          item.command = d.scriptPreview || "";
        } else if (d._is4657Fallback && item.artifact) {
          // 4657 items already have artifact/command set during post-processing
        } else if (item.category === "Domain Persistence") {
          item.artifact = d.objectDN || "";
          item.command = d.attributeName ? `${d.attributeName}: ${d.attributeValue || ""}` : d.objectClass || "";
        } else if (item.name === "User Account Changed") {
          d.scriptPath = _normalizeAcctField(d.scriptPath);
          d.userAccountControl = _normalizeAcctField(d.userAccountControl);
          d.homeDirectory = _normalizeAcctField(d.homeDirectory);
          d.profilePath = _normalizeAcctField(d.profilePath);
          d.userParameters = _normalizeAcctField(d.userParameters);
          d.allowedToDelegateTo = _normalizeAcctField(d.allowedToDelegateTo);
          item.artifact = d.targetUser || d.samAccountName || "";
          item.command = [
            _isMeaningfulScriptPath(d.scriptPath) ? `scriptPath: ${d.scriptPath}` : "",
            !_isUnsetAcctField(d.userAccountControl) ? `UAC: ${d.userAccountControl}` : "",
            _isMeaningfulDelegation(d.allowedToDelegateTo) ? `delegateTo: ${d.allowedToDelegateTo}` : "",
          ].filter(Boolean).join(" | ") || "";
        } else if (item.category === "WMI Persistence") {
          item.artifact = d._wmiName || d.name || "";
          item.command = d._wmiCommand || d._wmiQuery || d.query || d.poss_command || "";
        } else if (item.mode === "evtx") {
          item.artifact = d.taskName || d.serviceName || d.targetObject || d.targetFilename || d.name || d.imageLoaded || "";
          item.command = d.executable || d.command || d.serviceFile || d.imagePath || d.image || d.query || d.destination || d.details || "";
        } else {
          item.artifact = d.keyPath || "";
          item.command = d.valueData || "";
        }
      }

      // --- Known AV/EDR whitelist: suppress legitimate security products from expected paths ---
      const AV_EDR_WHITELIST = [
        // Palo Alto / Cortex XDR / Traps
        { namePattern: /^(?:cyvrmtgn|cyverak|cyvrfsfd|tedrdrv|tdevflt|telam|Cortex\s*XDR|Cortex\s*XDR\s*Health\s*Helper|CyMemDef|CyProtectDrv|CyOpticsRuntimeDriver|TrapsSupervisor|PanGPS|PanUpdater)$/i,
          pathPattern: /(?:Palo\s*Alto\s*Networks|Cortex\s*XDR)/i },
        // Microsoft Defender / MpKsl* drivers / MsMpEng / NisSrv
        { namePattern: /^(?:Microsoft\s*Defender|MpDefender|WinDefend|MsMpSvc|NisSrv|MpKsl[0-9a-f]+|WdNisSvc|WdNisDrv|WdFilter|WdBoot|SecurityHealthService|Sense|MsSecCore|Microsoft\s*Defender\s*Core\s*Service)$/i,
          pathPattern: /(?:Windows\s*Defender|Microsoft\s*Defender|Microsoft\\Windows\s*Defender|ProgramData\\Microsoft\\Windows\s*Defender)/i },
        // CrowdStrike Falcon
        { namePattern: /^(?:CSFalcon|CsFalconService|csagent|CSAgent|csdevicecontrol|CrowdStrike|CsInstallerService|CsDisk[A-Z]|CsBoot|CsEFW)$/i,
          pathPattern: /CrowdStrike/i },
        // SentinelOne
        { namePattern: /^(?:SentinelAgent|SentinelOne|SentinelMonitor|SentinelStaticEngine|LogProcessorService|SentinelStaticEngineScanner|SentinelHelperService)$/i,
          pathPattern: /SentinelOne/i },
        // Carbon Black (VMware/Broadcom)
        { namePattern: /^(?:CbDefense|CbDefenseSensor|CarbonBlack|cb\.exe|RepMgr|CbStream|carbonblackk|CbSensor)$/i,
          pathPattern: /(?:CarbonBlack|Carbon\s*Black|Cb\\)/i },
        // Sophos
        { namePattern: /^(?:Sophos|SAVService|SAVAdminService|SophosHealth|SophosCleanup|SophosFileScanner|SophosFS|SophosNtpService|hmpalert|SophosUI)$/i,
          pathPattern: /Sophos/i },
        // Symantec / Broadcom / Norton
        { namePattern: /^(?:SepMaster|SepScan|ccSvcHst|SymCorpUI|SymEFA|Norton|NortonSecurity|smc|SmcService|Symantec|SylinkDrop|ccEvtMgr)$/i,
          pathPattern: /(?:Symantec|Norton|Broadcom)/i },
        // McAfee / Trellix
        { namePattern: /^(?:McAfee|McShield|mfemms|mfefire|mfevtp|TrellixENS|TrellixEDR|masvc|macmnsvc|mfewc|mfetp)$/i,
          pathPattern: /(?:McAfee|Trellix)/i },
        // Kaspersky
        { namePattern: /^(?:AVP|avp|kavsvc|kavfs|klnagent|KAVFS|KESCapability|KLSysEvLog)$/i,
          pathPattern: /Kaspersky/i },
        // ESET
        { namePattern: /^(?:ekrn|ESET|EsetService|ERAAgent|eamonm|ehdrv|epfwwfp|epfw)$/i,
          pathPattern: /ESET/i },
        // Trend Micro
        { namePattern: /^(?:TrendMicro|Ntrtscan|tmlisten|TmFilter|TmPreFilter|ds_agent|Apex\s*One)$/i,
          pathPattern: /(?:Trend\s*Micro|TrendMicro)/i },
        // Bitdefender
        { namePattern: /^(?:EPSecurityService|EPProtectedService|EPUpdateService|EPIntegrationService|EPRedline|BDAuxSrv|TRUFOS|bdservicehost)$/i,
          pathPattern: /Bitdefender/i },
        // Cylance (BlackBerry)
        { namePattern: /^(?:CylanceSvc|CylanceUI|CylanceDrv|CylanceProtect|CyOptics)$/i,
          pathPattern: /Cylance/i },
        // Elastic Agent / Endpoint Security
        { namePattern: /^(?:elastic-agent|elastic-endpoint|ElasticEndpoint|winlogbeat|filebeat)$/i,
          pathPattern: /(?:Elastic|elastic)/i },
        // Fortinet FortiClient / FortiEDR
        { namePattern: /^(?:FortiClient|FortiEDR|FortiGate|FA_Scheduler|FortiClientProductUpdate)$/i,
          pathPattern: /Fortinet/i },
      ];

      // --- Risk scoring + suspicious detection ---
      const LOLBIN_PAT = /(?:powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec|forfiles|cmstp|hh\.exe|odbcconf|regasm|regsvcs|installutil|pcalua|msconfig|msbuild|xwizard|presentationhost|ieexec|control\.exe)/i;
      const SUSPICIOUS_PATHS = /\\(?:Temp|AppData|Downloads|Users\\Public|ProgramData\\[^\\]*$|Recycle)/i;
      const SUSPICIOUS_CMDS = /(?:powershell|pwsh|cmd\.exe\s*\/c|certutil|bitsadmin|mshta|regsvr32|wscript|cscript|rundll32|msiexec.*\/q|forfiles|cmstp|odbcconf|regasm|regsvcs|installutil|pcalua|msbuild)/i;
      const ENCODING_INDICATORS = /(?:base64|frombase64|-[eE]nc\s|-[eE]\s|iex|invoke-expression|downloadstring|downloadfile|webclient|bitstransfer)/i;
      const SEVERITY_SCORES = { critical: 8, high: 6, medium: 4, low: 2 };
      // Known-legitimate task name prefixes (not suspicious)
      const LEGIT_TASK_PREFIXES = /^\\(?:Microsoft\\|Apple\\|Google\\|Adobe\\|Mozilla\\)/i;

      // Known-legitimate Windows task executables and action handlers (noisy FPs)
      const LEGIT_TASK_EXECUTABLES = /^(?:taskhostw\.exe|InputToCdsTaskHandler|svchost\.exe|conhost\.exe|backgroundTaskHost\.exe|RuntimeBroker\.exe|MusNotification\.exe|devicecensus\.exe|AppHostRegistrationVerifier\.exe|dstokenclean\.exe|UsoClient\.exe|OfficeBackgroundTaskHandlerRegistration|OfficeBackgroundTaskHandlerLogon|WaaSMedicAgent\.exe)$/i;

      // Known-legitimate browser scheduled tasks (task name patterns)
      const LEGIT_BROWSER_TASKS = /^\\?(?:MicrosoftEdgeUpdate|GoogleUpdate|Google(?:Chrome)?Update|ChromeUpdate|BraveSoftwareUpdate|MozillaUpdate|OperaSoftwareUpdate|VivaldiUpdate|Firefox\s*Default\s*Browser\s*Agent)/i;
      // Known-legitimate browser executables (expected paths)
      const LEGIT_BROWSER_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Microsoft\\Edge|Google\\(?:Chrome|Update)|Mozilla\s*Firefox|BraveSoftware|Opera|Vivaldi)|\\AppData\\Local\\(?:Microsoft\\Edge|Google\\Chrome|BraveSoftware|Mozilla\s*Firefox)\\)/i;
      const LEGIT_VENDOR_TASKS = /^\\?(?:OneDrive(?:\s+Standalone\s+Update\s+Task)?(?:\s+Per-Machine)?(?:-S-1-5-\d+(?:-\d+){2,})?|OneDrive\s+Reporting\s+Task(?:-S-1-5-\d+(?:-\d+){2,})?|Outlook\s+Update|Office(?:Automatic|Feature)\s+Updates?|Office\s+Background\s+Task(?:\s+\S+)?|Teams(?:\s+Update)?|Microsoft\s+Office\s+Updates?|SharePoint(?:\s+Workspace)?(?:\s+Update)?)$/i;
      const LEGIT_VENDOR_TASK_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Microsoft Office|Microsoft\\Office|Microsoft OneDrive|Microsoft\\OneDrive)|\\AppData\\Local\\Microsoft\\(?:OneDrive|Teams)|%localappdata%\\microsoft\\onedrive\\(?:onedrive(?:standaloneupdater)?|onedrivesetup)\.exe|OfficeClickToRun|OneDrive(?:Setup|StandaloneUpdater)?\.exe|OUTLOOK\.EXE|\\Office\d+\\GROOVE\.EXE)/i;
      const LEGIT_ENTERPRISE_TASKS = /^\\?(?:Adobe(?:\s+\w+)?(?:\s+Updater|\s+Update)?|Zoom(?:\s+Update)?|Slack(?:\s+Update)?|Webex(?:\s+Update)?|Citrix(?:\s+\w+)?|VMware(?:\s+\w+)?|Duo(?:\s+\w+)?|Okta(?:\s+\w+)?|Qualys(?:\s+\w+)?|Tanium(?:\s+\w+)?|BigFix(?:\s+\w+)?|Rapid7(?:\s+\w+)?|Nessus(?:\s+\w+)?|Intune(?:\s+\w+)?|SCCM(?:\s+\w+)?|ConfigMgr(?:\s+\w+)?|Windows\s+Defender(?:\s+\w+)?|Microsoft\s+Edge\s+Update)$/i;
      const LEGIT_ENTERPRISE_TASK_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Adobe|Zoom|Slack|Cisco\s*Webex|Citrix|VMware|Duo\s*Security|Okta|Qualys|Tanium|BigFix|Rapid7|Tenable|Microsoft|Google)|\\Windows\\System32\\|\\Windows\\SysWOW64\\|\\ProgramData\\Microsoft\\|IntuneManagementExtension|CCM\\|OfficeClickToRun|GoogleUpdate\.exe|MicrosoftEdgeUpdate\.exe)/i;
      const LEGIT_WINDOWS_SCHED_TASKS = /^\\Microsoft\\Windows\\(?:UpdateOrchestrator\\(?:Schedule\s+Wake\s+To\s+Work|Schedule\s+Maintenance\s+Work|USO_[^\\]+|Reboot(?:_AC|_Battery)?|Refresh\s+Settings|Maintenance\s+Install|MusUx_UpdateInterval|MusUx_UpdateIntervalNoWake)?|SoftwareProtectionPlatform\\SvcRestartTask)$/i;
      const LEGIT_WINDOWS_TASK_PREFIX = /^\\Microsoft\\Windows\\[^\\]+/i;
      const LEGIT_WINDOWS_TASK_CMD_PATHS = /(?:\\Windows\\System32\\|\\Windows\\SysWOW64\\|taskhostw\.exe|svchost\.exe|rundll32\.exe|sihclient\.exe|usoclient\.exe|musnotification\.exe|taskschd\.dll|\\ProgramData\\Microsoft\\)/i;
      const ENTERPRISE_SERVICE_NAMES = /(?:tanium|bigfix|besclient|qualys|rapid7|insight|nessus|tenable|carbon\s*black|cbdefense|crowdstrike|sentinelone|sophos|mcafee|trellix|symantec|defender|elastic|osquery|intune|ccmexec|sccm|configmgr|kaseya|connectwise|screenconnect|teamviewer|anydesk|rustdesk|splashtop|atera|meshagent|action1|pulseway|n-?able|solarwinds|manageengine|pdq)/i;
      const ENTERPRISE_SERVICE_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Tanium|BigFix\s*Enterprise|Qualys|Rapid7|Tenable|CrowdStrike|SentinelOne|Sophos|McAfee|Trellix|Symantec|Windows\s*Defender|Elastic|osquery|Microsoft\s*Intune|Microsoft\\CCM|ScreenConnect|TeamViewer|AnyDesk|RustDesk|Splashtop|Atera|MeshAgent|Action1|Pulseway|N-able|SolarWinds|ManageEngine|PDQ))/i;
      const BENIGN_RUN_VALUE_NAMES = /(?:onedrive|sharepoint|groove|teams|edgeupdate|googleupdate|adobe.*updater|acrobat|java|zoom|slack|webex|citrix|vmware|okta|duo|intune|ccmexec|sccm|defender|securityhealth|officeclicktorun)/i;
      const BENIGN_RUN_VALUE_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:Microsoft\\OneDrive|Microsoft\\Teams|Microsoft\\EdgeUpdate|Google\\Update|Adobe|Java|Zoom|Slack|Cisco\s*Webex|Citrix|VMware|Okta|Duo|Windows\s*Defender|Microsoft\s*Office)|\\AppData\\Local\\(?:Microsoft\\OneDrive|Microsoft\\Teams|Google\\Update)|OneDriveSetup\.exe|OneDriveStandaloneUpdater\.exe|GoogleUpdate\.exe|MicrosoftEdgeUpdate\.exe|OfficeClickToRun\.exe|SecurityHealthSystray\.exe|MsMpEng\.exe|\\Office\d+\\GROOVE\.EXE)/i;
      const MICROSOFT_SYNC_SERVICE_NAMES = /(?:onedrive|sharepoint|groove|microsoft\s+sharepoint\s+workspace)/i;
      const MICROSOFT_PRODUCT_PATHS = /(?:\\AppData\\Local\\Microsoft\\OneDrive\\|Program\s*Files(?:\s*\(x86\))?\\Microsoft\s+OneDrive\\|Program\s*Files(?:\s*\(x86\))?\\Microsoft\\EdgeUpdate\\|Program\s*Files\\Common\s*Files\\Microsoft\s*Shared\\ClickToRun\\|Program\s*Files(?:\s*\(x86\))?\\Microsoft\s*Office\\|\\Office\d+\\)/i;
      const MICROSOFT_PRODUCT_BINARIES = /^(?:onedrive\.exe|groove\.exe|officeclicktorun\.exe|microsoftedgeupdate(?:core)?\.exe|outlook\.exe|winword\.exe|excel\.exe|powerpnt\.exe|onenote\.exe|teams\.exe|ms-teams\.exe|ms-teamsupdate\.exe)$/i;
      const _extractCommandExecutable = (cmd = "") => {
        const s = String(cmd || "").trim().replace(/^[`'"]+|[`'"]+$/g, "");
        if (!s) return "";
        const m = s.match(/^"([^"]+\.(?:exe|dll|cmd|bat|ps1|vbs))"/i) || s.match(/^([^\s]+\.(?:exe|dll|cmd|bat|ps1|vbs))/i);
        return (m ? m[1] : s.split(/\s+/)[0]).replace(/"/g, "");
      };
      const _isExpectedMicrosoftBinary = (cmd = "", signatureBlob = "") => {
        const exe = _extractCommandExecutable(cmd);
        if (!exe) return false;
        const base = exe.split("\\").pop() || "";
        if (!MICROSOFT_PRODUCT_BINARIES.test(base) || !MICROSOFT_PRODUCT_PATHS.test(exe)) return false;
        const requireMicrosoftSignature = !!options.requireMicrosoftSignature;
        const sig = String(signatureBlob || "").toLowerCase();
        const hasSigContext = /(?:signer|signature|signed)\s*:/.test(sig);
        if (requireMicrosoftSignature) {
          return /(?:signer|signature)\s*:\s*.*microsoft/.test(sig) || (/\bsigned\s*:\s*true\b/.test(sig) && /microsoft/.test(sig));
        }
        if (hasSigContext) {
          if (/\bsigned\s*:\s*false\b/.test(sig)) return false;
          if (/(?:signer|signature)\s*:\s*(?!.*microsoft)/.test(sig)) return false;
        }
        return true;
      };
      const PRIV_GROUP_PAT = /(?:^|\\)(?:administrators?|remote desktop users|remote management users|backup operators|server operators|account operators|print operators|hyper-v administrators|distributed com users|domain admins|enterprise admins|schema admins|dnsadmins|key admins|enterprise key admins|group policy creator owners|cert(?:ificate)? publishers|laps[_ ]readers|exchange (?:organization )?admins?|ras and ias servers|windows authorization access group|protected users|cloneable domain controllers)$/i;
      // Privileged user pattern — accounts that warrant escalated scoring on modification/reset
      const PRIV_USER_PAT = /(?:^|\\)(?:administrator|krbtgt|admin(?:istrator)?s?\b|.*admin.*|.*svc.*admin.*|.*da_.*|.*ea_.*)/i;
      // Centralized account-risk helper
      const _accountRisk = (username, groupName) => {
        if (!username && !groupName) return "normal";
        const u = (username || "").trim();
        const g = (groupName || "").trim();
        if (BUILTIN_ACCOUNT_PAT.test(u)) return "builtin";
        if (MACHINE_ACCOUNT_PAT.test(u)) return "machine";
        if (g && PRIV_GROUP_PAT.test(g)) return "privileged-group";
        if (u && PRIV_USER_PAT.test(u)) return "privileged-user";
        return "normal";
      };

      // --- Helper: check if service/process is whitelisted AV/EDR ---
      const CORTEX_OFFLINE_COLLECTOR_PAT = /(?:offline_collector_config\.json|--offline-collector|--collect-artifacts|XDR_Collector)/i;
      const isWhitelistedAV = (name, path) => {
        if (!name) return false;
        const n = name.replace(/"/g, "").trim();
        const p = (path || "").replace(/"/g, "").trim();
        // Explicit Palo Alto Cortex XDR payload binary: installed agent path or sanctioned offline collector CLI
        if (/cortex-xdr-payload\.exe/i.test(n) || /cortex-xdr-payload\.exe/i.test(p)) {
          if (/palo alto networks/i.test(p) || CORTEX_OFFLINE_COLLECTOR_PAT.test(p)) return true;
        }
        return AV_EDR_WHITELIST.some(w => w.namePattern.test(n) && (!p || w.pathPattern.test(p)));
      };

      // --- Known malicious / offensive tool service patterns ---
      const MALICIOUS_TOOLS = [
        { namePattern: /^(?:psexesvc|psexec)$/i, severity: "critical", reasons: ["PsExec service — lateral movement"] },
        { namePattern: /(?:cobalt.*strike|beacon)/i, severity: "critical", reasons: ["Cobalt Strike beacon service"] },
        { namePattern: /(?:mimikatz|mimilib|mimidrv)/i, severity: "critical", reasons: ["Mimikatz credential theft"] },
        { namePattern: /(?:meterpreter|metasploit|reverse.?shell)/i, severity: "critical", reasons: ["Offensive framework service"] },
        { namePattern: /^(?:smbexec|atexec|dcomexec|wmiexec)/i, severity: "critical", reasons: ["Impacket lateral movement"] },
        { namePattern: /(?:screenconnect|connectwise)/i, severity: "high", reasons: ["ScreenConnect remote access"] },
        { namePattern: /^anydesk$/i, severity: "high", reasons: ["AnyDesk remote access"] },
        { namePattern: /^rustdesk$/i, severity: "high", reasons: ["RustDesk remote access"] },
        { namePattern: /^teamviewer$/i, severity: "high", reasons: ["TeamViewer remote access"] },
        { namePattern: /^(?:YOURSERVICENAME|default_service|test_service|debug_service)$/i, severity: "critical", reasons: ["Default/test malware service name"] },
      ];

      // --- Helper: detect browser service legitimacy vs mimicry ---
      const BROWSER_SVC_PAT = /(?:chrome|edge|brave|firefox|opera|vivaldi|browser).*(?:update|updater|elevat)/i;
      const checkBrowserService = (name, cmd) => {
        if (!name || !BROWSER_SVC_PAT.test(name)) return null;
        if (LEGIT_BROWSER_PATHS.test(cmd || "")) return "legitimate";
        if (cmd && cmd.trim()) return "suspicious";
        return null;
      };

      // Filter out whitelisted items
      items = items.filter((item) => {
        // AV/EDR services from expected paths
        if (item.category === "Services" && item.name === "Service Installed") {
          const sn = item.artifact || item.details?.serviceName || "";
          const cp = item.command || item.details?.imagePath || item.details?.serviceFile || "";
          if (isWhitelistedAV(sn, cp)) return false;
        }
        // Scheduled Tasks: suppress known legitimate tasks
        if (item.category === "Scheduled Tasks") {
          const art = item.artifact || item.details?.taskName || "";
          const cmd = item.command || item.details?.executable || "";
          const noisyTaskEvent = item.name === "Task Updated" || item.name === "Task Updated (Security)"
            || item.name === "Task Registered" || item.name === "Boot Trigger Fired" || item.name === "Logon Trigger Fired"
            || item.name === "Task Action Started" || item.name === "Task Process Created";
          const taskActionBlob = `${item.details?.command || ""} ${item.details?.executable || ""} ${cmd || ""}`;
          const hasTaskMutationSignal = Boolean(
            item.details?._taskHidden
            || item.details?._taskElevated
            || item.details?._taskComHandler
            || (item.details?._taskTriggers || []).includes("registration")
            || SUSPICIOUS_CMDS.test(taskActionBlob)
            || ENCODING_INDICATORS.test(taskActionBlob)
          );
          // Legitimate Windows system tasks with known system executables
          if ((item.name === "Task Process Created" || item.name === "Task Action Started")
            && LEGIT_TASK_PREFIXES.test(art) && LEGIT_TASK_EXECUTABLES.test(cmd.split("\\").pop())) return false;
          // Explicit Windows scheduler maintenance tasks (UpdateOrchestrator/SPP) are high-volume benign noise
          if (noisyTaskEvent && LEGIT_WINDOWS_SCHED_TASKS.test(art) && !hasTaskMutationSignal) return false;
          // Broad Microsoft Windows scheduler noise suppression for lifecycle/trigger events.
          // Keep signals that have strong suspicious context handled later in scoring/correlation.
          if (noisyTaskEvent
            && LEGIT_WINDOWS_TASK_PREFIX.test(art)
            && (!cmd || LEGIT_WINDOWS_TASK_CMD_PATHS.test(cmd))
            && !SUSPICIOUS_CMDS.test(cmd || "")
            && !ENCODING_INDICATORS.test(cmd || "")
            && !hasTaskMutationSignal) return false;
          // Browser update tasks from expected paths (all task event types)
          if (LEGIT_BROWSER_TASKS.test(art) && (!cmd || LEGIT_BROWSER_PATHS.test(cmd))) return false;
          // Office / OneDrive / Teams updater tasks from expected paths are common and noisy
          if (LEGIT_VENDOR_TASKS.test(art) && (!cmd || LEGIT_VENDOR_TASK_PATHS.test(cmd) || _isExpectedMicrosoftBinary(cmd, `${item.detailsSummary || ""} ${JSON.stringify(item.details || {})}`))) return false;
          // Additional enterprise updater/management tasks from expected binaries
          if (LEGIT_ENTERPRISE_TASKS.test(art) && (!cmd || LEGIT_ENTERPRISE_TASK_PATHS.test(cmd))) return false;
        }
        return true;
      });

      // --- Registry value-data analysis helper ---
      const _analyzeValueData = (valueData, keyPath) => {
        const flags = [];
        if (!valueData) return flags;
        if (LOLBIN_PAT.test(valueData))
          flags.push("lolbin-in-value");
        if (/\\(?:Users\\|Temp\\|AppData\\|Downloads\\|Public\\)/i.test(valueData))
          flags.push("user-writable-path");
        if (/(?:base64|frombase64|-enc\s|-e\s|iex|invoke-|downloadstring|webclient)/i.test(valueData))
          flags.push("encoded-value");
        if (/\.(?:tmp|dat|log|txt|cfg|bin)$/i.test(valueData.trim()) && /ServiceDll|AppInit_DLLs|InprocServer32/i.test(keyPath || ""))
          flags.push("suspicious-extension");
        return flags;
      };

      for (const item of items) {
        let score = SEVERITY_SCORES[item.severity] || 4;
        const blob = item.detailsSummary + " " + JSON.stringify(item.details);
        const reasons = item.suspiciousReasons || [];
        if (SUSPICIOUS_PATHS.test(blob)) score += 1;
        if (SUSPICIOUS_CMDS.test(blob)) score += 1;
        if (ENCODING_INDICATORS.test(blob)) score += 1;

        // Check for known malicious tools — escalate severity
        const art = item.artifact || "";
        if (item.category === "Services" && art) {
          const cp = item.command || item.details?.imagePath || item.details?.serviceFile || "";
          if (isWhitelistedAV(art, cp)) {
            item.whitelisted = true;
            item.whitelistReason = "Known AV/EDR component";
            item.severity = "low";
            score = SEVERITY_SCORES.low;
          }
          for (const mt of MALICIOUS_TOOLS) {
            if (mt.namePattern.test(art)) {
              item.severity = mt.severity;
              score = Math.max(score, SEVERITY_SCORES[mt.severity] || 6);
              reasons.push(...mt.reasons);
            }
          }
          // Browser services: downgrade if legitimate path, escalate if mimicked
          const browserCheck = checkBrowserService(art, item.command || "");
          if (browserCheck === "legitimate") {
            item.severity = "low";
            score = SEVERITY_SCORES.low;
          } else if (browserCheck === "suspicious") {
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high);
            reasons.push("Browser service name from unexpected path — possible mimicry");
          }
          if (!item.whitelisted
            && ENTERPRISE_SERVICE_NAMES.test(art)
            && (!cp || ENTERPRISE_SERVICE_PATHS.test(cp))
            && !SUSPICIOUS_CMDS.test(cp || "")
            && !ENCODING_INDICATORS.test(cp || "")) {
            item.details._benignServiceContext = true;
            reasons.push("Known enterprise management/security service pattern");
            score -= 2;
          }
          if (!item.whitelisted && MICROSOFT_SYNC_SERVICE_NAMES.test(art) && _isExpectedMicrosoftBinary(cp, `${item.detailsSummary || ""} ${JSON.stringify(item.details || {})}`)) {
            item.details._benignServiceContext = true;
            reasons.push("Microsoft sync/service binary from expected install path");
            score -= 2;
          }
        }

        if (item.category === "Account Persistence") {
          const d = item.details || {};
          const groupName = d.groupName || "";
          const memberName = d.memberName || d.targetUser || d.samAccountName || "";
          const subjectUser = d.subjectUser || "";
          const tgtRisk = _accountRisk(memberName, groupName);
          if (tgtRisk === "builtin" || tgtRisk === "machine") {
            item.whitelisted = true;
            item.whitelistReason = "Built-in or machine account";
            item.severity = "low";
            score = SEVERITY_SCORES.low;
          } else if (/Member Added/.test(item.name)) {
            if (tgtRisk === "privileged-group") {
              reasons.push("privileged group membership");
              item.severity = item.name.includes("Local") ? "high" : "critical";
              score = Math.max(score, SEVERITY_SCORES[item.severity] || 6) + 1;
            } else {
              item.severity = "medium";
              score = Math.max(score, SEVERITY_SCORES.medium);
            }
          } else if (item.name === "User Account Created") {
            const creatorRisk = _accountRisk(subjectUser);
            if (creatorRisk !== "builtin" && creatorRisk !== "machine") {
              reasons.push("new account persistence");
              score += 1;
            } else {
              item.severity = "medium";
              score = Math.max(score, SEVERITY_SCORES.medium);
            }
          } else if (item.name === "User Password Reset") {
            const tgt = d.targetUser || "";
            const resetRisk = _accountRisk(tgt);
            if (resetRisk === "privileged-user" || resetRisk === "privileged-group") {
              reasons.push("Password reset on privileged account");
              item.severity = "high";
              score = Math.max(score, SEVERITY_SCORES.high) + 1;
            } else {
              // Check chain context: escalate if reset follows recent creation or precedes group-add
              item.severity = "medium";
              score = Math.max(score, SEVERITY_SCORES.medium);
            }
          } else if (item.name === "User Account Changed") {
            // 4738: attribute-level semantics
            const sp = _normalizeAcctField(d.scriptPath || "");
            const uac = _normalizeAcctField(d.userAccountControl || "");
            const hp = _normalizeAcctField(d.homeDirectory || "");
            const pp = _normalizeAcctField(d.profilePath || "");
            const up = _normalizeAcctField(d.userParameters || "");
            const del = _normalizeAcctField(d.allowedToDelegateTo || "");
            const tgt = d.targetUser || "";
            d.scriptPath = sp; d.userAccountControl = uac; d.homeDirectory = hp; d.profilePath = pp; d.userParameters = up; d.allowedToDelegateTo = del;
            // 4738 is often noisy in enterprise baselines; default to medium unless strong indicators are present.
            item.severity = "medium";
            score = Math.min(score, SEVERITY_SCORES.medium);
            if (_isMeaningfulScriptPath(sp)) {
              reasons.push("Logon script path set/changed");
              item.severity = "critical";
              score = Math.max(score, SEVERITY_SCORES.critical) + 1;
            }
            if (_isMeaningfulDelegation(del)) {
              reasons.push("Delegation target configured");
              item.severity = "critical";
              score = Math.max(score, SEVERITY_SCORES.critical) + 1;
            }
            if (uac && /%%2087|DONT_REQ_PREAUTH/i.test(uac)) {
              reasons.push("Kerberos pre-auth disabled (AS-REP roast risk)");
              item.severity = "critical";
              score = Math.max(score, SEVERITY_SCORES.critical) + 1;
            }
            if (uac && /%%2089|USE_DES_KEY_ONLY/i.test(uac)) {
              reasons.push("DES-only Kerberos enabled (weak encryption)");
              score += 1;
            }
            if (uac && /%%2082|PASSWD_NOTREQD/i.test(uac)) {
              reasons.push("Password not required flag set");
              item.severity = "high";
              score = Math.max(score, SEVERITY_SCORES.high) + 1;
            }
            if (!_isUnsetAcctField(up) && !/^%%\d+$/.test(up)) {
              reasons.push("UserParameters modified");
              score += 1;
            }
            if ((!_isUnsetAcctField(hp) && !/^%%\d+$/.test(hp)) || (!_isUnsetAcctField(pp) && !/^%%\d+$/.test(pp))) {
              reasons.push("Home directory or profile path changed");
              score += 1;
            }
            // If nothing specific triggered, keep as medium baseline
            if (reasons.length === 0) {
              item.severity = "medium";
              score = Math.max(score, SEVERITY_SCORES.medium);
            }
          }
        }

        // --- Domain Persistence scoring ---
        if (item.category === "Domain Persistence") {
          const d = item.details || {};
          const objDN = (d.objectDN || "").toLowerCase();
          const attr = (d.attributeName || "").toLowerCase();
          const objClass = (d.objectClass || "").toLowerCase();
          const subjectUser = d.subjectUser || "";
          // AdminSDHolder modifications — always critical
          if (/adminsdholder/i.test(objDN)) {
            reasons.push("AdminSDHolder modification — domain-wide privilege persistence");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
          }
          // GPO tampering
          if (/cn=policies/i.test(objDN) || objClass === "grouppolicycontainer") {
            if (/gpcfilesyspath|gpcmachineextensionnames|gpcuserextensionnames/i.test(attr)) {
              reasons.push("GPO configuration modified — potential domain-wide persistence");
              item.severity = "critical";
              score = Math.max(score, SEVERITY_SCORES.critical) + 1;
            } else if (item.name === "AD Object Created") {
              reasons.push("New GPO created");
              item.severity = "high";
              score = Math.max(score, SEVERITY_SCORES.high) + 1;
            } else if (item.name === "AD Object Deleted") {
              reasons.push("GPO deleted — potential anti-forensics");
              item.severity = "high";
              score = Math.max(score, SEVERITY_SCORES.high) + 1;
            }
          }
          // msDS-KeyCredentialLink (Shadow Credentials)
          if (attr === "msds-keycredentiallink") {
            reasons.push("Shadow Credentials attack — msDS-KeyCredentialLink modified");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
          }
          // SPN manipulation (Kerberoasting setup)
          if (attr === "serviceprincipalname") {
            reasons.push("SPN modified — potential Kerberoasting setup");
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
          }
          // scriptPath on user objects
          if (attr === "scriptpath") {
            reasons.push("Logon script path modified on AD object");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 1;
          }
          // Privileged group membership modification via 5136
          if (attr === "member" && PRIV_GROUP_PAT.test(objDN)) {
            reasons.push("Privileged group membership changed via AD modification");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 1;
          }
          // SIDHistory injection
          if (attr === "sidhistory") {
            reasons.push("SIDHistory modified — potential privilege escalation");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
          }
          // nTSecurityDescriptor (ACL modification)
          if (attr === "ntsecuritydescriptor") {
            reasons.push("Security descriptor modified on AD object");
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
          }
          // UAC flags on AD objects
          if (attr === "useraccountcontrol") {
            reasons.push("User account control flags changed on AD object");
            score += 1;
          }
          // Delegation settings
          if (/msds-allowedtodelegateto/i.test(attr)) {
            reasons.push("Constrained delegation configured");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 1;
          }
          // Trusted domain object creation/deletion
          if (objClass === "trusteddomain") {
            reasons.push("Trust relationship modified");
            item.severity = "critical";
            score = Math.max(score, SEVERITY_SCORES.critical) + 1;
          }
          // Allowlist: suppress machine account and SYSTEM-initiated changes
          if (BUILTIN_ACCOUNT_PAT.test(subjectUser) || MACHINE_ACCOUNT_PAT.test(subjectUser)) {
            item.whitelisted = true;
            item.whitelistReason = "System/machine account AD change";
            item.severity = "low";
            score = SEVERITY_SCORES.low;
          }
          // If nothing specific triggered, keep at medium baseline
          if (reasons.length === 0 && !item.whitelisted) {
            item.severity = "medium";
            score = Math.max(score, SEVERITY_SCORES.medium);
          }
        }

        // Account chain correlation boost
        if (item.details?._acctChainLen >= 2 && !item.whitelisted) {
          reasons.push(`Account persistence chain (${item.details._acctChainEvents.join(" → ")})`);
          score += Math.min(item.details._acctChainLen - 1, 3);
        }
        // Cross-technique: account event followed by persistence mechanism
        if (item.details?._acctToPersistenceSeen && !item.whitelisted) {
          if (item.category === "Account Persistence") {
            // Account event side: note the follow-on persistence technique
            const tech = item.details._acctToPersistenceTechnique || "persistence";
            reasons.push(`Account change followed by ${tech}`);
            score += 1;
          } else {
            // Persistence item side: note that the actor also manipulated accounts
            const types = item.details._acctToPersistenceTypes || [];
            reasons.push(`Persistence by user with recent account activity (${types.join(", ")})`);
            score += 2;
          }
        }

        // Suspicious artifact/task indicators
        if (art && item.category === "Scheduled Tasks") {
          if (art.startsWith("\\") && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Non-standard task path");
            score += 1;
          }
          if (/^\\{[0-9a-f-]+}$/i.test(art)) {
            reasons.push("GUID-named task");
            score += 1;
          }
        }
        if (item.category === "Scheduled Tasks") {
          const cmd = item.command || item.details?.executable || "";
          const noisyTaskEvent = item.name === "Task Updated" || item.name === "Task Updated (Security)"
            || item.name === "Task Registered" || item.name === "Boot Trigger Fired" || item.name === "Logon Trigger Fired";
          const benignTaskContext = LEGIT_TASK_PREFIXES.test(art)
            || LEGIT_BROWSER_TASKS.test(art)
            || LEGIT_VENDOR_TASKS.test(art)
            || LEGIT_ENTERPRISE_TASKS.test(art);
          const expectedTaskPath = !cmd || LEGIT_BROWSER_PATHS.test(cmd) || LEGIT_VENDOR_TASK_PATHS.test(cmd) || LEGIT_ENTERPRISE_TASK_PATHS.test(cmd);
          const hasStrongTaskSignals = Boolean(item.details?._taskHidden || item.details?._taskElevated || item.details?._taskComHandler || item.details?._ps4104Seen || item.details?._serviceProcessParentSuspicious);
          if (noisyTaskEvent && benignTaskContext && expectedTaskPath && !hasStrongTaskSignals) {
            item.details._benignTaskContext = true;
            reasons.push("Common enterprise/system task activity");
            score -= 2;
          }
        }
        // LOLBin execution in non-Microsoft context
        const _hasLolbin = item.command && LOLBIN_PAT.test(item.command) && art && !LEGIT_TASK_PREFIXES.test(art);
        const _hasUserPath = item.command && /\\Users\\|\\Temp\\|\\AppData\\|\\Downloads\\|\\Public\\/i.test(item.command);
        const _boostCats = new Set(["Services", "Scheduled Tasks", "Registry Autorun", "IFEO", "AppInit DLLs"]);
        if (_hasLolbin && !item.whitelisted) {
          reasons.push("LOLBin execution");
          if (_boostCats.has(item.category)) score += 1;
        }
        if (_hasUserPath && !item.whitelisted) {
          reasons.push("User-writable path");
          if (_boostCats.has(item.category)) score += 1;
        }
        if (_hasLolbin && _hasUserPath && !item.whitelisted && _boostCats.has(item.category)) {
          reasons.push("LOLBin from user-writable path — high-confidence abuse");
          score += 1; // synergy
        }
        // RMM tool context scoring (service installs only — not auto-malicious, boosted by suspicious context)
        if (item.rmmTool && item.category === "Services" && !item.whitelisted) {
          const rmmCmd = item.command || item.details?.imagePath || item.details?.serviceFile || "";
          const RMM_EXPECTED_PATHS = /(?:Program\s*Files(?:\s*\(x86\))?\\(?:ScreenConnect|AnyDesk|TeamViewer|Atera|Splashtop|RustDesk|ConnectWise|PDQ|MeshAgent|Action1|SimpleHelp|TacticalRMM|FleetDeck|DWService|HopToDesk|LiteManager|UltraVNC|TigerVNC|RAdmin|Zoho|Pulseway|LabTech|Kaseya|SolarWinds|N-able))/i;
          const rmmFromExpectedPath = RMM_EXPECTED_PATHS.test(rmmCmd);
          const rmmFromUserPath = _hasUserPath;
          if (rmmFromUserPath) {
            reasons.push("RMM tool from user-writable/temp path");
            score += 2;
          } else if (!rmmFromExpectedPath) {
            reasons.push("RMM tool from non-standard path");
            score += 1;
          }
          // Synergy: RMM + LOLBin or RMM + browser mimicry or RMM + 4104 script
          if (_hasLolbin) { reasons.push("RMM installed via LOLBin"); score += 1; }
          if (item.details?._ps4104Seen) { reasons.push("RMM installed via PowerShell script"); score += 1; }
        }
        // Anti-forensics: task deletion
        if (item.name === "Task Deleted" && art && !LEGIT_TASK_PREFIXES.test(art)) {
          reasons.push("Non-standard task deleted");
          score += 1;
        }

        // --- Registry value-data semantics (registry-mode items + 4657 fallback) ---
        if (item.mode === "registry" || item.details?._is4657Fallback) {
          const vdFlags = _analyzeValueData(item.command, item.artifact);
          for (const f of vdFlags) {
            if (f === "lolbin-in-value") { reasons.push("LOLBin in registry value"); score += 2; }
            else if (f === "user-writable-path") { reasons.push("User-writable path in registry value"); score += 1; }
            else if (f === "encoded-value") { reasons.push("Encoded/obfuscated registry value"); score += 2; }
            else if (f === "suspicious-extension") { reasons.push("Suspicious file extension for DLL value"); score += 1; }
          }
          if ((item.category === "Run Keys" || item.category === "Registry Autorun")
            && item.command?.trim()
            && !item.details?._ps4104Seen
            && !vdFlags.includes("lolbin-in-value")
            && !vdFlags.includes("encoded-value")
            && !vdFlags.includes("user-writable-path")) {
            const valueName = (item.details?.valueName || "").trim();
            if (BENIGN_RUN_VALUE_NAMES.test(valueName) || BENIGN_RUN_VALUE_PATHS.test(item.command) || _isExpectedMicrosoftBinary(item.command, `${item.detailsSummary || ""} ${JSON.stringify(item.details || {})}`)) {
              item.details._benignRunKeyContext = true;
              reasons.push("Common updater/enterprise autorun");
              score -= 2;
            }
          }
        }

        // --- IFEO-specific inspection ---
        if (item.category === "IFEO") {
          const targetBin = (item.artifact || "").split("\\").pop() || "";
          const ACCESSIBILITY_BINS = /^(?:sethc|utilman|osk|narrator|magnify|displayswitch|atbroker)(?:\.exe)?$/i;
          if (ACCESSIBILITY_BINS.test(targetBin)) {
            reasons.push("Accessibility binary IFEO hijack — sticky keys backdoor");
            item.severity = "critical";
            score = Math.max(score, 9);
          }
          if (item.command && /(?:cmd\.exe|powershell|pwsh|mshta)$/i.test(item.command.trim())) {
            reasons.push("LOLBin as IFEO debugger");
            score += 2;
          }
        }

        // --- AppInit_DLLs conditional escalation ---
        if (item.category === "AppInit DLLs") {
          const vn = (item.details?.valueName || "").toLowerCase();
          if (vn === "loadappinit_dlls" && item.command?.trim() === "1") {
            reasons.push("AppInit_DLLs loading enabled");
            score += 1;
          } else if (vn === "appinit_dlls" && item.command?.trim()) {
            reasons.push("AppInit_DLLs path set — DLL injection vector");
            score += 2;
            if (_analyzeValueData(item.command, item.artifact).includes("user-writable-path")) score += 1;
          }
        }

        // --- Silent Process Exit semantics ---
        if (item.category === "Silent Process Exit") {
          const vn = (item.details?.valueName || "").toLowerCase();
          if (vn === "monitorprocess" && item.command?.trim()) {
            reasons.push("Silent exit monitor process configured");
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("lolbin-in-value")) { reasons.push("LOLBin as monitor process"); score += 1; }
            if (vdFlags.includes("user-writable-path")) { reasons.push("Monitor process from user-writable path"); score += 1; }
          }
        }

        // --- Logon Script semantics ---
        if (item.category === "Logon Script") {
          if (item.command?.trim()) {
            reasons.push("User logon script path set");
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("lolbin-in-value")) { reasons.push("LOLBin in logon script"); score += 1; }
            if (vdFlags.includes("user-writable-path")) { reasons.push("Logon script from user-writable path"); score += 1; }
            if (vdFlags.includes("encoded-value")) { reasons.push("Obfuscated logon script command"); score += 2; }
          }
        }

        // --- AppCert DLLs semantics ---
        if (item.category === "AppCert DLLs") {
          if (item.command?.trim()) {
            reasons.push("AppCert DLL path set — loaded into every process calling CreateProcess");
            score = Math.max(score, SEVERITY_SCORES.critical) + 2;
            if (_analyzeValueData(item.command, item.artifact).includes("user-writable-path")) {
              reasons.push("AppCert DLL from user-writable path");
              score += 1;
            }
          }
        }

        // --- Credential Provider semantics ---
        if (item.category === "Credential Providers") {
          reasons.push("Custom credential provider registered");
          score = Math.max(score, SEVERITY_SCORES.high) + 1;
          if (item.command?.trim()) {
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("user-writable-path")) { reasons.push("Credential provider DLL from user-writable path"); score += 2; }
            // Score system vs non-system DLL path
            const dllPath = item.command.trim().toLowerCase().replace(/"/g, "");
            if (dllPath && !/^(?:c:\\windows\\|c:\\program files)/i.test(dllPath)) {
              reasons.push("Credential provider from non-system path");
              score += 1;
            }
          }
        }

        // --- Command Processor AutoRun semantics ---
        if (item.category === "Command Processor") {
          if (item.command?.trim()) {
            reasons.push("cmd.exe AutoRun command set");
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("lolbin-in-value")) { reasons.push("LOLBin in cmd AutoRun"); score += 2; }
            if (vdFlags.includes("user-writable-path")) { reasons.push("AutoRun from user-writable path"); score += 1; }
            if (vdFlags.includes("encoded-value")) { reasons.push("Obfuscated AutoRun command"); score += 2; }
          }
        }

        // --- Explorer Autoruns (ShellServiceObjectDelayLoad) semantics ---
        if (item.category === "Explorer Autoruns") {
          if (item.command?.trim()) {
            reasons.push("ShellServiceObjectDelayLoad entry");
            score = Math.max(score, SEVERITY_SCORES.high);
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("user-writable-path")) { reasons.push("SSODL DLL from user-writable path"); score += 2; }
          }
        }

        // --- Netsh Helper DLLs semantics ---
        if (item.category === "Netsh Helper DLLs") {
          if (item.command?.trim()) {
            reasons.push("Netsh helper DLL registered");
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
            const vdFlags = _analyzeValueData(item.command, item.artifact);
            if (vdFlags.includes("user-writable-path")) { reasons.push("Netsh helper from user-writable path"); score += 2; }
            // Non-system DLL path is very suspicious for netsh helpers
            const dllPath = item.command.trim().toLowerCase().replace(/"/g, "");
            if (dllPath && !/^(?:c:\\windows\\|c:\\program files)/i.test(dllPath)) {
              reasons.push("Netsh helper from non-system path");
              score += 1;
            }
          }
        }

        // --- DLL Hijacking noise reduction ---
        if (item.category === "DLL Hijacking") {
          const dll = (item.details?.imageLoaded || "").toLowerCase().replace(/"/g, "").trim();
          const proc = (item.details?.image || "").toLowerCase().replace(/"/g, "").trim();
          const SYSTEM_DLL_PATHS = /^(?:c:\\windows\\|c:\\program files(?:\s*\(x86\))?\\)/i;
          const isUserWritable = /\\(?:Users\\|Temp\\|AppData\\|Downloads\\|Public\\|ProgramData\\)/i.test(dll);
          const isTempProc = /\\(?:Users\\|Temp\\|AppData\\|Downloads\\|Public\\)/i.test(proc);
          if (isUserWritable) {
            reasons.push("Unsigned DLL from user-writable path");
            item.severity = "high";
            score = Math.max(score, SEVERITY_SCORES.high) + 1;
            if (isTempProc) { reasons.push("Loaded by process in user-writable path"); score += 1; }
          } else if (!SYSTEM_DLL_PATHS.test(dll)) {
            // Non-standard but not user-writable — moderate signal
            reasons.push("Unsigned DLL from non-standard path");
          } else {
            // System/vendor path — likely benign unsigned DLL (driver components, etc.)
            item.severity = "low";
            item.whitelisted = true;
            item.whitelistReason = "Unsigned DLL in system/vendor path";
            score = SEVERITY_SCORES.low;
          }
        }

        // --- Service subtypes ---
        if (item.category === "Services") {
          if (item.details?._is4657Fallback) {
            // 4657 re-categorized as Services — treat like registry mode
            if (/servicedll/i.test(item.details?.targetObject || "")) { item.subtype = "service-dll"; reasons.push("ServiceDll modification (4657)"); score += 1; }
            else if (/failurecommand/i.test(item.details?.targetObject || "")) { item.subtype = "service-failure"; reasons.push("Service FailureCommand set (4657)"); score += 2; }
            else item.subtype = "service-registry";
          } else if (item.mode === "evtx") {
            if (item.name === "Service StartType Changed") {
              item.subtype = "service-starttype";
              const nt = (item.details?.newStartType || "").toLowerCase();
              if (/auto/i.test(nt)) {
                reasons.push("Service set to auto start");
                score += 1;
              }
              if (/disabled/i.test((item.details?.oldStartType || "").toLowerCase()) && /auto|demand/i.test(nt)) {
                reasons.push("Disabled service re-enabled");
                score += 1;
              }
            } else {
              item.subtype = "service-install";
            }
          } else if (item.mode === "registry") {
            const vn = (item.details?.valueName || "").toLowerCase();
            if (vn === "imagepath") item.subtype = "service-imagepath";
            else if (vn === "servicedll") { item.subtype = "service-dll"; reasons.push("ServiceDll modification"); score += 1; }
            else if (vn === "failurecommand") { item.subtype = "service-failure"; reasons.push("Service FailureCommand set"); score += 2; }
            else item.subtype = "service-registry";
          }
          // Correlation-derived subtype refinement (most specific wins)
          if (item.details?._serviceStarted) item.subtype = "service-start-confirmed";
          else if (item.details?._serviceProcessStarted) item.subtype = "service-process-confirmed";
          // RMM service subtype (after correlation, so it layers on top)
          if (item.rmmTool) item.subtype = (item.subtype === "service-start-confirmed" || item.subtype === "service-process-confirmed") ? "service-rmm-confirmed" : "service-rmm";
        }

        // --- Task subtypes ---
        if (item.category === "Scheduled Tasks") {
          if (item.name === "Task Deleted" || item.name === "Scheduled Task Deleted") {
            item.subtype = "task-deleted";
          } else if (item.name === "Task Process Created" || item.name === "Task Action Started") {
            item.subtype = "task-execution";
            if (item.command && SUSPICIOUS_CMDS.test(item.command) && !LEGIT_TASK_PREFIXES.test(art)) {
              reasons.push("Suspicious task execution");
              score += 1;
            }
          } else if (item.name === "Task Registered" || item.name === "Scheduled Task Created") {
            item.subtype = "task-created";
          } else if (item.name === "Task Updated" || item.name === "Task Updated (Security)") {
            item.subtype = "task-updated";
          } else if (item.name === "Boot Trigger Fired" || item.name === "Logon Trigger Fired") {
            item.subtype = "task-trigger";
          } else {
            item.subtype = "task-other";
          }
          // Short/random task name detection
          const leafName = (art || "").split("\\").pop() || "";
          if (leafName && leafName.length <= 4 && /^[a-zA-Z0-9]+$/.test(leafName) && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Short random task name");
            score += 1;
          }
          // Deep XML semantics (4698/4702): hidden, elevated, COM handler, trigger types
          if (item.details?._taskHidden && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Hidden task");
            score += 2;
          }
          if (item.details?._taskElevated && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Runs with highest privileges");
            score += 1;
          }
          if (item.details?._taskComHandler && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("COM handler task");
            score += 1;
          }
          const trigs = item.details?._taskTriggers || [];
          if (trigs.includes("boot") || trigs.includes("logon")) {
            if (!LEGIT_TASK_PREFIXES.test(art)) {
              reasons.push(`Persistence trigger: ${trigs.filter(t => t === "boot" || t === "logon").join("+")}`);
              score += 1;
            }
          }
          if (trigs.includes("registration") && !LEGIT_TASK_PREFIXES.test(art)) {
            reasons.push("Immediate execution on registration");
            score += 1;
          }
        }

        // --- Confidence-based score adjustment (from cross-event correlation) ---
        if (item.confidence === "confirmed" || item.confidence === "likely") {
          const src = item.details?._serviceStarted ? "service start (7036)"
            : item.details?._serviceProcessStarted ? "process creation"
            : item.details?._svcControlSeen ? "service control request (7035)"
            : item.details?._serviceExecSeen ? "registry/DLL evidence"
            : item.details?._execSeen ? "autorun execution"
            : item.details?._wmiComplete ? "complete WMI subscription"
            : item.details?._wmiPartial ? "partial WMI subscription"
            : item.details?._ps4104Seen ? "PowerShell script block (4104)"
            : item.details?._ps4104Standalone ? "PowerShell script block (4104)"
            : item.details?._is4657Fallback ? "Security 4657 registry audit"
            : item.details?._acctChainLen ? "account persistence chain"
            : item.details?._acctToPersistenceSeen ? "account-to-persistence correlation"
            : "cross-event";
          // Whitelist-aware: whitelisted items get confidence but not risk boost
          if (!item.whitelisted) {
            const weakServiceCorrelation = item.category === "Services"
              && item.confidence === "likely"
              && (item.details?._svcDisplayNameMatch
                || (item.details?._svcControlSeen && !item.details?._serviceStarted && !item.details?._serviceProcessStarted));
            const weakStandalone4104 = item.details?._ps4104Standalone && !item.details?._ps4104Strong;
            if (!weakServiceCorrelation && !weakStandalone4104) {
              reasons.push(`Execution corroborated by ${src}`);
              if (item.confidence === "confirmed") score += 2;
              else score += 1; // likely gets smaller boost
            } else {
              reasons.push("Correlation signal present but low-fidelity");
            }
            // Suspicious parent process in service correlation
            if (item.details?._serviceProcessParentSuspicious) {
              const pb = (item.details._serviceProcessParent || "").split("\\").pop();
              reasons.push(`Unexpected parent process: ${pb}`);
              score += 1;
            }
          }
        } else if (item.confidence === "present") {
          score -= 1;
        }

        // --- 4657 lower-fidelity dampener: offset confidence boost unless strong semantics ---
        if (item.details?._is4657Fallback && item.confidence === "likely" && !item.whitelisted) {
          const _4657Strong = new Set(["IFEO", "AppInit DLLs", "Winlogon", "Boot Execute", "LSA", "Silent Process Exit", "AppCert DLLs", "Logon Script", "Command Processor", "Netsh Helper DLLs"]);
          if (!_4657Strong.has(item.category)) {
            score -= 1; // offset the +1 from "likely" confidence for weaker 4657 signals
          }
        }
        if (item.details?._4657NoKeyPath) {
          score -= 1; // further penalize when key path couldn't be extracted
        }

        // --- 4104-specific scoring boosts ---
        const _ps4104Ind = item.details?._ps4104SuspiciousIndicators || [];
        if (item.details?._ps4104Seen && !item.whitelisted) {
          reasons.push("Created via PowerShell script");
          score += 1;
          if (_ps4104Ind.length > 0) { score += Math.min(_ps4104Ind.length, 3); }
        }
        if (item.details?._ps4104Standalone && !item.whitelisted) {
          const indSet = new Set(_ps4104Ind);
          if (indSet.has("EncodedCommand") || indSet.has("FromBase64String")) { reasons.push("Encoded/obfuscated payload"); score += 2; }
          if (indSet.has("DownloadString") || indSet.has("Net.WebClient") || indSet.has("Start-BitsTransfer") || indSet.has("Web download")) { reasons.push("Remote payload download"); score += 2; }
          if (indSet.has("Invoke-Expression")) { reasons.push("Dynamic code execution (IEX)"); score += 1; }
          if (indSet.has("Assembly loading")) { reasons.push("In-memory assembly loading"); score += 2; }
          if (indSet.has("Defender exclusion") || indSet.has("Defender disable")) { reasons.push("Security product tampering"); score += 2; }
          if ((item.details.matchedPatterns || []).length >= 2) { reasons.push("Multi-technique persistence script"); score += 2; }
          if (!item.details?._ps4104Strong) {
            reasons.push("Standalone script-block signal without strong malicious indicators");
            score -= 2;
          }
        }

        item.triageScore = score;
        item.riskScore = Math.min(score, 10);
        item.isSuspicious = reasons.length > 0;
        item.suspiciousReasons = reasons;
      }

      // --- Evidence pills from suspiciousReasons + context ---
      for (const item of items) {
        const pills = [];
        for (const r of (item.suspiciousReasons || [])) {
          const rl = r.toLowerCase();
          if (rl.includes("user-writable path"))          pills.push({ text: "user-writable path", type: "execution" });
          else if (rl.includes("lolbin"))                  pills.push({ text: "LOLBin execution", type: "execution" });
          else if (rl.includes("encoded") || rl.includes("base64") || rl.includes("invoke-expression"))
                                                           pills.push({ text: "encoded payload", type: "execution" });
          else if (rl.includes("browser") && rl.includes("unexpected"))
                                                           pills.push({ text: "path mimicry", type: "context" });
          else if (rl.includes("guid-named"))              pills.push({ text: "GUID task", type: "context" });
          else if (rl.includes("non-standard task"))       pills.push({ text: "non-standard task", type: "context" });
          else if (rl.includes("psexec"))                  pills.push({ text: "PsExec", type: "execution" });
          else if (rl.includes("remote access"))           pills.push({ text: "remote access tool", type: "execution" });
          else if (rl.includes("task deleted"))            pills.push({ text: "anti-forensics", type: "correlation" });
          else                                             pills.push({ text: r.substring(0, 40), type: "context" });
        }
        if (item.rmmTool)                                  pills.push({ text: "RMM tool", type: "execution" });
        if (item.details?._is4657Fallback)                 pills.push({ text: "Security 4657 fallback", type: "context" });
        if (/WOW6432Node/i.test(item.details?.targetObject || item.artifact || "")) pills.push({ text: "WOW64 (32-bit)", type: "execution" });
        if (item.category === "WMI Persistence") {
          const wt = item.details?._wmiType || "";
          if (/CommandLine/i.test(wt))       pills.push({ text: "CmdLine consumer", type: "execution" });
          else if (/ActiveScript/i.test(wt)) pills.push({ text: "script consumer", type: "execution" });
          else if (/EventFilter|__Event/i.test(wt)) pills.push({ text: "event filter", type: "context" });
          else if (/Binding/i.test(wt))      pills.push({ text: "WMI binding", type: "context" });
          else if (wt)                       pills.push({ text: wt.replace(/EventConsumer$/i, "").trim() || "WMI consumer", type: "context" });
          else                               pills.push({ text: "WMI consumer", type: "context" });
          if (item.details?._wmiCommand)     pills.push({ text: "has payload", type: "execution" });
        }
        if (item.category === "Silent Process Exit")       pills.push({ text: "silent exit monitor", type: "execution" });
        if (item.category === "Logon Script")              pills.push({ text: "logon script", type: "execution" });
        if (item.category === "AppCert DLLs")              pills.push({ text: "AppCert DLL", type: "execution" });
        if (item.category === "Credential Providers")      pills.push({ text: "credential provider", type: "execution" });
        if (item.category === "Command Processor")          pills.push({ text: "cmd AutoRun", type: "execution" });
        if (item.category === "Explorer Autoruns")          pills.push({ text: "SSODL", type: "execution" });
        if (item.category === "Netsh Helper DLLs")          pills.push({ text: "netsh helper", type: "execution" });
        if (item.details?._svcControlSeen)                  pills.push({ text: "7035 control request", type: "correlation" });
        // Domain Persistence pills
        if (item.category === "Domain Persistence") {
          const _attr = (item.details?.attributeName || "").toLowerCase();
          if (/adminsdholder/i.test(item.details?.objectDN || "")) pills.push({ text: "AdminSDHolder", type: "execution" });
          if (_attr === "msds-keycredentiallink")                  pills.push({ text: "Shadow Credentials", type: "execution" });
          if (_attr === "serviceprincipalname")                    pills.push({ text: "SPN change", type: "execution" });
          if (/cn=policies/i.test(item.details?.objectDN || ""))   pills.push({ text: "GPO", type: "execution" });
          if (_attr === "sidhistory")                               pills.push({ text: "SIDHistory", type: "execution" });
          if (_attr === "ntsecuritydescriptor")                     pills.push({ text: "ACL change", type: "context" });
          if (_attr === "member")                                   pills.push({ text: "group membership", type: "context" });
          if (item.details?.objectClass)                            pills.push({ text: item.details.objectClass, type: "context" });
        }
        // Account chain pill
        if (item.details?._acctChainLen >= 2) {
          pills.push({ text: `${item.details._acctChainLen}-step chain`, type: "correlation" });
        }
        // Cross-technique: account → persistence pill
        if (item.details?._acctToPersistenceSeen) {
          if (item.category === "Account Persistence") {
            pills.push({ text: `→ ${item.details._acctToPersistenceTechnique || "persistence"}`, type: "correlation" });
          } else {
            pills.push({ text: "acct change by same user", type: "correlation" });
          }
        }
        // 4738 Account Changed pills
        if (item.name === "User Account Changed") {
          if (_isMeaningfulScriptPath(item.details?.scriptPath || "")) pills.push({ text: "logon script", type: "execution" });
          if (_isMeaningfulDelegation(item.details?.allowedToDelegateTo || "")) pills.push({ text: "delegation", type: "execution" });
          if (/DONT_REQ_PREAUTH|%%2087/i.test(item.details?.userAccountControl || "")) pills.push({ text: "AS-REP roast", type: "execution" });
        }
        if (item.computer)                                 pills.push({ text: item.computer, type: "target" });
        if (item.details?.hiveScope)                       pills.push({ text: item.details.hiveScope, type: "context" });
        if (item.whitelistReason)                          pills.push({ text: item.whitelistReason, type: "context" });
        // Service correlation pills
        if (item.details?._serviceStarted)                 pills.push({ text: item.details._svcDisplayNameMatch ? "7036 display-name match" : "service started", type: "correlation" });
        if (item.details?._serviceProcessStarted)          pills.push({ text: "service process observed", type: "correlation" });
        if (item.details?._serviceProcessParent) {
          const pb = (item.details._serviceProcessParent || "").split("\\").pop();
          if (pb === "services.exe")                       pills.push({ text: "started by services.exe", type: "correlation" });
          else if (item.details._serviceProcessParentSuspicious) pills.push({ text: `unexpected parent: ${pb}`, type: "execution" });
        }
        if (item.details?._serviceExecSeen)                pills.push({ text: "registry/DLL evidence", type: "correlation" });
        // WMI + autorun correlation pills
        if (item.details?._wmiComplete)                    pills.push({ text: "complete WMI sub", type: "correlation" });
        if (item.details?._wmiPartial)                     pills.push({ text: "orphaned WMI", type: "correlation" });
        if (item.details?._execSeen)                       pills.push({ text: "autorun executed", type: "correlation" });
        // 4104 correlation/standalone pills
        if (item.details?._ps4104Seen) {
          pills.push({ text: "created via PowerShell", type: "correlation" });
          const sp = item.details._ps4104ScriptPath;
          if (sp) pills.push({ text: sp.split(/[/\\]/).pop(), type: "context" });
        }
        if (item.details?._ps4104Standalone) {
          pills.push({ text: "script block", type: "context" });
          if ((item.details.fragmentCount || 1) > 1) pills.push({ text: `${item.details.fragmentCount} fragments`, type: "context" });
          const ind4104 = item.details._ps4104SuspiciousIndicators || [];
          for (const lbl of ind4104) {
            if (/Encoded|Base64/i.test(lbl))           pills.push({ text: "encoded payload", type: "execution" });
            else if (/Download|WebClient|Bits/i.test(lbl)) pills.push({ text: "download", type: "execution" });
            else if (/Invoke-Expression|iex/i.test(lbl))   pills.push({ text: "IEX", type: "execution" });
            else if (/Defender|MpPreference/i.test(lbl))   pills.push({ text: "security tampering", type: "execution" });
            else if (/Assembly/i.test(lbl))                pills.push({ text: "assembly load", type: "execution" });
          }
        }
        // Confidence pill (only for confirmed/likely)
        if (item.confidence === "confirmed")               pills.push({ text: "confirmed", type: "correlation" });
        else if (item.confidence === "likely")             pills.push({ text: "likely", type: "correlation" });
        // Subtype pills
        if (item.subtype === "service-dll")                pills.push({ text: "ServiceDll", type: "context" });
        if (item.subtype === "service-failure")            pills.push({ text: "FailureCommand", type: "context" });
        if (item.subtype === "service-starttype")          pills.push({ text: "start type change", type: "context" });
        if (item.subtype === "service-rmm")               pills.push({ text: "remote access svc", type: "context" });
        if (item.subtype === "service-rmm-confirmed")     pills.push({ text: "remote access svc", type: "execution" });
        if (item.subtype === "task-execution")             pills.push({ text: "task executed", type: "execution" });
        if (item.subtype === "task-trigger")               pills.push({ text: "trigger fired", type: "execution" });
        // Task XML semantic pills
        if (item.details?._taskHidden)                     pills.push({ text: "hidden", type: "execution" });
        if (item.details?._taskElevated)                   pills.push({ text: "elevated", type: "execution" });
        if (item.details?._taskComHandler)                 pills.push({ text: "COM handler", type: "context" });
        if (item.details?._taskTriggers?.length > 0)       pills.push({ text: item.details._taskTriggers.join("+"), type: "context" });
        if (item.details?._taskPrincipal && !/^(SYSTEM|S-1-5-18|LOCAL SERVICE|NETWORK SERVICE)$/i.test(item.details._taskPrincipal))
                                                           pills.push({ text: `user: ${item.details._taskPrincipal}`, type: "context" });
        if (item.details?._taskXmlPartial)                 pills.push({ text: "task XML partial", type: "context" });
        const seen = new Set();
        item.evidencePills = pills.filter(p => { if (seen.has(p.text)) return false; seen.add(p.text); return true; });
      }

      items.sort((a, b) => b.triageScore - a.triageScore || (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));

      // --- Incident clustering ---
      const _normArt = (a) => (a || "").replace(/^\\+/, "").replace(/\{[0-9a-f-]+\}$/i, "").trim().toLowerCase();
      const _secondaryArt = (it) => {
        // When primary artifact is empty, derive a discriminator from details
        const d = it.details || {};
        return d.groupName || d.targetUser || d.memberName || d.samAccountName || d._wmiName || d._wmiType || d.namespace || d.operationType || d.valueName || "";
      };
      const _incKey = (it) => {
        const art = _normArt(it.artifact);
        const disc = art || _normArt(_secondaryArt(it));
        return [it.category || "", it.name || "", (it.computer || "").toUpperCase(), disc, it.user ? it.user.toLowerCase() : ""].join("|");
      };
      const _incGroups = new Map();
      for (const it of items) { const k = _incKey(it); if (!_incGroups.has(k)) _incGroups.set(k, []); _incGroups.get(k).push(it); }
      const _INC_GAP = 3600000; // 60-min merge window
      const sevOrd = { critical: 0, high: 1, medium: 2, low: 3 };
      const incidents = [];
      let _paIncId = 0;
      for (const [, grp] of _incGroups) {
        grp.sort((a, b) => ((a.timestamp || "") < (b.timestamp || "") ? -1 : (a.timestamp || "") > (b.timestamp || "") ? 1 : 0));
        const clusters = [];
        let cur = [grp[0]];
        for (let i = 1; i < grp.length; i++) {
          const pT = new Date(cur[cur.length - 1].timestamp || "");
          const nT = new Date(grp[i].timestamp || "");
          if (!isNaN(pT) && !isNaN(nT) && Math.abs(nT - pT) <= _INC_GAP) cur.push(grp[i]);
          else { clusters.push(cur); cur = [grp[i]]; }
        }
        clusters.push(cur);
        for (const cl of clusters) {
          const rep = cl.reduce((best, it) => (it.riskScore || 0) > (best.riskScore || 0) ? it : best, cl[0]);
          const allTs = cl.map(i => i.timestamp).filter(Boolean).sort();
          const allReasons = [...new Set(cl.flatMap(i => i.suspiciousReasons || []))];
          const pillSeen = new Set(); const allPills = [];
          for (const it of cl) for (const p of (it.evidencePills || [])) { if (!pillSeen.has(p.text)) { pillSeen.add(p.text); allPills.push(p); } }
          const maxRisk = Math.max(...cl.map(i => i.triageScore || i.riskScore || 0));
          const worstSev = cl.reduce((b, i) => (sevOrd[i.severity] ?? 4) < (sevOrd[b] ?? 4) ? i.severity : b, "low");
          const artShort = (rep.artifact || "").split("\\").pop() || _secondaryArt(rep) || "";
          let title = rep.name;
          if (artShort && artShort.toLowerCase() !== rep.name.toLowerCase()) title = `${artShort} — ${rep.name}`;
          if (rep.computer) title += ` on ${rep.computer}`;
          incidents.push({
            id: _paIncId++, category: rep.category, title, severity: worstSev, triageScore: maxRisk,
            computer: rep.computer || "", user: rep.user || "", artifact: rep.artifact || _secondaryArt(rep) || "", command: rep.command || "", source: rep.source || "",
            firstSeen: allTs[0] || "", lastSeen: allTs[allTs.length - 1] || "", occurrenceCount: cl.length,
            items: cl, itemRowids: cl.map(i => i.rowid),
            suspiciousReasons: allReasons, evidencePills: allPills,
            isSuspicious: allReasons.length > 0, rmmTool: cl.some(i => i.rmmTool),
            details: rep.details, mode: rep.mode,
          });
        }
      }
      incidents.sort((a, b) => (b.triageScore - a.triageScore) || ((sevOrd[a.severity] ?? 4) - (sevOrd[b.severity] ?? 4)) || ((a.firstSeen || "") < (b.firstSeen || "") ? -1 : 1));

      // --- Build stats ---
      const byCategory = {};
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const item of items) {
        byCategory[item.category] = (byCategory[item.category] || 0) + 1;
        bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
      }
      const byIncidentSeverity = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const inc of incidents) byIncidentSeverity[inc.severity] = (byIncidentSeverity[inc.severity] || 0) + 1;

      return {
        items,
        incidents,
        warnings,
        stats: {
          total: items.length,
          incidentCount: incidents.length,
          byCategory,
          bySeverity,
          byIncidentSeverity,
          suspicious: items.filter(i => i.isSuspicious).length,
          suspiciousIncidents: incidents.filter(i => i.isSuspicious).length,
          uniqueComputers: new Set(items.map(i => i.computer).filter(Boolean)).size,
          categoriesFound: Object.keys(byCategory).length,
          ps4104Scripts: ps4104Reassembled?.length || 0,
          ps4104Correlated: ps4104CorrelatedCount,
        },
        columns,
        detectedMode: mode,
        error: null,
      };
    } catch (e) {
      return { items: [], incidents: [], warnings: [], stats: {}, columns, detectedMode: mode, error: e.message };
    }
  }

  /**
   * Get FTS build status for a tab (used by renderer to show indexing progress)
   */
  getFtsStatus(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return { ready: false, building: false };
    return { ready: !!meta.ftsReady, building: !!meta.ftsBuilding };
  }

  closeTab(tabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return;
    // Signal async builders (FTS/index) to stop — they check this flag
    meta.closed = true;
    // Remove from map so concurrent async operations bail out on databases.has() check
    this.databases.delete(tabId);
    // Purge caches for this tab
    if (this._countCache) this._countCache.delete(tabId);
    if (this._filterCache) this._filterCache.delete(tabId);
    try {
      meta.db.pragma("analysis_limit = 1000");
      meta.db.pragma("optimize");
      meta.db.close();
    } catch (e) {}
    try {
      fs.unlinkSync(meta.dbPath);
    } catch (e) {}
    // Clean WAL/SHM files too
    try {
      fs.unlinkSync(meta.dbPath + "-wal");
    } catch (e) {}
    try {
      fs.unlinkSync(meta.dbPath + "-shm");
    } catch (e) {}
  }

  /**
   * Merge multiple tabs into a single chronological timeline.
   * Reads from each source DB via its own connection (avoids EXCLUSIVE lock conflicts)
   * and inserts into the merged DB in batches.
   *
   * @param {string} mergedTabId - New tab ID for the merged result
   * @param {Array<{tabId, tabName, tsCol}>} sources - Source tabs with timestamp column mapping
   * @param {Function} onProgress - callback({ phase, current, total, sourceName })
   * @returns {{ headers, rowCount, tsColumns, numericColumns }}
   */
  mergeTabs(mergedTabId, sources, onProgress) {
    // Collect metadata from all source tabs
    const sourceMetas = [];
    for (const src of sources) {
      const meta = this.databases.get(src.tabId);
      if (!meta) throw new Error(`Source tab "${src.tabName}" (${src.tabId}) not found`);
      sourceMetas.push({ ...src, meta });
    }

    // Build unified header list: _Source + datetime + union of all other headers
    const headerSet = new Set();
    for (const src of sourceMetas) {
      for (const h of src.meta.headers) headerSet.add(h);
    }
    const restHeaders = [...headerSet].filter((h) => h !== "_Source" && h !== "datetime").sort();
    const unifiedHeaders = ["_Source", "datetime", ...restHeaders];
    const colCount = unifiedHeaders.length;

    // Create the merged tab
    this.createTab(mergedTabId, unifiedHeaders);
    const mergedMeta = this.databases.get(mergedTabId);

    let totalInserted = 0;
    const totalRows = sourceMetas.reduce((sum, s) => sum + s.meta.rowCount, 0);
    const MERGE_BATCH = 50000;

    for (let si = 0; si < sourceMetas.length; si++) {
      const src = sourceMetas[si];
      const srcMeta = src.meta;

      if (onProgress) onProgress({ phase: "copying", current: totalInserted, total: totalRows, sourceName: src.tabName });

      // Build column index mapping: for each unified header, find the source safe column index
      // This avoids per-row object lookups
      const srcSelectCols = [];
      for (const uh of unifiedHeaders) {
        if (uh === "_Source" || uh === "datetime") {
          srcSelectCols.push(null); // handled specially
        } else {
          srcSelectCols.push(srcMeta.colMap[uh] || null);
        }
      }
      const tsSafeCol = srcMeta.colMap[src.tsCol] || null;

      // Build SELECT for source — read all columns from source DB
      const srcCols = srcMeta.safeCols.map((c) => c.safe).join(", ");
      const selectStmt = srcMeta.db.prepare(`SELECT ${srcCols} FROM data`);

      // Stream rows from source, map to unified schema, batch insert into merged
      let batch = [];
      for (const srcRow of selectStmt.iterate()) {
        const values = new Array(colCount);
        values[0] = src.tabName; // _Source
        values[1] = tsSafeCol ? (srcRow[tsSafeCol] || "") : ""; // datetime

        for (let i = 2; i < colCount; i++) {
          const sc = srcSelectCols[i];
          values[i] = sc ? (srcRow[sc] || "") : "";
        }

        batch.push(values);

        if (batch.length >= MERGE_BATCH) {
          this.insertBatchArrays(mergedTabId, batch);
          totalInserted += batch.length;
          batch = [];
          if (onProgress) onProgress({ phase: "copying", current: totalInserted, total: totalRows, sourceName: src.tabName });
        }
      }

      // Insert remaining rows
      if (batch.length > 0) {
        this.insertBatchArrays(mergedTabId, batch);
        totalInserted += batch.length;
        batch = [];
      }

      if (onProgress) onProgress({ phase: "copying", current: totalInserted, total: totalRows, sourceName: src.tabName });
    }

    // Finalize (creates indexedCols Set, detects types)
    if (onProgress) onProgress({ phase: "indexing", current: totalInserted, total: totalRows, sourceName: "" });
    const result = this.finalizeImport(mergedTabId);

    // Index the unified datetime and _Source columns
    const mergedDb = mergedMeta.db;
    const dtSafe = mergedMeta.colMap["datetime"];
    if (dtSafe && !mergedMeta.indexedCols.has(dtSafe)) {
      mergedDb.exec(`CREATE INDEX IF NOT EXISTS idx_${dtSafe} ON data(${dtSafe})`);
      mergedMeta.indexedCols.add(dtSafe);
    }
    const srcColSafe = mergedMeta.colMap["_Source"];
    if (srcColSafe && !mergedMeta.indexedCols.has(srcColSafe)) {
      mergedDb.exec(`CREATE INDEX IF NOT EXISTS idx_${srcColSafe} ON data(${srcColSafe})`);
      mergedMeta.indexedCols.add(srcColSafe);
    }

    return {
      headers: unifiedHeaders,
      rowCount: result.rowCount,
      tsColumns: result.tsColumns,
      numericColumns: result.numericColumns,
    };
  }

  // ── Ransomware analysis constants ──────────────────────────────────────────
  static _RW_COMMON_EXTENSIONS = new Set([
    // Documents
    ".doc",".docx",".docm",".dot",".dotx",".odt",".rtf",".txt",".pdf",".xps",".wpd",".wps",".pages",
    // Spreadsheets
    ".xls",".xlsx",".xlsm",".xlsb",".xlt",".xltx",".ods",".csv",".tsv",".numbers",
    // Presentations
    ".ppt",".pptx",".pptm",".odp",".key",
    // Images
    ".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".svg",".ico",".webp",
    ".psd",".ai",".eps",".indd",".raw",".cr2",".nef",".dng",".heic",
    // Audio/Video
    ".mp3",".wav",".flac",".aac",".ogg",".wma",".mp4",".avi",".mkv",".mov",
    ".wmv",".flv",".webm",".m4v",".m4a",".m4b",".3gp",
    // Archives
    ".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".cab",".iso",".dmg",
    // Code
    ".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",".hpp",
    ".go",".rs",".rb",".php",".swift",".kt",".scala",".r",".m",".pl",
    ".sh",".bat",".ps1",".cmd",".vbs",".wsf",
    // Web
    ".html",".htm",".css",".scss",".less",".xml",".json",".yaml",".yml",
    // Config
    ".ini",".cfg",".conf",".config",".reg",".inf",".toml",".env",".properties",
    // Executables & Libraries
    ".exe",".dll",".sys",".drv",".ocx",".cpl",".msi",".msp",".mst",
    ".com",".scr",".pif",".jar",".class",".war",".ear",
    // Database
    ".mdb",".accdb",".sql",".sqlite",".db",".dbf",".mdf",".ndf",".ldf",
    // Email
    ".pst",".ost",".msg",".eml",".mbox",
    // Fonts
    ".ttf",".otf",".woff",".woff2",".eot",
    // VM
    ".vmdk",".vmx",".vhd",".vhdx",".ova",".ovf",".qcow2",".vdi",
    // System
    ".log",".tmp",".bak",".dat",".bin",".manifest",".cat",".mui",
    ".nls",".tlb",".ax",".lnk",".url",".theme",".msstyles",".etl",
    // Certificate
    ".cer",".crt",".pfx",".p12",".pem",".key",".csr",
    // CAD
    ".dwg",".dxf",".dgn",".rvt",".ifc",".step",".stp",".stl",
    // Misc
    ".hta",".chm",".hlp",".man",".info",".md",".rst",".tex",".latex",
    // Forensic / DFIR / system artifacts
    ".map",".mo",".po",".tkape",".time_stamp",".mkape",".mum",".evtx",".pak",".admx",
    // Additional system / resource files
    ".3",".rego",".fon",".cur",".adml",".cdf-ms",".mfl",".resx",".cdxml",
  ]);

  static _RW_BUSINESS_IMPACT = {
    "Documents": [".doc",".docx",".docm",".dot",".dotx",".odt",".rtf",".txt",".pdf",".xps",".wpd",".pages"],
    "Spreadsheets": [".xls",".xlsx",".xlsm",".xlsb",".xlt",".xltx",".ods",".csv",".tsv",".numbers"],
    "Presentations": [".ppt",".pptx",".pptm",".odp",".key"],
    "Email & Messaging": [".pst",".ost",".msg",".eml",".mbox",".dbx",".nsf"],
    "Databases": [".mdb",".accdb",".sql",".sqlite",".db",".dbf",".mdf",".ndf",".ldf"],
    "Archives": [".zip",".rar",".7z",".tar",".gz",".bz2",".xz",".cab",".iso"],
    "Source Code": [".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",".hpp",".go",".rs",".rb",".php",".swift",".kt",".scala",".sh",".bat",".ps1"],
    "Images & Design": [".jpg",".jpeg",".png",".gif",".bmp",".tif",".tiff",".svg",".psd",".ai",".eps",".indd",".raw",".cr2",".nef",".dng",".heic"],
    "Audio & Video": [".mp3",".wav",".flac",".aac",".mp4",".avi",".mkv",".mov",".wmv",".webm",".m4v"],
    "Virtual Machines": [".vmdk",".vmx",".vhd",".vhdx",".ova",".ovf",".qcow2",".vdi"],
    "Backups & Recovery": [".bak",".bkf",".tib",".mrimg",".spf",".v2i",".spi",".fbk",".trn",".dmp"],
    "CAD & Engineering": [".dwg",".dxf",".dgn",".rvt",".ifc",".step",".stp",".stl"],
  };

  static _RW_BACKUP_RECOVERY = new Map([
    [".bak","Database backup"],[".bkf","Windows backup"],[".tib","Acronis image"],
    [".mrimg","Macrium image"],[".vhdx","Hyper-V disk"],[".vmdk","VMware disk"],
    [".vhd","Virtual hard disk"],[".ova","VM appliance"],[".qcow2","QEMU disk"],
    [".vdi","VirtualBox disk"],[".pst","Outlook archive"],[".ost","Outlook cache"],
    [".mdf","SQL Server data"],[".ldf","SQL Server log"],[".ndf","SQL Server secondary"],
    [".iso","Disk image"],[".spf","ShadowProtect"],[".v2i","Symantec image"],
    [".trn","SQL transaction log"],[".dmp","Memory dump"],[".fbk","Firebird backup"],
  ]);

  // Reverse lookup: extension → business impact category (lazy-initialized)
  static _RW_EXT_TO_CATEGORY = null;
  static _getExtToCategory() {
    if (!TimelineDB._RW_EXT_TO_CATEGORY) {
      const m = new Map();
      for (const [cat, exts] of Object.entries(TimelineDB._RW_BUSINESS_IMPACT)) {
        for (const e of exts) if (!m.has(e)) m.set(e, cat);
      }
      TimelineDB._RW_EXT_TO_CATEGORY = m;
    }
    return TimelineDB._RW_EXT_TO_CATEGORY;
  }

  /**
   * Scan MFT for candidate ransomware extensions and ransom note filenames.
   * Returns scored candidates ranked by burst timing, rarity, and file count.
   */
  scanRansomwareExtensions(tabId, progressCb) {
    const _p = typeof progressCb === "function" ? progressCb : () => {};
    const meta = this.databases.get(tabId);
    const empty = { candidates: [], noteCandidates: [] };
    if (!meta) return empty;

    const db = meta.db;
    const col = (name) => meta.colMap[name];
    const ext = col("Extension"), fn = col("FileName"), pp = col("ParentPath"), fs = col("FileSize");
    const lastMod = col("LastModified0x10"), isDir = col("IsDirectory"), created = col("Created0x10");
    if (!ext || !fn || !pp) return empty;

    const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";

    try {
      // Phase 1: Get all extensions with counts >= 50
      _p({ stage: "extensions", pct: 5, detail: "Scanning extension distribution" });
      const allExts = db.prepare(
        `SELECT LOWER(${ext}) as extension, COUNT(*) as cnt FROM data WHERE ${ext} IS NOT NULL AND ${ext} != '' ${notDir} GROUP BY LOWER(${ext}) HAVING cnt >= 50 ORDER BY cnt DESC LIMIT 200`
      ).all();

      // Filter to non-common extensions
      const rawCandidates = allExts.filter(e => !TimelineDB._RW_COMMON_EXTENSIONS.has(e.extension));
      _p({ stage: "extensions", pct: 15, detail: `Found ${rawCandidates.length} uncommon extensions` });

      // Phase 1b: Also try lower threshold (cnt >= 5) if no candidates at >= 50
      if (rawCandidates.length === 0) {
        const lowExts = db.prepare(
          `SELECT LOWER(${ext}) as extension, COUNT(*) as cnt FROM data WHERE ${ext} IS NOT NULL AND ${ext} != '' ${notDir} GROUP BY LOWER(${ext}) HAVING cnt >= 5 ORDER BY cnt DESC LIMIT 200`
        ).all();
        const lowCandidates = lowExts.filter(e => !TimelineDB._RW_COMMON_EXTENSIONS.has(e.extension));
        if (lowCandidates.length > 0) rawCandidates.push(...lowCandidates);
      }

      // Normalize count scores (0-1)
      const maxCount = rawCandidates[0]?.cnt || 1;

      // Phase 2: Burst timing + sample paths for top 30
      _p({ stage: "burst", pct: 20, detail: "Analyzing burst timing" });
      const candidates = [];
      const top = rawCandidates.slice(0, 30);
      for (let _ti = 0; _ti < top.length; _ti++) {
        const rc = top[_ti];
        _p({ stage: "burst", pct: 20 + Math.round((_ti / top.length) * 40), detail: `Scoring ${rc.extension} (${_ti + 1}/${top.length})` });
        // Peak minute
        let peakMinute = null, peakMinuteCount = 0, burstScore = 0;
        if (lastMod) {
          const peak = db.prepare(
            `SELECT extract_datetime_minute(${lastMod}) as bucket, COUNT(*) as cnt FROM data WHERE LOWER(${ext}) = LOWER(?) ${notDir} AND ${lastMod} IS NOT NULL AND ${lastMod} != '' GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY cnt DESC LIMIT 1`
          ).get(rc.extension);
          if (peak) {
            peakMinute = peak.bucket;
            peakMinuteCount = peak.cnt;
            burstScore = peak.cnt / rc.cnt; // concentration in peak minute
          }
        }

        // Sample paths (top 3 directories)
        const pathRows = db.prepare(
          `SELECT ${pp} as path FROM data WHERE LOWER(${ext}) = LOWER(?) ${notDir} GROUP BY ${pp} ORDER BY COUNT(*) DESC LIMIT 3`
        ).all(rc.extension);
        const samplePaths = pathRows.map(r => r.path);

        // Rarity score: 1.0 for totally unknown extensions
        const rarityScore = 1.0;

        // Composite score
        const countNorm = rc.cnt / maxCount;
        const score = (countNorm * 0.3) + (burstScore * 0.5) + (rarityScore * 0.2);

        candidates.push({
          extension: rc.extension,
          fileCount: rc.cnt,
          score: Math.round(score * 100) / 100,
          peakMinute,
          peakMinuteCount,
          samplePaths,
        });
      }

      // Sort by score descending
      candidates.sort((a, b) => b.score - a.score);

      // Phase 3: Auto-detect ransom note filenames (runs independently of extension detection)
      _p({ stage: "notes", pct: 65, detail: "Scanning for ransom note patterns" });
      const noteCandidates = [];
      if (fs) {
        // Adaptive threshold: use >= 3 if MFT has < 500 unique directories, else >= 10
        const dirCountRow = db.prepare(`SELECT COUNT(DISTINCT ${pp}) as dc FROM data ${notDir ? "WHERE " + notDir.replace(/^AND /,"") : ""}`).get();
        const noteThreshold = (dirCountRow?.dc || 0) < 500 ? 3 : 10;
        const noteRows = db.prepare(
          `SELECT ${fn} as fileName, LOWER(${ext}) as extension, COUNT(DISTINCT ${pp}) as dirCount, COUNT(*) as total FROM data WHERE LOWER(${ext}) IN ('.txt','.html','.htm','.hta','.url','.bmp','.png') AND CAST(${fs} AS REAL) < 102400 ${notDir} GROUP BY LOWER(${fn}) HAVING dirCount >= ${noteThreshold} ORDER BY dirCount DESC LIMIT 20`
        ).all();

        const parseTs = (s) => { const m = String(s).match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/); return m ? new Date(Date.UTC(+m[1], m[2]-1, +m[3], +m[4], +m[5], +m[6])) : null; };
        const createdCol = created || lastMod;

        const noteSlice = noteRows.slice(0, 10);
        for (let _ni = 0; _ni < noteSlice.length; _ni++) {
          const nr = noteSlice[_ni];
          _p({ stage: "notes", pct: 65 + Math.round((_ni / noteSlice.length) * 25), detail: `Scoring note: ${nr.fileName} (${_ni + 1}/${noteSlice.length})` });
          let timeSpanMinutes = null;
          if (createdCol) {
            const span = db.prepare(
              `SELECT MIN(sort_datetime(${createdCol})) as earliest, MAX(sort_datetime(${createdCol})) as latest FROM data WHERE LOWER(${fn}) = LOWER(?) ${notDir}`
            ).get(nr.fileName);
            if (span?.earliest && span?.latest) {
              const t1 = parseTs(span.earliest), t2 = parseTs(span.latest);
              if (t1 && t2) timeSpanMinutes = Math.max(1, Math.round((t2 - t1) / 60000));
            }
          }

          // Score: high dirCount + short time span = strong signal
          const dirScore = Math.min(1, nr.dirCount / 100);
          const spanScore = timeSpanMinutes !== null && timeSpanMinutes < 1440 ? 1.0 : timeSpanMinutes !== null && timeSpanMinutes < 10080 ? 0.5 : 0.2;
          const noteScore = (dirScore * 0.6) + (spanScore * 0.4);

          noteCandidates.push({
            fileName: nr.fileName,
            extension: nr.extension,
            dirCount: nr.dirCount,
            totalCount: nr.total,
            timeSpanMinutes,
            score: Math.round(noteScore * 100) / 100,
          });
        }

        noteCandidates.sort((a, b) => b.score - a.score);
      }

      _p({ stage: "done", pct: 100, detail: `Found ${candidates.length} extensions, ${noteCandidates.length} note patterns` });
      return { candidates: candidates.slice(0, 15), noteCandidates };
    } catch (err) {
      return { ...empty, error: err.message };
    }
  }

  /**
   * Group flat directory counts into subtrees using a trie with path compression.
   */
  static _groupBySubtree(encDirs, allDirs, maxGroups = 25) {
    const totalMap = new Map(allDirs.map(d => [d.path, d.total]));

    // Build trie
    const root = { children: {}, encCount: 0, totalCount: 0, dirCount: 0 };
    for (const { path, count } of encDirs) {
      const segments = (path || "").replace(/^\.\\/, "").split(/[\\\/]+/).filter(Boolean);
      let node = root;
      for (const seg of segments) {
        if (!node.children[seg]) node.children[seg] = { children: {}, encCount: 0, totalCount: 0, dirCount: 0 };
        node = node.children[seg];
      }
      node.encCount += count;
      node.totalCount += totalMap.get(path) || count;
      node.dirCount += 1;
    }

    // Accumulate subtree counts
    function accumulate(node) {
      let enc = node.encCount, total = node.totalCount, dirs = node.dirCount;
      for (const child of Object.values(node.children)) {
        const c = accumulate(child);
        enc += c.enc; total += c.total; dirs += c.dirs;
      }
      node._subtreeEnc = enc;
      node._subtreeTotal = total;
      node._subtreeDirs = dirs;
      return { enc, total, dirs };
    }
    accumulate(root);

    // Walk trie, path-compress single-child chains, cut at branching points
    const results = [];
    function walk(node, pathSoFar, depth) {
      const childKeys = Object.keys(node.children);
      // Path compress single-child chain
      if (childKeys.length === 1 && depth < 6) {
        const key = childKeys[0];
        walk(node.children[key], pathSoFar ? pathSoFar + "\\" + key : key, depth + 1);
        return;
      }
      // Emit subtree at branching point, leaf, or max depth
      if (node._subtreeEnc > 0 && (childKeys.length >= 2 || childKeys.length === 0 || depth >= 3)) {
        results.push({
          path: ".\\" + (pathSoFar || "(root)"),
          encryptedCount: node._subtreeEnc,
          totalCount: node._subtreeTotal,
          ratio: node._subtreeTotal > 0 ? Math.round((node._subtreeEnc / node._subtreeTotal) * 1000) / 1000 : 0,
          childDirCount: node._subtreeDirs,
        });
        return;
      }
      // Recurse
      for (const [key, child] of Object.entries(node.children)) {
        walk(child, pathSoFar ? pathSoFar + "\\" + key : key, depth + 1);
      }
    }
    walk(root, "", 0);

    return results.sort((a, b) => b.encryptedCount - a.encryptedCount).slice(0, maxGroups);
  }

  /**
   * Ransomware MFT Analysis — runs targeted SQL queries to build a comprehensive
   * ransomware impact report from MFT data.
   */
  analyzeRansomware(tabId, { encryptedExt, ransomNotePattern, noteMatchMode, usnTabId, progressCb }) {
    const _p = typeof progressCb === "function" ? progressCb : () => {};
    const meta = this.databases.get(tabId);
    const empty = { encryptedCount: 0, totalEncryptedSizeBytes: 0, firstEncrypted: null, lastEncrypted: null, durationMinutes: 0, filesPerMinute: 0, ransomNotes: [], ransomNoteCount: 0, timeline: [], topDirectories: [], deletedEncrypted: 0, timestompedCount: 0, suspiciousFiles: [], usnEnrichment: null, timingEvidence: null };
    if (!meta) return empty;

    const db = meta.db;
    const col = (name) => meta.colMap[name];
    const parseTs = (s) => {
      const m = String(s || "").match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
      return m ? new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6])) : null;
    };
    const fmtTs = (d) => {
      if (!(d instanceof Date) || isNaN(d.getTime())) return null;
      const pad = (n) => String(n).padStart(2, "0");
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    };
    const pickAnchorTs = (row, mode = "start") => {
      const candidates = [row?.recordChange0x10, row?.timestamp, row?.lastMod0x30].map(parseTs).filter(Boolean);
      if (candidates.length === 0) return null;
      const millis = candidates.map((d) => d.getTime());
      return new Date(mode === "end" ? Math.max(...millis) : Math.min(...millis));
    };
    const buildTimingSnapshot = (row, usnTimestamp = null) => {
      const candidates = [
        row?.timestamp ? { key: "timeline", label: "SI Modified", column: "LastModified0x10", timestamp: row.timestamp, basis: "observed", role: "timeline" } : null,
        row?.recordChange0x10 ? { key: "recordChange", label: "Record Change", column: "LastRecordChange0x10", timestamp: row.recordChange0x10, basis: "observed", role: "metadata" } : null,
        row?.lastMod0x30 ? { key: "fnModified", label: "FN Modified", column: "LastModified0x30", timestamp: row.lastMod0x30, basis: "observed", role: "metadata" } : null,
        row?.created0x10 ? { key: "siCreated", label: "SI Created", column: "Created0x10", timestamp: row.created0x10, basis: "observed", role: "context" } : null,
        row?.created0x30 ? { key: "fnCreated", label: "FN Created", column: "Created0x30", timestamp: row.created0x30, basis: "observed", role: "context" } : null,
        usnTimestamp ? { key: "usnRename", label: "USN Rename", column: "UpdateTimestamp", timestamp: usnTimestamp, basis: "observed", role: "journal" } : null,
      ].filter(Boolean);
      const parsed = candidates.map((c) => ({ ...c, parsed: parseTs(c.timestamp) })).filter((c) => c.parsed);
      const earliest = parsed.reduce((best, cur) => (!best || cur.parsed < best.parsed ? cur : best), null);
      const latest = parsed.reduce((best, cur) => (!best || cur.parsed > best.parsed ? cur : best), null);
      const preferred = parsed.find((c) => c.key === "usnRename")
        || parsed.find((c) => c.key === "recordChange")
        || parsed.find((c) => c.key === "timeline")
        || parsed[0]
        || null;
      const pack = (item) => item ? {
        label: item.label,
        column: item.column,
        timestamp: item.timestamp,
        basis: item.basis,
        role: item.role,
      } : null;
      return {
        preferred: pack(preferred),
        earliest: pack(earliest),
        latest: pack(latest),
        skewMinutes: earliest && latest ? Math.round((((latest.parsed - earliest.parsed) / 60000) + Number.EPSILON) * 10) / 10 : 0,
        sources: candidates.map((c) => pack(c)),
      };
    };

    // Validate required MFT columns exist
    const ext = col("Extension"), fn = col("FileName"), pp = col("ParentPath"), fs = col("FileSize");
    const inUse = col("InUse"), isDir = col("IsDirectory"), siFN = col("SI<FN");
    const created = col("Created0x10"), lastMod = col("LastModified0x10"), entry = col("EntryNumber"), zoneId = col("ZoneIdContents");
    const recChange = col("LastRecordChange0x10");
    const created0x30 = col("Created0x30");
    const lastMod0x30 = col("LastModified0x30");
    if (!ext || !fn || !pp || !lastMod || !entry) return { ...empty, error: "MFT columns not found. This feature requires MFT data." };

    // Normalize extensions — support comma-separated multi-extension input
    const extParts = (encryptedExt || "").split(/[,;|]+/).map(s => s.trim()).filter(Boolean).map(s => s.startsWith(".") ? s : "." + s);
    if (extParts.length === 0) return { ...empty, error: "No extension provided." };
    const extWhereAll = `LOWER(${ext}) IN (${extParts.map(() => "LOWER(?)").join(",")})`;
    const coreTsSelect = `${created ? `, ${created} as created0x10` : ""}${recChange ? `, ${recChange} as recordChange0x10` : ""}${created0x30 ? `, ${created0x30} as created0x30` : ""}${lastMod0x30 ? `, ${lastMod0x30} as lastMod0x30` : ""}`;

    const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";

    try {
      // Q1: Encrypted file stats (multi-extension)
      _p({ stage: "counting", pct: 5, detail: "Counting encrypted files" });
      const q1 = db.prepare(`SELECT COUNT(*) as cnt, SUM(CAST(${fs || "'0'"} AS REAL)) as totalSize FROM data WHERE ${extWhereAll} ${notDir}`).get(...extParts);
      const encryptedCount = q1?.cnt || 0;
      if (encryptedCount === 0) return { ...empty, encryptedCount: 0, extensions: extParts };

      // Q2: First and Last encrypted files
      _p({ stage: "timeline", pct: 10, detail: `${encryptedCount.toLocaleString()} encrypted files found` });
      const firstQ = db.prepare(`SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${lastMod} as timestamp${coreTsSelect} FROM data WHERE ${extWhereAll} ${notDir} ORDER BY sort_datetime(${lastMod}) ASC LIMIT 1`).get(...extParts);
      const lastQ = db.prepare(`SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${lastMod} as timestamp${coreTsSelect} FROM data WHERE ${extWhereAll} ${notDir} ORDER BY sort_datetime(${lastMod}) DESC LIMIT 1`).get(...extParts);
      const startAnchorDt = pickAnchorTs(firstQ, "start") || parseTs(firstQ?.timestamp);
      const endAnchorDt = pickAnchorTs(lastQ, "end") || parseTs(lastQ?.timestamp);

      // Compute duration
      let durationMinutes = 0, filesPerMinute = 0;
      if (startAnchorDt && endAnchorDt) {
        durationMinutes = Math.max(1, Math.round((endAnchorDt - startAnchorDt) / 60000));
        filesPerMinute = encryptedCount / durationMinutes;
      }

      // Q2b: First 50 encrypted files (encryption spread) — with multi-timestamp columns
      const fsSel = fs ? `, ${fs} as fileSize` : "";
      const firstEncryptedFiles = db.prepare(
        `SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${lastMod} as timestamp${fsSel}${coreTsSelect} FROM data WHERE ${extWhereAll} ${notDir} ORDER BY sort_datetime(${lastMod}) ASC LIMIT 50`
      ).all(...extParts);

      // Q3: Ransom notes — multi-mode matching (exact/contains/regex/multi)
      _p({ stage: "notes", pct: 20, detail: "Searching for ransom notes" });
      let ransomNotes = [];
      if (ransomNotePattern && ransomNotePattern.trim()) {
        const noteParam = ransomNotePattern.trim();
        const createdCol = created || lastMod;
        const noteExtraCols = `${lastMod !== createdCol ? `, ${lastMod} as lastModified` : ""}${recChange ? `, ${recChange} as recordChange0x10` : ""}`;
        let noteWhere, noteParams;
        const mode = noteMatchMode || "exact";
        switch (mode) {
          case "contains": {
            const escaped = noteParam.replace(/[%_]/g, c => "\\" + c);
            noteWhere = `LOWER(${fn}) LIKE ? ESCAPE '\\'`;
            noteParams = [`%${escaped.toLowerCase()}%`];
            break;
          }
          case "regex":
            // Pre-filter by note-like extensions for performance, then JS regex post-filter
            noteWhere = `LOWER(${ext}) IN ('.txt','.html','.htm','.hta','.url','.bmp','.png') AND CAST(${fs || "'0'"} AS REAL) < 102400`;
            noteParams = [];
            break;
          case "multi": {
            const names = noteParam.split(/[,;|]+/).map(s => s.trim()).filter(Boolean);
            if (names.length === 0) { noteWhere = "0"; noteParams = []; break; }
            noteWhere = names.map(() => `LOWER(${fn}) = LOWER(?)`).join(" OR ");
            noteParams = names;
            break;
          }
          default:
            noteWhere = `LOWER(${fn}) = LOWER(?)`;
            noteParams = [noteParam];
        }
        ransomNotes = db.prepare(
          `SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${createdCol} as created${noteExtraCols} FROM data WHERE (${noteWhere}) ORDER BY sort_datetime(${createdCol}) ASC LIMIT 1000`
        ).all(...noteParams);
        if (mode === "regex") {
          try {
            const re = new RegExp(noteParam, "i");
            ransomNotes = ransomNotes.filter(n => re.test(n.fileName));
          } catch { ransomNotes = []; }
        }
      }

      // Q3b: USN Journal enrichment (optional)
      _p({ stage: "usn", pct: 25, detail: "USN Journal correlation" });
      let usnEnrichment = null;
      if (usnTabId && (startAnchorDt || firstQ?.timestamp) && (endAnchorDt || lastQ?.timestamp)) {
        const usnMeta = this.databases.get(usnTabId);
        if (usnMeta) {
          try {
            const uT1 = startAnchorDt || parseTs(firstQ?.timestamp);
            const uT2 = endAnchorDt || parseTs(lastQ?.timestamp);
            if (uT1 && uT2) {
              const usnStart = fmtTs(new Date(uT1.getTime() - 5 * 60000));
              const usnEnd = fmtTs(new Date(uT2.getTime() + 5 * 60000));
              const usnDb = usnMeta.db;
              const usnCol = (name) => usnMeta.colMap[name];
              const usnTs = usnCol("UpdateTimestamp"), usnName = usnCol("Name"), usnReasons = usnCol("UpdateReasons");
              const usnExtC = usnCol("Extension"), usnPp = usnCol("ParentPath");
              if (usnTs && usnName && usnReasons) {
                const usnExtLikes = extParts.map(() => `LOWER(${usnName}) LIKE ?`).join(" OR ");
                const usnExtParams = extParts.map((e) => `%${e.toLowerCase()}`);
                const renameEvents = usnDb.prepare(
                  `SELECT ${usnTs} as timestamp, ${usnName} as name${usnExtC ? `, ${usnExtC} as extension` : ""}${usnPp ? `, ${usnPp} as parentPath` : ""}, ${usnReasons} as reasons FROM data WHERE ${usnReasons} LIKE '%RenameNewName%' AND sort_datetime(${usnTs}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND (${usnExtLikes}) ORDER BY sort_datetime(${usnTs}) ASC LIMIT 500`
                ).all(usnStart, usnEnd, ...usnExtParams);
                const overwriteEvents = usnDb.prepare(
                  `SELECT extract_datetime_minute(${usnTs}) as bucket, COUNT(*) as count FROM data WHERE (${usnReasons} LIKE '%DataOverwrite%' OR ${usnReasons} LIKE '%DataExtend%') AND sort_datetime(${usnTs}) BETWEEN sort_datetime(?) AND sort_datetime(?) GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`
                ).all(usnStart, usnEnd);
                const deleteEvents = usnDb.prepare(
                  `SELECT extract_datetime_minute(${usnTs}) as bucket, COUNT(*) as count FROM data WHERE ${usnReasons} LIKE '%FileDelete%' AND sort_datetime(${usnTs}) BETWEEN sort_datetime(?) AND sort_datetime(?) GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`
                ).all(usnStart, usnEnd);
                usnEnrichment = {
                  renameCount: renameEvents.length,
                  renameSamples: renameEvents.slice(0, 20),
                  overwriteBuckets: overwriteEvents,
                  overwriteTotal: overwriteEvents.reduce((s, b) => s + b.count, 0),
                  deleteBuckets: deleteEvents,
                  deleteTotal: deleteEvents.reduce((s, b) => s + b.count, 0),
                  preciseStartTime: renameEvents.length > 0 ? renameEvents[0].timestamp : null,
                  windowStart: usnStart,
                  windowEnd: usnEnd,
                };
              }
            }
          } catch { /* USN correlation failed — non-fatal */ }
        }
      }

      // Q4: Timeline buckets (minute-level)
      _p({ stage: "timeline", pct: 30, detail: "Building encryption timeline" });
      const timeline = db.prepare(`SELECT extract_datetime_minute(${lastMod}) as bucket, COUNT(*) as count FROM data WHERE ${extWhereAll} ${notDir} AND ${lastMod} IS NOT NULL AND ${lastMod} != '' GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`).all(...extParts);

      // Q5: Top affected directories — subtree grouped with encrypted/total ratios
      _p({ stage: "directories", pct: 35, detail: "Mapping affected directories" });
      const encDirsRaw = db.prepare(`SELECT ${pp} as path, COUNT(*) as count FROM data WHERE ${extWhereAll} ${notDir} GROUP BY ${pp} ORDER BY count DESC LIMIT 500`).all(...extParts);
      const allDirsRaw = db.prepare(`SELECT ${pp} as path, COUNT(*) as total FROM data WHERE ${pp} IN (SELECT DISTINCT ${pp} FROM data WHERE ${extWhereAll} ${notDir}) ${notDir} GROUP BY ${pp}`).all(...extParts);
      const topDirectories = TimelineDB._groupBySubtree(encDirsRaw, allDirsRaw);

      // Q6: Forensic indicators
      let deletedEncrypted = 0, timestompedCount = 0;
      if (inUse) {
        const dq = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${extWhereAll} AND ${inUse} = 'False'`).get(...extParts);
        deletedEncrypted = dq?.cnt || 0;
      }
      if (siFN) {
        const tq = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${extWhereAll} AND ${siFN} = 'True'`).get(...extParts);
        timestompedCount = tq?.cnt || 0;
      }

      // Q7: Suspicious files near infection time (±30 min window) — scored payload candidates
      _p({ stage: "payloads", pct: 45, detail: "Scoring suspicious payloads" });
      let suspiciousFiles = [];
      let windowStart = null, windowEnd = null;
      const suspiciousAnchorDt = parseTs(usnEnrichment?.preciseStartTime) || startAnchorDt || parseTs(firstQ?.timestamp);
      if (suspiciousAnchorDt && created) {
          windowStart = fmtTs(new Date(suspiciousAnchorDt.getTime() - 30 * 60000));
          windowEnd = fmtTs(new Date(suspiciousAnchorDt.getTime() + 30 * 60000));
          const suspExts = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".jar",".py",".com"];
          const extPlaceholders = suspExts.map(() => "?").join(",");
          const zoneCol = zoneId || `''`;
          const q7extra = `${inUse ? `, ${inUse} as inUse` : ""}${siFN ? `, ${siFN} as siFN` : ""}${lastMod ? `, ${lastMod} as lastModified` : ""}${recChange ? `, ${recChange} as recordChange0x10` : ""}${created0x30 ? `, ${created0x30} as created0x30` : ""}${lastMod0x30 ? `, ${lastMod0x30} as lastMod0x30` : ""}`;
          suspiciousFiles = db.prepare(
            `SELECT data.rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${created} as created, ${ext} as extension, ${zoneCol} as zoneId${q7extra} FROM data WHERE sort_datetime(${created}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND LOWER(${ext}) IN (${extPlaceholders}) ${notDir} ORDER BY sort_datetime(${created}) ASC LIMIT 200`
          ).all(windowStart, windowEnd, ...suspExts);

          // Score each suspicious file
          const riskyPathRe = /\\(temp|programdata|appdata|public|\$recycle\.bin|downloads|users\\public)/i;
          const firstNoteTs = ransomNotes.length > 0 ? parseTs(ransomNotes[0].created) : null;
          const firstEncTs = suspiciousAnchorDt;
          for (const sf of suspiciousFiles) {
            const signals = [];
            let score = 0;
            const sfTs = parseTs(sf.created);
            if (sfTs && firstEncTs) {
              const deltaMin = Math.abs(sfTs - firstEncTs) / 60000;
              score += Math.max(0, 1 - deltaMin / 60) * 0.4;
              if (deltaMin <= 5) signals.push({ text: `${Math.round(deltaMin)}min from onset`, type: "correlation", basis: "observed" });
              else if (deltaMin <= 15) signals.push({ text: `${Math.round(deltaMin)}min from onset`, type: "correlation", basis: "observed" });
            }
            if (riskyPathRe.test(sf.parentPath)) { score += 0.15; signals.push({ text: "risky-path", type: "context", basis: "observed" }); }
            if (sf.zoneId) { score += 0.2; signals.push({ text: "web-download", type: "execution", basis: "observed" }); }
            if (sf.inUse === "False") { score += 0.1; signals.push({ text: "deleted", type: "execution", basis: "observed" }); }
            if (sf.siFN === "True") { score += 0.1; signals.push({ text: "timestomped", type: "execution", basis: "observed" }); }
            if (firstNoteTs && sfTs) {
              const noteDelta = Math.abs(sfTs - firstNoteTs) / 60000;
              if (noteDelta <= 5) { score += 0.05; signals.push({ text: "near-note-drop", type: "correlation", basis: "inferred" }); }
            }
            sf.score = Math.min(1, Math.round(score * 1000) / 1000);
            sf.signals = signals;
            sf.confidence = sf.score >= 0.6 ? "confirmed" : sf.score >= 0.35 ? "likely" : sf.score >= 0.15 ? "suspicious" : "anomalous";
          }
          suspiciousFiles.sort((a, b) => b.score - a.score);
      }

      // Q8: File type impact breakdown + business impact + backup/recovery
      _p({ stage: "impact", pct: 55, detail: "Assessing business impact" });
      // e.g. "report.docx.locked" → ".docx", "photo.jpg.encrypted" → ".jpg"
      const rows8 = db.prepare(
        `SELECT ${fn} as fileName, ${ext} as extension FROM data WHERE ${extWhereAll} ${notDir}`
      ).all(...extParts);
      const origCounts = {};
      // Build strip regex that handles any of the encrypted extensions
      const rxExtAlts = extParts.map(e => e.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
      const stripRe = new RegExp("(" + rxExtAlts + ")$", "i");
      for (const r of rows8) {
        const name = (r.fileName || "").replace(stripRe, "");
        const dot = name.lastIndexOf(".");
        const origExt = dot > 0 ? name.slice(dot).toLowerCase() : "(no extension)";
        origCounts[origExt] = (origCounts[origExt] || 0) + 1;
      }
      const fileTypeBreakdown = Object.entries(origCounts)
        .map(([e, count]) => ({ ext: e, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 20);

      // Business impact categories
      const catCounts = {};
      for (const [e, count] of Object.entries(origCounts)) {
        const cat = TimelineDB._getExtToCategory().get(e) || "Other";
        catCounts[cat] = (catCounts[cat] || 0) + count;
      }
      const businessImpact = Object.entries(catCounts)
        .map(([category, count]) => ({ category, count, percentage: Math.round((count / encryptedCount) * 1000) / 1000 }))
        .sort((a, b) => b.count - a.count);

      // Backup & recovery artifacts
      const backupRecoveryImpact = [];
      for (const [e, count] of Object.entries(origCounts)) {
        const subtype = TimelineDB._RW_BACKUP_RECOVERY.get(e);
        if (subtype) backupRecoveryImpact.push({ ext: e, count, subtype });
      }
      backupRecoveryImpact.sort((a, b) => b.count - a.count);
      const backupRecoveryTotal = backupRecoveryImpact.reduce((s, r) => s + r.count, 0);

      // Q9: Original-to-encrypted pair detection (JS-based, single-pass lookup)
      _p({ stage: "pairs", pct: 65, detail: "Detecting original-encrypted pairs" });
      const originalPairs = (() => {
        const pairSampleLimit = 100;
        const sampled = encryptedCount > pairSampleLimit;
        // 1. Fetch sample of encrypted files
        const encSample = db.prepare(
          `SELECT ${entry} as encEntry, ${fn} as encFileName, ${pp} as parentPath FROM data WHERE ${extWhereAll} ${notDir} LIMIT ${pairSampleLimit}`
        ).all(...extParts);
        // 2. Compute expected original filenames in JS
        const candidates = [];
        for (const ef of encSample) {
          let origName = ef.encFileName;
          for (const e of extParts) {
            if (origName.toLowerCase().endsWith(e.toLowerCase())) {
              origName = origName.slice(0, -e.length);
              break;
            }
          }
          if (origName && origName !== ef.encFileName && origName.length > 0) {
            candidates.push({ ...ef, origFileName: origName });
          }
        }
        if (candidates.length === 0) return { confirmedPairs: 0, likelyPairs: 0, pairRate: 0, samplePairs: [], sampled };
        // 3. Single query to check which originals exist (OR-chain, one table scan)
        const origNotDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";
        const orClauses = candidates.map(() => `(${fn} = ? AND ${pp} = ?)`).join(" OR ");
        const orParams = candidates.flatMap(c => [c.origFileName, c.parentPath]);
        const foundRows = db.prepare(
          `SELECT ${fn} as fileName, ${pp} as parentPath${inUse ? `, ${inUse} as inUse` : ""}, ${entry} as entryNumber FROM data WHERE (${orClauses}) ${origNotDir}`
        ).all(...orParams);
        const foundMap = new Map();
        for (const f of foundRows) foundMap.set(`${f.fileName}\0${f.parentPath}`, f);
        // 4. Evaluate pairs
        let confirmed = 0, likely = 0;
        const samplePairs = [];
        for (const c of candidates) {
          const orig = foundMap.get(`${c.origFileName}\0${c.parentPath}`);
          if (orig && inUse && orig.inUse === "False") {
            confirmed++;
            samplePairs.push({ originalFile: c.origFileName, encryptedFile: c.encFileName, parentPath: c.parentPath, originalDeleted: true, origEntry: orig.entryNumber, encEntry: c.encEntry });
          } else if (!orig) {
            likely++;
            samplePairs.push({ originalFile: c.origFileName, encryptedFile: c.encFileName, parentPath: c.parentPath, originalDeleted: false, origEntry: null, encEntry: c.encEntry });
          }
        }
        const total = confirmed + likely;
        const pairRate = candidates.length > 0 ? Math.round((total / candidates.length) * 1000) / 1000 : 0;
        const scale = sampled ? encryptedCount / pairSampleLimit : 1;
        return {
          confirmedPairs: Math.round(confirmed * scale),
          likelyPairs: Math.round(likely * scale),
          pairRate,
          samplePairs: samplePairs.sort((a, b) => (b.originalDeleted ? 1 : 0) - (a.originalDeleted ? 1 : 0)).slice(0, 50),
          sampled,
        };
      })();

      // Q10: Anti-forensics around encryption window
      _p({ stage: "anti-forensics", pct: 75, detail: "Detecting anti-forensics artifacts" });
      let antiForensics = { deletedEncrypted: [], timestomped: [], cleanup: [], drops: [] };
      const antiForensicsStart = parseTs(usnEnrichment?.preciseStartTime) || startAnchorDt || parseTs(firstQ?.timestamp);
      const antiForensicsEnd = endAnchorDt || parseTs(lastQ?.timestamp);
      if (antiForensicsStart && antiForensicsEnd) {
          const afStart = fmtTs(new Date(antiForensicsStart.getTime() - 30 * 60000));
          const afEnd = fmtTs(new Date(antiForensicsEnd.getTime() + 30 * 60000));
          // 10a: Deleted encrypted file details
          if (inUse) {
            antiForensics.deletedEncrypted = db.prepare(
              `SELECT ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${lastMod} as lastModified${created ? `, ${created} as created` : ""} FROM data WHERE ${extWhereAll} AND ${inUse} = 'False' ${notDir} ORDER BY sort_datetime(${lastMod}) ASC LIMIT 20`
            ).all(...extParts);
          }
          // 10b: Timestomped files in encryption window
          if (siFN) {
            antiForensics.timestomped = db.prepare(
              `SELECT ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${ext} as extension${created ? `, ${created} as created` : ""}, ${lastMod} as lastModified FROM data WHERE ${siFN} = 'True' AND sort_datetime(${lastMod}) BETWEEN sort_datetime(?) AND sort_datetime(?) ${notDir} LIMIT 50`
            ).all(afStart, afEnd);
          }
          // 10c: Cleanup artifacts (deleted executables/scripts/logs near window)
          if (inUse && created) {
            const cleanupExts = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".log",".tmp",".dat"];
            const clPh = cleanupExts.map(() => "?").join(",");
            antiForensics.cleanup = db.prepare(
              `SELECT ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${ext} as extension, ${created} as created, ${lastMod} as lastModified FROM data WHERE ${inUse} = 'False' AND LOWER(${ext}) IN (${clPh}) AND sort_datetime(${created}) BETWEEN sort_datetime(?) AND sort_datetime(?) ${notDir} ORDER BY sort_datetime(${created}) ASC LIMIT 30`
            ).all(...cleanupExts, afStart, afEnd);
          }
          // 10d: Suspicious drops in risky paths during window
          if (created) {
            antiForensics.drops = db.prepare(
              `SELECT ${entry} as entryNumber, ${fn} as fileName, ${pp} as parentPath, ${ext} as extension, ${created} as created FROM data WHERE sort_datetime(${created}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND (LOWER(${pp}) LIKE '%\\temp\\%' OR LOWER(${pp}) LIKE '%\\programdata\\%' OR LOWER(${pp}) LIKE '%\\appdata\\%' OR LOWER(${pp}) LIKE '%users\\public%' OR LOWER(${pp}) LIKE '%$recycle.bin%') ${notDir} ORDER BY sort_datetime(${created}) ASC LIMIT 30`
            ).all(afStart, afEnd);
          }
      }

      // Forensic indicators — structured with observed/inferred labels
      _p({ stage: "indicators", pct: 85, detail: "Building forensic indicators" });
      const notePathCount = new Set(ransomNotes.map(n => n.parentPath)).size;
      const forensicIndicators = [
        deletedEncrypted > 0 ? { text: `${deletedEncrypted} deleted encrypted files`, type: "execution", basis: "observed", count: deletedEncrypted } : null,
        timestompedCount > 0 ? { text: `${timestompedCount} timestomped files`, type: "execution", basis: "observed", count: timestompedCount } : null,
        originalPairs.pairRate > 0 ? { text: `${Math.round(originalPairs.pairRate * 100)}% pair rate — ${originalPairs.pairRate >= 0.7 ? "strong encryption pattern" : "partial encryption"}`, type: "correlation", basis: "inferred", count: null } : null,
        ransomNotes.length > 0 ? { text: `${ransomNotes.length} ransom notes across ${notePathCount} directories`, type: "execution", basis: "observed", count: ransomNotes.length } : null,
        (antiForensics.cleanup.length > 0 || antiForensics.drops.length > 0) ? { text: `${antiForensics.cleanup.length + antiForensics.drops.length} anti-forensic artifacts detected`, type: "execution", basis: "inferred", count: antiForensics.cleanup.length + antiForensics.drops.length } : null,
      ].filter(Boolean);

      const filterWindowUsesRecordChange = !!(recChange && firstQ?.recordChange0x10 && lastQ?.recordChange0x10);
      const timingEvidence = {
        timelineBasis: {
          label: "SI Modified",
          column: "LastModified0x10",
          description: "Timeline buckets and first/last encrypted cards are built from this field across the encrypted set.",
        },
        suspiciousWindowBasis: {
          label: usnEnrichment?.preciseStartTime ? "USN Rename" : (recChange ? "Record Change" : "SI Modified"),
          column: usnEnrichment?.preciseStartTime ? "UpdateTimestamp" : (recChange ? "LastRecordChange0x10" : "LastModified0x10"),
          timestamp: usnEnrichment?.preciseStartTime || fmtTs(suspiciousAnchorDt) || firstQ?.timestamp || null,
          description: usnEnrichment?.preciseStartTime
            ? "Payload-candidate timing is anchored to the earliest correlated USN rename event."
            : (recChange ? "Payload-candidate timing is anchored to the earliest MFT metadata-change timestamp for the first encrypted file." : "Payload-candidate timing falls back to SI last-modified time."),
        },
        start: buildTimingSnapshot(firstQ, usnEnrichment?.preciseStartTime || null),
        end: buildTimingSnapshot(lastQ, null),
        filterWindow: {
          column: filterWindowUsesRecordChange ? "LastRecordChange0x10" : "LastModified0x10",
          from: filterWindowUsesRecordChange ? firstQ.recordChange0x10 : (firstQ?.timestamp || null),
          to: filterWindowUsesRecordChange ? lastQ.recordChange0x10 : (lastQ?.timestamp || null),
        },
      };

      return {
        encryptedCount,
        extensions: extParts,
        totalEncryptedSizeBytes: q1?.totalSize || 0,
        firstEncrypted: firstQ || null,
        lastEncrypted: lastQ || null,
        durationMinutes,
        filesPerMinute,
        ransomNotes,
        ransomNoteCount: ransomNotes.length,
        timeline,
        topDirectories,
        deletedEncrypted,
        timestompedCount,
        suspiciousFiles,
        fileTypeBreakdown,
        firstEncryptedFiles,
        businessImpact,
        backupRecoveryImpact,
        backupRecoveryTotal,
        originalPairs,
        antiForensics,
        forensicIndicators,
        usnEnrichment,
        timingEvidence,
      };
    } catch (err) {
      return { ...empty, error: err.message };
    }
  }

  /**
   * Timestomping Detector — finds files where SI timestamps predate FN timestamps,
   * computes severity based on delta and file type, returns enriched results.
   */
  detectTimestomping(tabId) {
    const meta = this.databases.get(tabId);
    const empty = {
      totalTimestomped: 0,
      rawSiFnCount: 0,
      suppressedCount: 0,
      totalFiles: 0,
      percentTimestomped: 0,
      files: [],
      topDirectories: [],
      extensionBreakdown: [],
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      highConfidenceCount: 0,
      likelyCount: 0,
      contextCount: 0,
      notes: [],
    };
    if (!meta) return empty;

    const db = meta.db;
    const col = (name) => meta.colMap[name];
    const siFN = col("SI<FN"), fn = col("FileName"), ext = col("Extension"), pp = col("ParentPath");
    const entry = col("EntryNumber"), inUse = col("InUse"), isDir = col("IsDirectory");
    const uSecZeros = col("uSecZeros"), copied = col("Copied");
    const siCreated = col("Created0x10"), fnCreated = col("Created0x30");
    const siModified = col("LastModified0x10"), fnModified = col("LastModified0x30");
    const siRecordChange = col("LastRecordChange0x10"), fnRecordChange = col("LastRecordChange0x30");
    const siAccess = col("LastAccess0x10"), fnAccess = col("LastAccess0x30");
    if (!siFN || !fn || !entry) return { ...empty, error: "Required MFT columns not found (SI<FN, FileName, EntryNumber)." };

    const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";

    try {
      // Q1: Total timestomped count
      const q1 = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${siFN} = 'True' ${notDir}`).get();
      const rawSiFnCount = q1?.cnt || 0;
      if (rawSiFnCount === 0) return { ...empty, rawSiFnCount: 0 };

      // Q2: Total file count for percentage
      const q2 = db.prepare(`SELECT COUNT(*) as cnt FROM data ${notDir ? "WHERE " + notDir.slice(4) : ""}`).get();
      const totalFiles = q2?.cnt || 0;

      // Q3: Detailed timestomped files (limit 3000)
      const tsCols = [
        siCreated ? `${siCreated} as siCreated` : `'' as siCreated`,
        fnCreated ? `${fnCreated} as fnCreated` : `'' as fnCreated`,
        siModified ? `${siModified} as siModified` : `'' as siModified`,
        fnModified ? `${fnModified} as fnModified` : `'' as fnModified`,
        siRecordChange ? `${siRecordChange} as siRecordChange` : `'' as siRecordChange`,
        fnRecordChange ? `${fnRecordChange} as fnRecordChange` : `'' as fnRecordChange`,
        siAccess ? `${siAccess} as siAccess` : `'' as siAccess`,
        fnAccess ? `${fnAccess} as fnAccess` : `'' as fnAccess`,
      ].join(", ");
      const files = db.prepare(
        `SELECT ${entry} as entryNumber, ${fn} as fileName, ${ext ? ext + " as extension" : "'' as extension"}, ${pp ? pp + " as parentPath" : "'' as parentPath"}, ${uSecZeros ? `${uSecZeros} as uSecZeros, ` : `'' as uSecZeros, `}${copied ? `${copied} as copied, ` : `'' as copied, `}${tsCols}${inUse ? ", " + inUse + " as inUse" : ", '' as inUse"} FROM data WHERE ${siFN} = 'True' ${notDir} ORDER BY sort_datetime(${siCreated || fn}) ASC LIMIT 3000`
      ).all();

      // Q4: Top directories
      const topDirectories = pp ? db.prepare(`SELECT ${pp} as path, COUNT(*) as count FROM data WHERE ${siFN} = 'True' ${notDir} GROUP BY ${pp} ORDER BY count DESC LIMIT 20`).all() : [];

      // Q5: Extension breakdown
      const extensionBreakdown = ext ? db.prepare(`SELECT ${ext} as extension, COUNT(*) as count FROM data WHERE ${siFN} = 'True' ${notDir} GROUP BY ${ext} ORDER BY count DESC LIMIT 20`).all() : [];

      // JS post-processing: compute severity, stomped fields, deltas
      const suspExts = new Set([".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".sys",".drv",".jar",".lnk"]);
      const archiveExts = new Set([".zip", ".rar", ".7z", ".iso", ".img", ".cab"]);
      const noisyExts = new Set([".manifest", ".mum", ".cat", ".mui"]);
      const noisyPathRe = /^\.\\windows\\(?:winsxs\\|servicing\\packages\\|softwaredistribution\\|installer\\)|^\.\\program files\\windowsapps\\/i;
      const userWritableRe = /^\.\\users\\[^\\]+\\(?:downloads|desktop|appdata|temp)|^\.\\users\\public\\|^\.\\programdata\\|^\.\\windows\\temp\\/i;
      const parseTs = (s) => { if (!s) return null; const m = String(s).match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/); return m ? new Date(Date.UTC(+m[1], m[2]-1, +m[3], +m[4], +m[5], +m[6])).getTime() : null; };
      let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
      let highConfidenceCount = 0, likelyCount = 0, contextCount = 0;
      let suppressedCount = 0;
      const kept = [];

      for (const f of files) {
        const stompedFields = [];
        const deltas = [];
        const mismatchMap = {};
        for (const [field, si, fn2] of [
          ["Created", f.siCreated, f.fnCreated],
          ["Modified", f.siModified, f.fnModified],
          ["RecordChange", f.siRecordChange, f.fnRecordChange],
          ["Accessed", f.siAccess, f.fnAccess],
        ]) {
          const siMs = parseTs(si), fnMs = parseTs(fn2);
          if (siMs && fnMs && siMs < fnMs) {
            stompedFields.push(field);
            const deltaHours = (fnMs - siMs) / 3600000;
            deltas.push(deltaHours);
            mismatchMap[field] = deltaHours;
          }
        }
        f.stompedFields = stompedFields;
        f.maxDeltaHours = deltas.length > 0 ? Math.max(...deltas) : 0;
        const extension = (f.extension || "").toLowerCase();
        const parentPath = (f.parentPath || "").toLowerCase();
        const isExec = suspExts.has(extension);
        const isArchive = archiveExts.has(extension);
        const isNoisyPath = noisyPathRe.test(parentPath);
        const isNoisyExt = noisyExts.has(extension);
        const isUserWritable = userWritableRe.test(parentPath);
        const hasZeroUsec = String(f.uSecZeros || "").toLowerCase() === "true";
        const looksCopied = String(f.copied || "").toLowerCase() === "true";
        const createdMismatch = mismatchMap.Created != null;
        const modifiedMismatch = mismatchMap.Modified != null;
        const recordMismatch = mismatchMap.RecordChange != null;
        const accessMismatch = mismatchMap.Accessed != null;
        const hasFnCreated = !!parseTs(f.fnCreated);

        const onlyAccessMismatch = accessMismatch && !createdMismatch && !modifiedMismatch && !recordMismatch;
        let score = 0;
        const indicators = [];
        if (createdMismatch && hasFnCreated) { score += 3; indicators.push("SI created precedes FN created"); }
        if (modifiedMismatch) { score += 1; indicators.push("SI modified precedes FN modified"); }
        if (recordMismatch) { score += 1; indicators.push("SI record change precedes FN record change"); }
        if (onlyAccessMismatch) { score += 0; indicators.push("access-only mismatch"); }
        if (stompedFields.length >= 2) { score += 1; indicators.push("multiple SI/FN mismatches"); }
        if (hasZeroUsec) { score += 2; indicators.push("zeroed SI subseconds"); }
        if (f.maxDeltaHours >= 24 * 30) score += 1;
        if (f.maxDeltaHours >= 24 * 365) score += 1;
        if (isExec) { score += 2; indicators.push("executable/script extension"); }
        else if (isArchive) { score += 1; indicators.push("container/archive extension"); }
        if (isUserWritable) { score += 2; indicators.push("user-writable path"); }
        if (looksCopied) { score -= 2; indicators.push("copy-like timestamp pattern"); }
        if (isNoisyPath) { score -= 4; indicators.push("system servicing path"); }
        if (isNoisyPath && isNoisyExt) { score -= 3; indicators.push("servicing/manifests extension"); }
        if (createdMismatch && hasZeroUsec && !looksCopied && !isNoisyPath) score += 1;

        let confidence = "low";
        if (createdMismatch && hasZeroUsec && !looksCopied && !isNoisyPath && (isExec || isUserWritable || stompedFields.length >= 2)) confidence = "high";
        else if (createdMismatch && !isNoisyPath && (hasZeroUsec || stompedFields.length >= 2 || f.maxDeltaHours >= 720)) confidence = "medium";

        if (
          score <= 0 ||
          onlyAccessMismatch ||
          (looksCopied && !isExec && !isUserWritable && stompedFields.length < 2) ||
          (isNoisyPath && !isExec && !isUserWritable && confidence !== "high") ||
          (isNoisyExt && !isExec && !isUserWritable && score < 5)
        ) {
          suppressedCount++;
          continue;
        }

        f.score = score;
        f.confidence = confidence;
        f.indicators = indicators;
        f.noisyContext = isNoisyPath;
        if (confidence === "high" && (isExec || isUserWritable)) f.severity = "critical";
        else if (confidence === "high" || (confidence === "medium" && (isExec || isUserWritable || f.maxDeltaHours >= 8760))) f.severity = "high";
        else if (confidence === "medium" || score >= 3) f.severity = "medium";
        else f.severity = "low";

        if (confidence === "high") highConfidenceCount++;
        else if (confidence === "medium") likelyCount++;
        else contextCount++;
        if (f.severity === "critical") criticalCount++;
        else if (f.severity === "high") highCount++;
        else if (f.severity === "medium") mediumCount++;
        else lowCount++;
        kept.push(f);
      }

      // Sort: critical first, then by delta descending
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      kept.sort((a, b) => (sevOrder[a.severity] - sevOrder[b.severity]) || ((b.score || 0) - (a.score || 0)) || (b.maxDeltaHours - a.maxDeltaHours));

      const totalTimestomped = kept.length;
      const keptEntries = new Set(kept.map((f) => f.entryNumber));
      const filteredTopDirectories = topDirectories
        .map((dir) => ({ ...dir, count: kept.filter((f) => (f.parentPath || "") === (dir.path || "")).length }))
        .filter((dir) => dir.count > 0)
        .sort((a, b) => b.count - a.count)
        .slice(0, 20);
      const filteredExtensionBreakdown = extensionBreakdown
        .map((eb) => ({ ...eb, count: kept.filter((f) => (f.extension || "") === (eb.extension || "")).length }))
        .filter((eb) => eb.count > 0)
        .sort((a, b) => b.count - a.count)
        .slice(0, 20);

      return {
        totalTimestomped,
        rawSiFnCount,
        suppressedCount,
        totalFiles,
        percentTimestomped: totalFiles > 0 ? (totalTimestomped / totalFiles * 100) : 0,
        files: kept,
        topDirectories: filteredTopDirectories,
        extensionBreakdown: filteredExtensionBreakdown,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        highConfidenceCount,
        likelyCount,
        contextCount,
        notes: [
          "SI<FN and zeroed subseconds are indicators, not proof.",
          "Copy-like timestamp patterns and common servicing paths are dampened.",
          "High-confidence results require stacked indicators plus suspicious file/path context.",
        ],
      };
    } catch (err) {
      return { ...empty, error: err.message };
    }
  }

  /**
   * File Activity Heatmap — analyzes file creation and modification patterns
   * across the MFT, returning hourly/daily buckets and a day-of-week × hour matrix.
   */
  getFileActivityHeatmap(tabId, progressCb) {
    const _p = typeof progressCb === "function" ? progressCb : () => {};
    const meta = this.databases.get(tabId);
    const zeroMatrix = () => Array.from({ length: 7 }, () => new Array(24).fill(0));
    const empty = {
      createdBuckets: [],
      modifiedBuckets: [],
      combinedBuckets: [],
      totalCreated: 0,
      totalModified: 0,
      timeRange: {
        earliest: null,
        latest: null,
        createdEarliest: null,
        createdLatest: null,
        modifiedEarliest: null,
        modifiedLatest: null,
        focusEarliest: null,
        focusLatest: null,
      },
      bucketSize: "hourly",
      peakCreated: null,
      peakModified: null,
      peakCombined: null,
      dowHourMatrix: zeroMatrix(),
      dowHourByMonth: {},
      createdDowHourMatrix: zeroMatrix(),
      modifiedDowHourMatrix: zeroMatrix(),
      combinedDowHourMatrix: zeroMatrix(),
      createdDowHourByMonth: {},
      modifiedDowHourByMonth: {},
      combinedDowHourByMonth: {},
      suspiciousWindows: [],
    };
    if (!meta) return empty;

    const db = meta.db;
    const col = (name) => meta.colMap[name];
    const created = col("Created0x10"), modified = col("LastModified0x10"), isDir = col("IsDirectory");
    const pp = col("ParentPath"), ext = col("Extension"), inUse = col("InUse");
    if (!created && !modified) return { ...empty, error: "No timestamp columns found (Created0x10, LastModified0x10)." };

    const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";

    try {
      _p({ stage: "range", pct: 0, detail: "Detecting time range" });
      const getRangeFor = (tsSafe) => tsSafe
        ? (db.prepare(`SELECT MIN(sort_datetime(${tsSafe})) as earliest, MAX(sort_datetime(${tsSafe})) as latest FROM data WHERE ${tsSafe} IS NOT NULL AND ${tsSafe} != '' ${notDir}`).get() || {})
        : {};
      const createdRange = getRangeFor(created);
      const modifiedRange = getRangeFor(modified);
      const earliest = [createdRange?.earliest, modifiedRange?.earliest].filter(Boolean).sort()[0] || null;
      const latest = [createdRange?.latest, modifiedRange?.latest].filter(Boolean).sort().slice(-1)[0] || null;

      // Determine bucket size based on time span
      let bucketSize = "hourly";
      if (earliest && latest) {
        const spanDays = (new Date(latest) - new Date(earliest)) / 86400000;
        if (spanDays > 90) bucketSize = "daily";
      }
      const subLen = bucketSize === "daily" ? 10 : 13; // "yyyy-MM-dd" or "yyyy-MM-dd HH"

      const bucketToRange = (bucket) => {
        if (!bucket) return { from: null, to: null };
        if (bucketSize === "daily") {
          return { from: `${bucket} 00:00:00`, to: `${bucket} 23:59:59` };
        }
        return { from: `${bucket}:00:00`, to: `${bucket}:59:59` };
      };
      const bucketMeta = (bucket) => {
        const { from, to } = bucketToRange(bucket);
        const iso = bucketSize === "daily" ? `${bucket}T00:00:00Z` : `${bucket.replace(" ", "T")}:00:00Z`;
        const dt = new Date(iso);
        const dow = Number.isFinite(dt.getTime()) ? dt.getUTCDay() : null;
        const hour = bucketSize === "hourly" && Number.isFinite(dt.getTime()) ? dt.getUTCHours() : null;
        return {
          from,
          to,
          dow,
          hour,
          month: bucket ? bucket.slice(0, 7) : "",
          weekend: dow === 0 || dow === 6,
          offHours: hour !== null ? (hour < 6 || hour >= 22) : false,
        };
      };
      const mergeBucketSeries = (seriesList) => {
        const merged = new Map();
        for (const series of seriesList) {
          for (const row of series || []) {
            const cur = merged.get(row.bucket) || { bucket: row.bucket, count: 0 };
            cur.count += row.count || 0;
            merged.set(row.bucket, cur);
          }
        }
        return Array.from(merged.values()).sort((a, b) => a.bucket.localeCompare(b.bucket));
      };
      const addMatrixInto = (target, source) => {
        for (let dow = 0; dow < 7; dow++) {
          for (let hour = 0; hour < 24; hour++) {
            target[dow][hour] += source[dow][hour];
          }
        }
      };
      const buildMatrix = (tsSafe) => {
        const matrix = zeroMatrix();
        const byMonth = {};
        if (!tsSafe) return { matrix, byMonth };
        const rows = db.prepare(
          `SELECT SUBSTR(sort_datetime(${tsSafe}), 1, 7) as ym, CAST(strftime('%w', sort_datetime(${tsSafe})) AS INTEGER) as dow, CAST(SUBSTR(sort_datetime(${tsSafe}), 12, 2) AS INTEGER) as hour, COUNT(*) as count FROM data WHERE ${tsSafe} IS NOT NULL AND ${tsSafe} != '' ${notDir} AND sort_datetime(${tsSafe}) IS NOT NULL GROUP BY ym, dow, hour`
        ).all();
        for (const r of rows) {
          if (r.dow >= 0 && r.dow < 7 && r.hour >= 0 && r.hour < 24) {
            matrix[r.dow][r.hour] += r.count;
            if (r.ym) {
              if (!byMonth[r.ym]) byMonth[r.ym] = zeroMatrix();
              byMonth[r.ym][r.dow][r.hour] += r.count;
            }
          }
        }
        return { matrix, byMonth };
      };
      const combineByMonth = (left, right) => {
        const months = new Set([...Object.keys(left || {}), ...Object.keys(right || {})]);
        const out = {};
        for (const month of months) {
          out[month] = zeroMatrix();
          if (left?.[month]) addMatrixInto(out[month], left[month]);
          if (right?.[month]) addMatrixInto(out[month], right[month]);
        }
        return out;
      };
      const median = (values) => {
        if (!values || values.length === 0) return 0;
        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
      };
      const buildFocusRange = (buckets) => {
        if (!earliest || !latest || !buckets || buckets.length < 6) return { focusEarliest: earliest, focusLatest: latest };
        const total = buckets.reduce((sum, b) => sum + (b.count || 0), 0);
        if (total <= 0) return { focusEarliest: earliest, focusLatest: latest };
        const lowTarget = total * 0.02;
        const highTarget = total * 0.98;
        let acc = 0;
        let lowBucket = buckets[0].bucket;
        let highBucket = buckets[buckets.length - 1].bucket;
        let lowSet = false;
        for (const bucket of buckets) {
          acc += bucket.count || 0;
          if (!lowSet && acc >= lowTarget) {
            lowBucket = bucket.bucket;
            lowSet = true;
          }
          if (acc >= highTarget) {
            highBucket = bucket.bucket;
            break;
          }
        }
        return {
          focusEarliest: bucketToRange(lowBucket).from || earliest,
          focusLatest: bucketToRange(highBucket).to || latest,
        };
      };

      _p({ stage: "created", pct: 15, detail: "Aggregating created timestamps" });
      // Q2: Created activity buckets
      let createdBuckets = [];
      let totalCreated = 0;
      if (created) {
        createdBuckets = db.prepare(`SELECT SUBSTR(sort_datetime(${created}), 1, ${subLen}) as bucket, COUNT(*) as count FROM data WHERE ${created} IS NOT NULL AND ${created} != '' ${notDir} GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`).all();
        const tc = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${created} IS NOT NULL AND ${created} != '' ${notDir}`).get();
        totalCreated = tc?.cnt || 0;
      }

      _p({ stage: "modified", pct: 35, detail: "Aggregating modified timestamps" });
      // Q3: Modified activity buckets
      let modifiedBuckets = [];
      let totalModified = 0;
      if (modified) {
        modifiedBuckets = db.prepare(`SELECT SUBSTR(sort_datetime(${modified}), 1, ${subLen}) as bucket, COUNT(*) as count FROM data WHERE ${modified} IS NOT NULL AND ${modified} != '' ${notDir} GROUP BY bucket HAVING bucket IS NOT NULL ORDER BY bucket`).all();
        const tm = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${modified} IS NOT NULL AND ${modified} != '' ${notDir}`).get();
        totalModified = tm?.cnt || 0;
      }

      const combinedBuckets = mergeBucketSeries([createdBuckets, modifiedBuckets]);
      const focusRange = buildFocusRange(combinedBuckets);

      _p({ stage: "matrix", pct: 55, detail: "Building day-of-week patterns" });
      // Q4: Day-of-week × hour-of-day matrices
      const createdMatrixData = buildMatrix(created);
      const modifiedMatrixData = buildMatrix(modified);
      const combinedDowHourMatrix = zeroMatrix();
      addMatrixInto(combinedDowHourMatrix, createdMatrixData.matrix);
      addMatrixInto(combinedDowHourMatrix, modifiedMatrixData.matrix);
      const combinedDowHourByMonth = combineByMonth(createdMatrixData.byMonth, modifiedMatrixData.byMonth);

      _p({ stage: "suspicious", pct: 75, detail: "Analyzing suspicious windows" });
      // Q5: Rank suspicious windows with analyst context
      const riskyExts = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".jar",".com",".lnk"];
      const riskyExtPlaceholders = riskyExts.map(() => "LOWER(?)").join(",");
      const buildSuspiciousWindows = (mode, buckets, tsSafe) => {
        if (!tsSafe || !buckets || buckets.length === 0) return [];
        const counts = buckets.map((b) => b.count || 0);
        const med = median(counts);
        const mad = median(counts.map((v) => Math.abs(v - med))) || 1;
        const maxCount = Math.max(...counts, 1);
        const dirStmt = pp ? db.prepare(`SELECT ${pp} as path, COUNT(*) as count FROM data WHERE sort_datetime(${tsSafe}) BETWEEN sort_datetime(?) AND sort_datetime(?) ${notDir} GROUP BY ${pp} ORDER BY count DESC LIMIT 3`) : null;
        const extStmt = ext ? db.prepare(`SELECT COALESCE(NULLIF(${ext}, ''), '(no extension)') as ext, COUNT(*) as count FROM data WHERE sort_datetime(${tsSafe}) BETWEEN sort_datetime(?) AND sort_datetime(?) ${notDir} GROUP BY COALESCE(NULLIF(${ext}, ''), '(no extension)') ORDER BY count DESC LIMIT 5`) : null;
        const riskyStmt = ext ? db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE sort_datetime(${tsSafe}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND LOWER(COALESCE(${ext}, '')) IN (${riskyExtPlaceholders}) ${notDir}`) : null;
        const deletedStmt = inUse ? db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE sort_datetime(${tsSafe}) BETWEEN sort_datetime(?) AND sort_datetime(?) AND ${inUse} = 'False' ${notDir}`) : null;
        // Phase 1: Base scoring (robustZ + timing)
        const candidates = buckets.map((bucket) => {
          const metaInfo = bucketMeta(bucket.bucket);
          const robustZ = ((bucket.count || 0) - med) / (1.4826 * mad || 1);
          let baseScore = Math.max(0, robustZ);
          if (metaInfo.weekend) baseScore += 0.6;
          if (metaInfo.offHours) baseScore += 0.4;
          if ((bucket.count || 0) >= maxCount * 0.5) baseScore += 0.25;
          return {
            mode,
            column: mode === "created" ? "Created0x10" : "LastModified0x10",
            bucket: bucket.bucket,
            count: bucket.count || 0,
            baseScore,
            zScore: Math.round(robustZ * 100) / 100,
            weekend: metaInfo.weekend,
            offHours: metaInfo.offHours,
            from: metaInfo.from,
            to: metaInfo.to,
            month: metaInfo.month,
          };
        }).filter((w) => w.baseScore >= 1.25 || w.count >= maxCount * 0.35);

        // Phase 2: Enrich with context + incorporate into final score
        return candidates.map((window) => {
          const riskyExtensionCount = riskyStmt ? (riskyStmt.get(window.from, window.to, ...riskyExts)?.cnt || 0) : 0;
          const deletedCount = deletedStmt ? (deletedStmt.get(window.from, window.to)?.cnt || 0) : 0;
          let score = window.baseScore;
          if (window.count > 0) {
            const riskyRatio = riskyExtensionCount / window.count;
            score += riskyRatio * 0.5;
            const deletedRatio = deletedCount / window.count;
            score += deletedRatio * 0.3;
          }
          return {
            ...window,
            score: Math.round(score * 100) / 100,
            topDirectories: dirStmt ? dirStmt.all(window.from, window.to) : [],
            topExtensions: extStmt ? extStmt.all(window.from, window.to) : [],
            riskyExtensionCount,
            deletedCount,
          };
        }).sort((a, b) => b.score - a.score || b.count - a.count)
          .slice(0, 8)
          .map(({ baseScore, ...rest }) => rest);
      };
      const suspiciousWindows = [
        ...buildSuspiciousWindows("created", createdBuckets, created),
        ...buildSuspiciousWindows("modified", modifiedBuckets, modified),
      ].sort((a, b) => b.score - a.score || b.count - a.count).slice(0, 12);

      // Anchor focus range to top suspicious windows (so benign churn doesn't dominate)
      if (suspiciousWindows.length > 0) {
        const topWins = suspiciousWindows.slice(0, 3);
        const winFrom = topWins.map((w) => w.from).filter(Boolean).sort()[0];
        const winTo = topWins.map((w) => w.to).filter(Boolean).sort().slice(-1)[0];
        if (winFrom && focusRange.focusEarliest && winFrom < focusRange.focusEarliest) focusRange.focusEarliest = winFrom;
        if (winTo && focusRange.focusLatest && winTo > focusRange.focusLatest) focusRange.focusLatest = winTo;
      }

      _p({ stage: "peaks", pct: 95, detail: "Computing results" });
      // Find peaks
      const peakCreated = createdBuckets.reduce((best, b) => (!best || b.count > best.count) ? b : best, null);
      const peakModified = modifiedBuckets.reduce((best, b) => (!best || b.count > best.count) ? b : best, null);
      const peakCombined = combinedBuckets.reduce((best, b) => (!best || b.count > best.count) ? b : best, null);

      return {
        createdBuckets,
        modifiedBuckets,
        combinedBuckets,
        totalCreated,
        totalModified,
        timeRange: {
          earliest,
          latest,
          createdEarliest: createdRange?.earliest || null,
          createdLatest: createdRange?.latest || null,
          modifiedEarliest: modifiedRange?.earliest || null,
          modifiedLatest: modifiedRange?.latest || null,
          focusEarliest: focusRange.focusEarliest,
          focusLatest: focusRange.focusLatest,
        },
        bucketSize,
        peakCreated,
        peakModified,
        peakCombined,
        dowHourMatrix: createdMatrixData.matrix,
        dowHourByMonth: createdMatrixData.byMonth,
        createdDowHourMatrix: createdMatrixData.matrix,
        modifiedDowHourMatrix: modifiedMatrixData.matrix,
        combinedDowHourMatrix,
        createdDowHourByMonth: createdMatrixData.byMonth,
        modifiedDowHourByMonth: modifiedMatrixData.byMonth,
        combinedDowHourByMonth,
        suspiciousWindows,
      };
    } catch (err) {
      return { ...empty, error: err.message };
    }
  }

  /**
   * ADS (Alternate Data Streams) Analyzer — examines HasAds, IsAds, and
   * ZoneIdContents columns to identify downloaded files, ADS entries, and
   * extract Zone.Identifier metadata (referrer URLs, host URLs, zone IDs).
   */
  analyzeADS(tabId) {
    const meta = this.databases.get(tabId);
    const empty = {
      totalWithAds: 0,
      totalAdsEntries: 0,
      totalWithZoneId: 0,
      downloadedExecutables: [],
      zoneIdFiles: [],
      adsEntries: [],
      topDownloadDirs: [],
      zoneBreakdown: { local: 0, intranet: 0, trusted: 0, internet: 0, restricted: 0 },
      referrerUrls: [],
      hostUrls: [],
      prioritizedDownloads: [],
      archiveLineage: [],
      motwSuspicious: [],
      internalHosts: [],
      sourceClusters: [],
      adsAnomalies: [],
      summary: null,
    };
    if (!meta) return empty;

    const db = meta.db;
    const col = (name) => meta.colMap[name];
    const hasAds = col("HasAds"), isAds = col("IsAds"), zoneId = col("ZoneIdContents");
    const fn = col("FileName"), ext = col("Extension"), pp = col("ParentPath");
    const entry = col("EntryNumber"), created = col("Created0x10"), fs = col("FileSize");
    const isDir = col("IsDirectory");
    if (!hasAds && !isAds && !zoneId) return { ...empty, error: "No ADS columns found (HasAds, IsAds, ZoneIdContents)." };

    const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";

    // Helper to parse Zone.Identifier content
    const parseZoneId = (content) => {
      if (!content) return { zone: null, zoneName: "", referrerUrl: "", hostUrl: "" };
      const zoneMatch = content.match(/ZoneId\s*=\s*(\d)/);
      const zone = zoneMatch ? parseInt(zoneMatch[1]) : null;
      const zoneNames = { 0: "Local", 1: "Intranet", 2: "Trusted", 3: "Internet", 4: "Restricted" };
      const referrerMatch = content.match(/ReferrerUrl\s*=\s*(.+?)(?:\r?\n|$)/);
      const hostMatch = content.match(/HostUrl\s*=\s*(.+?)(?:\r?\n|$)/);
      return {
        zone,
        zoneName: zoneNames[zone] || (zone !== null ? `Zone ${zone}` : ""),
        referrerUrl: referrerMatch ? referrerMatch[1].trim() : "",
        hostUrl: hostMatch ? hostMatch[1].trim() : "",
      };
    };
    const parseTs = (s) => {
      if (!s) return null;
      const ms = Date.parse(String(s).replace(" ", "T"));
      return Number.isFinite(ms) ? ms : null;
    };
    const RISKY_EXTS = new Set([".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".jar",".py",".lnk",".iso",".img"]);
    const EXEC_EXTS = new Set([".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".jar",".py"]);
    const ARCHIVE_EXTS = new Set([".zip",".rar",".7z",".iso",".img",".cab",".tar",".gz",".bz2",".xz"]);
    const OFFICE_EXTS = new Set([".doc",".docm",".docx",".xls",".xlsm",".xlsx",".ppt",".pptm",".pptx",".rtf",".one"]);
    const STREAM_NAME_PAT = /:([^:\\]+)$/i;
    const hostFromUrl = (raw) => {
      if (!raw) return "";
      const s = String(raw).trim();
      try {
        const u = new URL(s);
        return (u.hostname || "").toLowerCase();
      } catch {
        const m = s.match(/^\\\\([^\\\/]+)[\\\/]/) || s.match(/^file:\/\/\/{0,2}([^\/\\]+)/i);
        return m ? String(m[1]).toLowerCase() : "";
      }
    };
    const isInternalHost = (host) => {
      if (!host) return false;
      if (/^(localhost|127\.|::1$)/i.test(host)) return true;
      if (/^(10\.)/.test(host)) return true;
      if (/^192\.168\./.test(host)) return true;
      if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return true;
      return !host.includes(".");
    };
    const inferTransferSource = (referrerUrl, hostUrl) => {
      const ref = String(referrerUrl || "").toLowerCase();
      const host = String(hostUrl || "").toLowerCase();
      const combined = `${ref} ${host}`;
      if (/^file:|^\\\\/.test(host) || /^file:|^\\\\/.test(ref)) return "smb/webdav";
      if (/https?:/.test(combined)) return isInternalHost(hostFromUrl(host || ref)) ? "internal web/file portal" : "browser/web";
      if (/ftp:/.test(combined)) return "ftp";
      if (/bits/.test(combined)) return "bits";
      if (/powershell|pwsh/.test(combined)) return "powershell";
      return host || ref ? "network transfer" : "";
    };
    const leafName = (s) => {
      const raw = String(s || "");
      const seg = raw.split(/[\\\/]/).pop() || raw;
      return seg.replace(/:[^:]+$/,"");
    };
    const parentDirRisk = (p) => /\\users\\[^\\]+\\(downloads|desktop|appdata|temp)\\|\\windows\\temp\\|\\users\\public\\/i.test(String(p || "").toLowerCase());

    try {
      // Q1: Summary counts
      const totalWithAds = hasAds ? (db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${hasAds} = 'True' ${notDir}`).get()?.cnt || 0) : 0;
      const totalAdsEntries = isAds ? (db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${isAds} = 'True'`).get()?.cnt || 0) : 0;
      const totalWithZoneId = zoneId ? (db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${zoneId} IS NOT NULL AND ${zoneId} != ''`).get()?.cnt || 0) : 0;

      if (totalWithAds === 0 && totalAdsEntries === 0 && totalWithZoneId === 0) return { ...empty };

      // Q2: Files with Zone.Identifier (limit 2000)
      let zoneIdFiles = [];
      if (zoneId && totalWithZoneId > 0) {
        const createdCol = created || `'' `;
        zoneIdFiles = db.prepare(
          `SELECT ${entry ? entry + " as entryNumber" : "rowid as entryNumber"}, ${fn} as fileName, ${ext ? ext + " as extension" : "'' as extension"}, ${pp ? pp + " as parentPath" : "'' as parentPath"}, ${createdCol} as created, ${zoneId} as zoneIdContents FROM data WHERE ${zoneId} IS NOT NULL AND ${zoneId} != '' ORDER BY ${created ? "sort_datetime(" + created + ")" : "rowid"} ASC LIMIT 2000`
        ).all();
        // Enrich with parsed zone data
        for (const f of zoneIdFiles) {
          const parsed = parseZoneId(f.zoneIdContents);
          f.zone = parsed.zone;
          f.zoneName = parsed.zoneName;
          f.referrerUrl = parsed.referrerUrl;
          f.hostUrl = parsed.hostUrl;
        }
      }

      // Q3: Downloaded executables (highest risk)
      let downloadedExecutables = [];
      if (zoneId && ext && totalWithZoneId > 0) {
        const suspExts = [".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif",".msi",".com",".jar",".py"];
        const extPlaceholders = suspExts.map(() => "?").join(",");
        const createdCol = created || `''`;
        downloadedExecutables = db.prepare(
          `SELECT ${entry ? entry + " as entryNumber" : "rowid as entryNumber"}, ${fn} as fileName, ${ext} as extension, ${pp ? pp + " as parentPath" : "'' as parentPath"}, ${createdCol} as created, ${zoneId} as zoneIdContents FROM data WHERE ${zoneId} IS NOT NULL AND ${zoneId} != '' AND LOWER(${ext}) IN (${extPlaceholders}) ORDER BY ${created ? "sort_datetime(" + created + ")" : "rowid"} ASC LIMIT 500`
        ).all(...suspExts);
        for (const f of downloadedExecutables) {
          const parsed = parseZoneId(f.zoneIdContents);
          f.zone = parsed.zone;
          f.zoneName = parsed.zoneName;
          f.referrerUrl = parsed.referrerUrl;
          f.hostUrl = parsed.hostUrl;
        }
      }

      // Q4: ADS entries (limit 1000)
      let adsEntries = [];
      if (isAds && totalAdsEntries > 0) {
        const createdCol = created || `''`;
        adsEntries = db.prepare(
          `SELECT ${entry ? entry + " as entryNumber" : "rowid as entryNumber"}, ${fn} as fileName, ${pp ? pp + " as parentPath" : "'' as parentPath"}, ${createdCol} as created, ${fs ? fs + " as fileSize" : "'' as fileSize"} FROM data WHERE ${isAds} = 'True' ORDER BY ${created ? "sort_datetime(" + created + ")" : "rowid"} ASC LIMIT 1000`
        ).all();
      }

      // Q5: Top directories with downloaded files
      let topDownloadDirs = [];
      if (zoneId && pp && totalWithZoneId > 0) {
        topDownloadDirs = db.prepare(`SELECT ${pp} as path, COUNT(*) as count FROM data WHERE ${zoneId} IS NOT NULL AND ${zoneId} != '' GROUP BY ${pp} ORDER BY count DESC LIMIT 20`).all();
      }

      // Build zone breakdown + URL aggregation from zoneIdFiles
      const zoneBreakdown = { local: 0, intranet: 0, trusted: 0, internet: 0, restricted: 0 };
      const referrerCounts = {};
      const hostCounts = {};
      for (const f of zoneIdFiles) {
        if (f.zone === 0) zoneBreakdown.local++;
        else if (f.zone === 1) zoneBreakdown.intranet++;
        else if (f.zone === 2) zoneBreakdown.trusted++;
        else if (f.zone === 3) zoneBreakdown.internet++;
        else if (f.zone === 4) zoneBreakdown.restricted++;
        if (f.referrerUrl) referrerCounts[f.referrerUrl] = (referrerCounts[f.referrerUrl] || 0) + 1;
        if (f.hostUrl) hostCounts[f.hostUrl] = (hostCounts[f.hostUrl] || 0) + 1;
      }
      const referrerUrls = Object.entries(referrerCounts).map(([url, count]) => ({ url, count })).sort((a, b) => b.count - a.count).slice(0, 30);
      const hostUrls = Object.entries(hostCounts).map(([url, count]) => ({ url, count })).sort((a, b) => b.count - a.count).slice(0, 30);

      // JS post-processing: prioritization, source clustering, archive lineage, MOTW heuristics, ADS anomalies
      const prioritizedDownloads = zoneIdFiles.map((f) => {
        const extLower = String(f.extension || "").toLowerCase();
        const host = hostFromUrl(f.hostUrl || f.referrerUrl);
        const internalHost = isInternalHost(host);
        const sourceType = inferTransferSource(f.referrerUrl, f.hostUrl);
        const reasons = [];
        let riskScore = 0;
        if (EXEC_EXTS.has(extLower)) { riskScore += 3; reasons.push("executable/script"); }
        else if (ARCHIVE_EXTS.has(extLower)) { riskScore += 2; reasons.push("archive/container"); }
        else if (OFFICE_EXTS.has(extLower)) { riskScore += 1; reasons.push("office/document"); }
        if (parentDirRisk(f.parentPath)) { riskScore += 1; reasons.push("user-writable location"); }
        if (internalHost) { riskScore += 2; reasons.push("internal-host download"); }
        if (f.zone === 3) { riskScore += 1; reasons.push("internet MOTW"); }
        if (f.zone === 1 && internalHost) { riskScore += 1; reasons.push("intranet MOTW"); }
        f.transferSource = sourceType;
        f.internalHost = internalHost;
        f.sourceHost = host;
        f.riskScore = riskScore;
        f.riskReasons = reasons;
        f.isArchive = ARCHIVE_EXTS.has(extLower);
        f.isExecutableLike = EXEC_EXTS.has(extLower);
        return f;
      }).sort((a, b) => (b.riskScore - a.riskScore) || String(a.created || "").localeCompare(String(b.created || "")));

      const clusterMap = new Map();
      for (const f of prioritizedDownloads) {
        const host = f.sourceHost || "(unknown)";
        const type = f.transferSource || "(unknown)";
        const key = `${host}||${type}`;
        const cur = clusterMap.get(key) || { host, transferSource: type, count: 0, internal: false, samplePaths: new Set(), sampleFiles: new Set() };
        cur.count++;
        cur.internal = cur.internal || !!f.internalHost;
        if (cur.samplePaths.size < 4 && f.parentPath) cur.samplePaths.add(f.parentPath);
        if (cur.sampleFiles.size < 4 && f.fileName) cur.sampleFiles.add(f.fileName);
        clusterMap.set(key, cur);
      }
      const sourceClusters = Array.from(clusterMap.values()).map((c) => ({
        host: c.host,
        transferSource: c.transferSource,
        count: c.count,
        internal: c.internal,
        samplePaths: Array.from(c.samplePaths),
        sampleFiles: Array.from(c.sampleFiles),
      })).sort((a, b) => b.count - a.count).slice(0, 20);

      const internalHosts = sourceClusters.filter((c) => c.internal).map((c) => ({ host: c.host, count: c.count, transferSource: c.transferSource })).sort((a, b) => b.count - a.count);

      const archiveDownloads = prioritizedDownloads.filter((f) => f.isArchive && f.created && f.parentPath);
      let archiveLineage = [];
      let motwSuspicious = [];
      if (archiveDownloads.length > 0 && fn && pp) {
        const dirs = Array.from(new Set(archiveDownloads.map((f) => f.parentPath).filter(Boolean))).slice(0, 50);
        const minTs = archiveDownloads.map((f) => parseTs(f.created)).filter(Boolean);
        const minCreated = minTs.length ? new Date(Math.min(...minTs) - 3600000).toISOString().slice(0, 19).replace("T", " ") : null;
        const maxCreated = minTs.length ? new Date(Math.max(...minTs) + 86400000).toISOString().slice(0, 19).replace("T", " ") : null;
        if (dirs.length > 0 && created && minCreated && maxCreated) {
          const dirPlaceholders = dirs.map(() => "?").join(",");
          const lineageRows = db.prepare(
            `SELECT ${entry ? entry + " as entryNumber" : "rowid as entryNumber"}, ${fn} as fileName, ${ext ? ext + " as extension" : "'' as extension"}, ${pp} as parentPath, ${created} as created, ${zoneId ? `${zoneId} as zoneIdContents` : "'' as zoneIdContents"} FROM data WHERE ${pp} IN (${dirPlaceholders}) AND ${created} IS NOT NULL AND ${created} != '' AND sort_datetime(${created}) >= sort_datetime(?) AND sort_datetime(${created}) <= sort_datetime(?) ${notDir} ORDER BY sort_datetime(${created}) ASC LIMIT 8000`
          ).all(...dirs, minCreated, maxCreated);
          const rowsByDir = new Map();
          for (const r of lineageRows) {
            if (!rowsByDir.has(r.parentPath)) rowsByDir.set(r.parentPath, []);
            rowsByDir.get(r.parentPath).push(r);
          }
          for (const arch of archiveDownloads) {
            const aTs = parseTs(arch.created);
            if (!aTs) continue;
            const candidates = (rowsByDir.get(arch.parentPath) || []).filter((r) => {
              if ((r.entryNumber || "") === (arch.entryNumber || "")) return false;
              const rTs = parseTs(r.created);
              if (!rTs || rTs < aTs || rTs > aTs + 30 * 60 * 1000) return false;
              const extLower = String(r.extension || "").toLowerCase();
              return EXEC_EXTS.has(extLower) || OFFICE_EXTS.has(extLower) || ARCHIVE_EXTS.has(extLower);
            });
            if (candidates.length === 0) continue;
            const children = candidates.slice(0, 12).map((r) => {
              const parsed = parseZoneId(r.zoneIdContents);
              const extLower = String(r.extension || "").toLowerCase();
              return {
                entryNumber: r.entryNumber,
                fileName: r.fileName,
                extension: r.extension,
                created: r.created,
                zoneName: parsed.zoneName,
                hasZoneId: !!parsed.zoneName,
                isExecutableLike: EXEC_EXTS.has(extLower),
              };
            });
            const motwLossChildren = children.filter((c) => c.isExecutableLike && !c.hasZoneId);
            archiveLineage.push({
              archiveEntry: arch.entryNumber,
              archiveName: arch.fileName,
              archivePath: arch.parentPath,
              archiveCreated: arch.created,
              sourceHost: arch.sourceHost || "",
              internalHost: !!arch.internalHost,
              childCount: children.length,
              children,
              motwLossCount: motwLossChildren.length,
            });
            for (const child of motwLossChildren) {
              motwSuspicious.push({
                archiveName: arch.fileName,
                archiveCreated: arch.created,
                archivePath: arch.parentPath,
                childName: child.fileName,
                childCreated: child.created,
                sourceHost: arch.sourceHost || "",
                internalHost: !!arch.internalHost,
                reason: "archive had Zone.Identifier but extracted executable/script did not",
              });
            }
          }
          archiveLineage.sort((a, b) => (b.motwLossCount - a.motwLossCount) || (b.childCount - a.childCount));
          motwSuspicious.sort((a, b) => String(a.childCreated || "").localeCompare(String(b.childCreated || "")));
        }
      }

      const adsAnomalies = adsEntries.map((a) => {
        const streamMatch = String(a.fileName || "").match(STREAM_NAME_PAT);
        const streamName = streamMatch ? streamMatch[1] : "";
        const suspicious = !!streamName && !/^zone\.identifier$/i.test(streamName);
        const execLike = /\.(exe|dll|js|vbs|ps1|hta|bat|cmd|scr|lnk)$/i.test(streamName);
        return {
          ...a,
          streamName,
          suspicious,
          execLike,
        };
      }).filter((a) => a.suspicious).slice(0, 100);

      const riskyCount = prioritizedDownloads.filter((f) => f.riskScore >= 3).length;
      const archiveCount = prioritizedDownloads.filter((f) => f.isArchive).length;
      const execCount = prioritizedDownloads.filter((f) => f.isExecutableLike).length;
      const summaryParts = [];
      if (totalWithZoneId > 0) summaryParts.push(`${totalWithZoneId} MOTW-marked download${totalWithZoneId === 1 ? "" : "s"}`);
      if (archiveCount > 0) summaryParts.push(`${archiveCount} archive${archiveCount === 1 ? "" : "s"}`);
      if (motwSuspicious.length > 0) summaryParts.push(`${motwSuspicious.length} likely MOTW-loss child${motwSuspicious.length === 1 ? "" : "ren"}`);
      if (execCount > 0) summaryParts.push(`${execCount} executable/script download${execCount === 1 ? "" : "s"}`);
      if (internalHosts.length > 0) summaryParts.push(`source host${internalHosts.length === 1 ? "" : "s"} ${internalHosts.slice(0, 2).map((h) => h.host).join(", ")}`);
      const summary = {
        narrative: summaryParts.length > 0 ? summaryParts.join(" • ") : "No download-forensics story available",
        riskyCount,
        archiveCount,
        execCount,
        motwLossCount: motwSuspicious.length,
        internalHostCount: internalHosts.length,
      };

      return {
        totalWithAds,
        totalAdsEntries,
        totalWithZoneId,
        downloadedExecutables,
        zoneIdFiles,
        adsEntries,
        topDownloadDirs,
        zoneBreakdown,
        referrerUrls,
        hostUrls,
        prioritizedDownloads: prioritizedDownloads.slice(0, 250),
        archiveLineage: archiveLineage.slice(0, 40),
        motwSuspicious: motwSuspicious.slice(0, 60),
        internalHosts,
        sourceClusters,
        adsAnomalies,
        summary,
      };
    } catch (err) {
      return { ...empty, error: err.message };
    }
  }

  /**
   * USN Journal Analysis — run targeted forensic queries on $J data within a time window.
   * Covers: renames, deletions, file creation, exfil staging, execution artifacts,
   * persistence paths, and suspicious paths.
   */
  analyzeUsnJournal(tabId, { startTime, endTime, analyses, pathFilter, mftTabId }) {
    const meta = this.databases.get(tabId);
    const empty = {
      summary: { totalEvents: 0, startTime, endTime, pathFilter: null },
      renames: null, deletions: null, creations: null, exfil: null,
      execution: null, persistence: null, suspiciousPaths: null, securityChanges: null,
      dataOverwrite: null, streamChanges: null, closePatterns: null,
      timeline: [], fileChains: [], directoryIncidents: [], likelyFindings: [], narrative: [],
    };
    if (!meta) return empty;

    const db = meta.db;
    const col = (name) => meta.colMap[name];
    const nameCol = col("Name"), extCol = col("Extension"), entryCol = col("EntryNumber");
    const seqCol = col("SequenceNumber");
    const parentPathCol = col("ParentPath"), tsCol = col("UpdateTimestamp");
    const reasonCol = col("UpdateReasons"), attrsCol = col("FileAttributes");
    const usnCol = col("UpdateSequenceNumber");

    if (!nameCol || !tsCol || !reasonCol)
      return { ...empty, error: "Required USN Journal columns not found (Name, UpdateTimestamp, UpdateReasons)." };
    if (!startTime)
      return { ...empty, error: "Start time is required." };

    // End time is optional — if omitted, use a far-future value
    // Pad end time with .9999999 if no sub-seconds provided, so BETWEEN includes the full second
    let effectiveEnd = endTime || "9999-12-31 23:59:59";
    if (effectiveEnd && !effectiveEnd.includes(".")) effectiveEnd += ".9999999";

    const timeFilter = `sort_datetime(${tsCol}) BETWEEN sort_datetime(?) AND sort_datetime(?)`;

    // Normalize path filter: replace double backslashes with single (users often type \\)
    const normPath = pathFilter ? pathFilter.replace(/\\\\/g, "\\") : null;
    const pathLike = normPath ? `AND ${parentPathCol} LIKE ?` : "";
    const baseParams = normPath ? [startTime, effectiveEnd, `%${normPath}%`] : [startTime, effectiveEnd];
    const notDir = attrsCol ? `AND (${attrsCol} IS NULL OR ${attrsCol} NOT LIKE '%Directory%')` : "";
    const REASON_LABELS = {
      rename: "Rename",
      create: "Create",
      delete: "Delete",
      overwrite: "Overwrite",
      "acl-change": "ACL change",
      "stream-change": "ADS/stream change",
      close: "Close",
      metadata: "Metadata change",
      persistence: "Persistence path",
      execution: "Executable/script activity",
      exfil: "Archive staging",
      suspicious: "Suspicious path",
    };
    const EXEC_EXTS = new Set([".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".scr", ".com", ".msi", ".msp", ".cpl", ".sys"]);
    const SHORTCUT_EXTS = new Set([".lnk", ".url"]);
    const EXT_RISK = new Set([...EXEC_EXTS, ...SHORTCUT_EXTS, ".iso", ".img", ".zip", ".rar", ".7z", ".jar", ".reg"]);
    const ARCHIVE_EXTS = new Set([".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".bz2", ".iso", ".img"]);
    const LOW_SIGNAL_EXTS = new Set([".tmp", ".log", ".etl", ".pf", ".db", ".dat", ".evtx", ".blf", ".regtrans-ms", ".chk", ".cat", ".mum", ".manifest", ".mui", ".pnf", ".idx", ".map"]);
    const EZ_TOOL_NORMALIZED_NAMES = new Set([
      "amcacheparser",
      "appcompatcacheparser",
      "bstrings",
      "evtxecmd",
      "ezviewer",
      "getzimmermantools",
      "hasher",
      "iisgeolocate",
      "jlecmd",
      "jumplistexplorer",
      "kape",
      "lecmd",
      "mftecmd",
      "mftexplorer",
      "pecmd",
      "rbcmd",
      "recentfilecacheparser",
      "recmd",
      "registryexplorer",
      "rla",
      "sbecmd",
      "sdbexplorer",
      "shellbagsexplorer",
      "sqlecmd",
      "srumecmd",
      "sumecmd",
      "timeapp",
      "timelineexplorer",
      "vscmount",
      "wxtcmd",
      "xwfim",
    ]);
    const CORTEX_ENDPOINT_NORMALIZED_NAMES = new Set([
      "cortexxdr",
      "cortexxdrhealthhelper",
      "cymemdef",
      "cyopticsruntimedriver",
      "cyprotectdrv",
      "cyverak",
      "cyvrfsfd",
      "cyvrmtgn",
      "pangps",
      "panupdater",
      "tdevflt",
      "tedrdrv",
      "telam",
      "trapssupervisor",
      "xdrcollector",
    ]);
    const OFFLINE_COLLECTOR_SCRIPT_NAMES = new Set([
      "amcache",
      "amcacheparser",
      "anydeskconnectionparser",
      "anydesktraceparser",
      "applicationresourceusage",
      "arpcache",
      "arpcachedef",
      "bamparser",
      "bcfparser",
      "cidsizemruparser",
      "comdlgreg",
      "commonlib",
      "customjumplistparser",
      "dnscache",
      "dnsdef",
      "driversparser",
      "esedbtable",
      "fileretrieval",
      "fileutilswin",
      "filterutil",
      "forensicparser",
      "forensicsearch",
      "handles",
      "hosts",
      "jumplistappids",
      "jumplistparser",
      "knownfolders",
      "knownipinterface",
      "lastvisitedpidmruparser",
      "lnkparser",
      "logmeinparser",
      "netsessions",
      "networkconnectivitydataparser",
      "networkdatausageparser",
      "opensavepidmruparser",
      "parserutils",
      "pathresolver",
      "pathlibimproved",
      "portlisting",
      "prefetch",
      "prefetchhash",
      "prefetchparser",
      "processlisting",
      "psreadline",
      "recentfilesparser",
      "recyclebinparser",
      "regscanner",
      "registry",
      "registrypersistenceparser",
      "reglib",
      "resultset",
      "scheduledtasksparser",
      "services",
      "servicesparser",
      "sevenzipfolderhistory",
      "shellbags",
      "shellbagsbinaryparser",
      "shellbagsparser",
      "shellbagsutils",
      "shellitems",
      "shimdatabasesparser",
      "shimcacheparser",
      "srumdbparser",
      "startupfolderparser",
      "teamviewerparser",
      "triage",
      "typedpathsparser",
      "useraccesslogging",
      "userassistparser",
      "windowstimelineparser",
      "winrararchistory",
      "wmiparser",
      "wordwheelqueryparser",
    ]);
    const SUSP_PATH_PAT = /(\\temp\\|\\tmp\\|\\appdata\\local\\temp\\|\\users\\public\\|\\programdata\\|\\music\\|\\pictures\\|\\videos\\|\$recycle\.bin)/i;
    const STARTUP_PATH_PAT = /\\(?:programdata\\microsoft\\windows\\start menu\\programs\\startup|users\\[^\\]+\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup)(?:\\|$)/i;
    const SCHEDULED_TASK_PATH_PAT = /\\windows\\system32\\tasks(?:\\|$)/i;
    const LEGACY_TASK_PATH_PAT = /\\windows\\tasks(?:\\|$)/i;
    const GPO_SCRIPT_PATH_PAT = /\\windows\\system32\\grouppolicy\\(?:machine|user)\\scripts\\(?:startup|shutdown|logon|logoff)(?:\\|$)/i;
    const WMI_MOF_PATH_PAT = /\\windows\\(?:system32|syswow64)\\wbem\\(?:mof|autorecover)(?:\\|$)/i;
    const TEMP_PATH_PAT = /\\(?:windows\\temp|temp|tmp|appdata\\local\\temp)(?:\\|$)/i;
    const PUBLIC_PATH_PAT = /\\users\\public(?:\\|$)/i;
    const PROGRAMDATA_PATH_PAT = /\\programdata(?:\\|$)/i;
    const RECYCLE_BIN_PATH_PAT = /\\\$recycle\.bin(?:\\|$)/i;
    const MEDIA_PATH_PAT = /\\users\\[^\\]+\\(?:music|pictures|videos)(?:\\|$)/i;
    const RECOVERY_PATH_PAT = /\\(?:recovery|perflogs)(?:\\|$)/i;
    const CORTEX_ENDPOINT_PATH_PAT = /\\(?:program files(?: \(x86\))?\\(?:palo alto networks|cortex xdr)|programdata\\(?:palo alto networks|cortex(?: xdr)?))(?:\\|$)/i;
    const OFFLINE_COLLECTOR_PATH_PAT = /\\(?:u42-?offline triage(?:_x64)?(?: \d+)?|offline triage(?:_x64)?(?: \d+)?|offline[_ -]?collector|xdr[_ -]?collector)(?:\\scripts)?(?:\\|$)/i;
    const DESTRUCTIVE_REASON_BUCKETS = new Set(["overwrite", "rename", "delete", "acl-change", "stream-change"]);
    const BENIGN_NOISE_RULES = [
      { label: "Defender", pattern: /\\programdata\\microsoft\\(?:windows defender|windows defender advanced threat protection|microsoft defender|windows security health)/i },
      { label: "Windows Update", pattern: /\\(?:programdata\\uso(?:shared|private)|windows\\softwaredistribution|windows\\winsxs|windows\\servicing|windows\\installer|programdata\\package cache)/i },
      { label: "OneDrive", pattern: /\\(?:programdata\\microsoft\\onedrive|users\\[^\\]+\\appdata\\local\\microsoft\\onedrive)/i },
      { label: "Office temp", pattern: /\\(?:appdata\\local\\temp\\content\.mso|appdata\\local\\microsoft\\office\\|appdata\\local\\microsoft\\windows\\inetcache\\content\.outlook)/i },
      { label: "Browser cache/update", pattern: /\\(?:users\\[^\\]+\\appdata\\local\\google\\(?:chrome\\user data\\.*\\(?:cache|code cache)|update)|users\\[^\\]+\\appdata\\local\\microsoft\\(?:edge\\user data\\.*\\(?:cache|code cache)|edgeupdate)|users\\[^\\]+\\appdata\\local\\mozilla\\firefox\\profiles\\.*\\(?:cache2?|startupcache))/i },
      { label: "Software deployment", pattern: /\\(?:windows\\ccm(?:cache)?|windows\\imecache|programdata\\microsoft\\intunemanagementextension|programdata\\(?:qualys|tenable|tanium|rapid7|bigfix|flexera|pdq deploy))/i },
    ];
    const BENIGN_TASK_RULES = [
      { label: "Windows built-in task", pattern: /\\windows\\system32\\tasks\\microsoft\\windows\\(?:defrag|diagnosis|diskcleanup|windowsupdate|updateorchestrator|wdi|defender|softwareprotectionplatform|time synchronization|filehistory|chkdsk|maps|pushToInstall|servicing|remediation|rempl|customer experience improvement program|subscription|memorydiagnostic|bitlocker|speech|printing)(?:\\|$)/i },
      { label: "Vendor updater task", pattern: /\\windows\\system32\\tasks\\(?:google|microsoftedgeupdate|adobe|onedrive|zoom|teams|office|citrix|vmware|slack|okta|qualys|tenable|rapid7|tanium|bigfix)(?:\\|$)/i },
    ];
    const TRUST_TIER_META = {
      system: { label: "System", dampening: 5 },
      "program-files": { label: "Program Files", dampening: 4 },
      "enterprise-management": { label: "Enterprise management", dampening: 4 },
      "browser-cache-update": { label: "Browser cache/update", dampening: 5 },
      "office-outlook": { label: "Office/Outlook", dampening: 5 },
      "onedrive-defender-update": { label: "OneDrive/Defender/Update", dampening: 6 },
      "security-tooling": { label: "Security tooling", dampening: 8, allowlist: true },
      "dfir-tooling": { label: "DFIR tooling", dampening: 8, allowlist: true },
    };
    const TWO_SIGNAL_EVENT_CATEGORIES = new Set(["execution", "exfil", "securityChanges", "closePatterns"]);
    const TWO_SIGNAL_REASON_BUCKETS = new Set(["execution", "exfil", "acl-change", "close"]);
    const TWO_SIGNAL_LOCATION_TAGS = new Set(["public-drop", "programdata-drop", "media-folder-payload"]);
    const OUTLIER_TAGS = new Set(["rare-directory", "rare-extension", "rare-reason-mix", "local-burst"]);
    const STRONG_MFT_TAGS = new Set(["downloaded", "timestomp", "deleted-in-mft"]);
    const STRONG_PATH_TAGS = new Set(["startup-folder", "scheduled-task", "gpo-script", "wmi-persistence", "temp-executable", "temp-archive", "temp-tampering", "public-drop", "programdata-drop", "recycle-bin-artifact", "media-folder-payload", "recovery-artifact"]);
    const parseTs = (v) => {
      if (!v) return NaN;
      const ms = Date.parse(String(v).replace(" ", "T"));
      return Number.isFinite(ms) ? ms : NaN;
    };
    const joinPath = (dir, name) => {
      if (!name) return dir || "";
      if (!dir) return name;
      return dir.endsWith("\\") ? `${dir}${name}` : `${dir}\\${name}`;
    };
    const deriveExtension = (name, extension) => {
      const ext = String(extension || "").trim().toLowerCase();
      if (ext) return ext.startsWith(".") ? ext : `.${ext}`;
      const fileName = String(name || "");
      const idx = fileName.lastIndexOf(".");
      return idx > 0 ? fileName.slice(idx).toLowerCase() : "";
    };
    const normalizeArtifactNameToken = (name) => {
      const fileName = String(name || "").split(/[\\/]/).pop() || "";
      const stem = fileName.replace(/\.[^.]+$/, "");
      return stem.toLowerCase().replace(/[^a-z0-9]+/g, "");
    };
    const classifyTrustedUsnArtifact = ({ name = "", parentPath = "", fullPath = "", extension = "" } = {}) => {
      const candidatePath = String(fullPath || joinPath(parentPath, name) || "");
      const pathLower = candidatePath.toLowerCase();
      const ext = deriveExtension(name || candidatePath.split(/[\\/]/).pop() || "", extension);
      const token = normalizeArtifactNameToken(name || candidatePath);
      const binaryLike = EXEC_EXTS.has(ext) || ARCHIVE_EXTS.has(ext);

      if (token && binaryLike && EZ_TOOL_NORMALIZED_NAMES.has(token)) {
        return {
          key: "dfir-tooling",
          label: "EZTools",
          suppressionReason: "EZTools forensic binary",
        };
      }

      if (token && ext === ".py" && OFFLINE_COLLECTOR_SCRIPT_NAMES.has(token) && OFFLINE_COLLECTOR_PATH_PAT.test(pathLower)) {
        return {
          key: "dfir-tooling",
          label: "Cortex XDR offline collector",
          suppressionReason: "Cortex XDR offline collector script",
        };
      }

      if ((EXEC_EXTS.has(ext) || token === "xdrcollector")
        && (CORTEX_ENDPOINT_PATH_PAT.test(pathLower) || CORTEX_ENDPOINT_NORMALIZED_NAMES.has(token))) {
        return {
          key: "security-tooling",
          label: "Palo Alto Cortex XDR",
          suppressionReason: "Palo Alto / Cortex XDR endpoint binary",
        };
      }

      return null;
    };
    const normalizeUsnReasons = (reasonStr, sectionKey) => {
      const s = String(reasonStr || "");
      const out = [];
      if (/RenameOldName|RenameNewName/i.test(s)) out.push("rename");
      if (/FileCreate/i.test(s)) out.push("create");
      if (/FileDelete/i.test(s)) out.push("delete");
      if (/DataOverwrite|DataExtend|DataTruncation/i.test(s)) out.push("overwrite");
      if (/SecurityChange/i.test(s)) out.push("acl-change");
      if (/StreamChange/i.test(s)) out.push("stream-change");
      if (/BasicInfoChange|FileNameChange|EAChange/i.test(s)) out.push("metadata");
      if (/^Close$/i.test(s) || (!out.length && /Close/i.test(s))) out.push("close");
      if (sectionKey === "persistence") out.push("persistence");
      if (sectionKey === "execution") out.push("execution");
      if (sectionKey === "exfil") out.push("exfil");
      if (sectionKey === "suspiciousPaths") out.push("suspicious");
      return [...new Set(out)];
    };
    const hasInterestingReasons = (reasonBuckets) => (reasonBuckets || []).some((bucket) => DESTRUCTIVE_REASON_BUCKETS.has(bucket));
    const matchRuleLabel = (rules, value) => {
      const candidate = String(value || "");
      for (const rule of rules) {
        if (rule.pattern.test(candidate)) return rule.label;
      }
      return "";
    };
    const summarizeUsnSuppressions = (rows) => {
      const counts = {};
      for (const row of rows || []) {
        const label = row?.suppressionReason || "Other benign churn";
        counts[label] = (counts[label] || 0) + 1;
      }
      return Object.entries(counts)
        .map(([label, count]) => ({ label, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 6);
    };
    const classifyPersistenceRow = (row) => {
      const parentPath = String(row?.parentPath || "");
      const fullPath = joinPath(parentPath, row?.name || "");
      const parentLower = parentPath.toLowerCase();
      const fullLower = fullPath.toLowerCase();
      const name = String(row?.name || "");
      const nameLower = name.toLowerCase();
      const extension = deriveExtension(name, row?.extension);
      const reasonBuckets = normalizeUsnReasons(row?.reasons, "persistence");
      const interestingReasons = hasInterestingReasons(reasonBuckets);
      let category = "";
      let tags = [];
      let heuristicRisk = 0;
      let suppressionReason = "";
      const trustedArtifact = classifyTrustedUsnArtifact({ name, parentPath, fullPath, extension });

      if (trustedArtifact) return { include: false, suppressionReason: trustedArtifact.suppressionReason };

      if (STARTUP_PATH_PAT.test(parentLower)) {
        category = "Startup Folder";
        tags = ["startup-folder"];
        heuristicRisk = 4;
        if (!(EXEC_EXTS.has(extension) || SHORTCUT_EXTS.has(extension) || !extension)) {
          suppressionReason = "Non-startup artifact in Startup folder";
        }
      } else if (SCHEDULED_TASK_PATH_PAT.test(parentLower)) {
        category = "Scheduled Task";
        tags = ["scheduled-task"];
        heuristicRisk = 4;
        const taskRule = matchRuleLabel(BENIGN_TASK_RULES, fullLower);
        if (taskRule && !interestingReasons) suppressionReason = taskRule;
      } else if (LEGACY_TASK_PATH_PAT.test(parentLower)) {
        category = "Legacy Task File";
        tags = ["scheduled-task"];
        heuristicRisk = 3;
        if (extension && extension !== ".job" && !EXEC_EXTS.has(extension) && !SHORTCUT_EXTS.has(extension)) {
          suppressionReason = "Non-task artifact in legacy task path";
        }
      } else if (GPO_SCRIPT_PATH_PAT.test(parentLower)) {
        category = "Group Policy Script";
        tags = ["gpo-script"];
        heuristicRisk = 4;
        if (extension && ![".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf"].includes(extension)) {
          suppressionReason = "Non-script artifact in GPO script path";
        }
      } else if (WMI_MOF_PATH_PAT.test(parentLower)) {
        category = "WMI MOF";
        tags = ["wmi-persistence"];
        heuristicRisk = 4;
        if (![".mof", ".mfl", ".bmf"].includes(extension) && !EXEC_EXTS.has(extension) && !interestingReasons) {
          suppressionReason = "Low-signal WMI file churn";
        }
      } else {
        return { include: false, suppressionReason: "Outside persistence scope" };
      }

      if (!suppressionReason && /^(desktop\.ini|thumbs\.db)$/i.test(nameLower)) suppressionReason = "Shell metadata";
      if (!suppressionReason && LOW_SIGNAL_EXTS.has(extension) && !interestingReasons) suppressionReason = "Low-signal file type";
      if (!suppressionReason) {
        const benignRule = matchRuleLabel(BENIGN_NOISE_RULES, fullLower);
        if (benignRule && !EXEC_EXTS.has(extension) && !SHORTCUT_EXTS.has(extension) && !interestingReasons) suppressionReason = benignRule;
      }

      return {
        include: !suppressionReason,
        suppressionReason,
        category,
        tags,
        heuristicRisk,
      };
    };
    const classifySuspiciousPathRow = (row) => {
      const parentPath = String(row?.parentPath || "");
      const fullPath = joinPath(parentPath, row?.name || "");
      const parentLower = parentPath.toLowerCase();
      const fullLower = fullPath.toLowerCase();
      const name = String(row?.name || "");
      const nameLower = name.toLowerCase();
      const extension = deriveExtension(name, row?.extension);
      const reasonBuckets = normalizeUsnReasons(row?.reasons, "suspiciousPaths");
      const interestingReasons = hasInterestingReasons(reasonBuckets);
      const payloadLike = EXEC_EXTS.has(extension) || SHORTCUT_EXTS.has(extension);
      const archiveLike = ARCHIVE_EXTS.has(extension);
      let category = "";
      let tags = [];
      let heuristicRisk = 0;
      let suppressionReason = "";
      const trustedArtifact = classifyTrustedUsnArtifact({ name, parentPath, fullPath, extension });

      if (trustedArtifact) return { include: false, suppressionReason: trustedArtifact.suppressionReason };

      if (STARTUP_PATH_PAT.test(parentLower) || SCHEDULED_TASK_PATH_PAT.test(parentLower) || LEGACY_TASK_PATH_PAT.test(parentLower) || GPO_SCRIPT_PATH_PAT.test(parentLower) || WMI_MOF_PATH_PAT.test(parentLower)) {
        return { include: false, suppressionReason: "Covered by persistence paths" };
      }
      if (TEMP_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "Routine temp churn" };
        category = payloadLike ? "Temp Payload" : archiveLike ? "Temp Archive" : "Temp Tampering";
        tags = [payloadLike ? "temp-executable" : archiveLike ? "temp-archive" : "temp-tampering"];
        heuristicRisk = payloadLike ? 4 : archiveLike ? 3 : 2;
      } else if (PUBLIC_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "Routine Public folder churn" };
        category = payloadLike || SHORTCUT_EXTS.has(extension) ? "Public Path Payload" : archiveLike ? "Public Archive" : "Public Path Tampering";
        tags = ["public-drop"];
        heuristicRisk = payloadLike || SHORTCUT_EXTS.has(extension) ? 4 : 3;
      } else if (RECYCLE_BIN_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "Routine Recycle Bin churn" };
        category = "Recycle Bin Artifact";
        tags = ["recycle-bin-artifact"];
        heuristicRisk = 4;
      } else if (PROGRAMDATA_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "Routine ProgramData churn" };
        category = payloadLike || SHORTCUT_EXTS.has(extension) ? "ProgramData Payload" : archiveLike ? "ProgramData Archive" : "ProgramData Tampering";
        tags = ["programdata-drop"];
        heuristicRisk = payloadLike || SHORTCUT_EXTS.has(extension) ? 3 : 2;
      } else if (RECOVERY_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || interestingReasons)) return { include: false, suppressionReason: "System recovery/log churn" };
        category = "Recovery/PerfLogs Artifact";
        tags = ["recovery-artifact"];
        heuristicRisk = 3;
      } else if (MEDIA_PATH_PAT.test(parentLower)) {
        if (!(payloadLike || archiveLike || SHORTCUT_EXTS.has(extension))) return { include: false, suppressionReason: "Regular media file activity" };
        category = "Media Folder Payload";
        tags = ["media-folder-payload"];
        heuristicRisk = 4;
      } else {
        return { include: false, suppressionReason: "Outside suspicious path scope" };
      }

      if (!suppressionReason && /^(desktop\.ini|thumbs\.db)$/i.test(nameLower)) suppressionReason = "Shell metadata";
      if (!suppressionReason && LOW_SIGNAL_EXTS.has(extension) && !interestingReasons && !payloadLike && !archiveLike) suppressionReason = "Low-signal file type";
      if (!suppressionReason) {
        const benignRule = matchRuleLabel(BENIGN_NOISE_RULES, fullLower);
        if (benignRule && !payloadLike && !interestingReasons) suppressionReason = benignRule;
      }

      return {
        include: !suppressionReason,
        suppressionReason,
        category,
        tags,
        heuristicRisk,
      };
    };
    const classifyTrustTier = (fullPath, parentPath) => {
      const trustedArtifact = classifyTrustedUsnArtifact({
        name: String(fullPath || "").split(/[\\/]/).pop() || "",
        parentPath,
        fullPath,
      });
      if (trustedArtifact && TRUST_TIER_META[trustedArtifact.key]) {
        return { key: trustedArtifact.key, ...TRUST_TIER_META[trustedArtifact.key] };
      }
      const candidate = String(fullPath || parentPath || "").toLowerCase();
      if (!candidate) return { key: "", label: "", dampening: 0 };
      const benignLabel = matchRuleLabel(BENIGN_NOISE_RULES, candidate);
      if (benignLabel === "Software deployment") return { key: "enterprise-management", ...TRUST_TIER_META["enterprise-management"] };
      if (benignLabel === "Browser cache/update") return { key: "browser-cache-update", ...TRUST_TIER_META["browser-cache-update"] };
      if (benignLabel === "Office temp") return { key: "office-outlook", ...TRUST_TIER_META["office-outlook"] };
      if (benignLabel === "OneDrive" || benignLabel === "Defender" || benignLabel === "Windows Update") {
        return { key: "onedrive-defender-update", ...TRUST_TIER_META["onedrive-defender-update"] };
      }
      if (/\\program files(?: \(x86\))?(?:\\|$)/i.test(candidate)) return { key: "program-files", ...TRUST_TIER_META["program-files"] };
      if (/\\windows\\(?:system32|syswow64|systemapps|systemresources|inf|fonts)(?:\\|$)/i.test(candidate)) return { key: "system", ...TRUST_TIER_META.system };
      return { key: "", label: "", dampening: 0 };
    };
    const primaryReasonBucket = (buckets) => {
      const order = ["acl-change", "overwrite", "stream-change", "rename", "delete", "create", "persistence", "execution", "exfil", "suspicious", "metadata", "close"];
      return order.find((k) => buckets.includes(k)) || (buckets[0] || "metadata");
    };
    const scoreUsnObservedEvent = (ev) => {
      let score = 0;
      if (ev.reasonBuckets.includes("acl-change")) score += 4;
      if (ev.reasonBuckets.includes("overwrite")) score += 4;
      if (ev.reasonBuckets.includes("stream-change")) score += 3;
      if (ev.reasonBuckets.includes("rename")) score += 2;
      if (ev.reasonBuckets.includes("delete")) score += 2;
      if (ev.reasonBuckets.includes("create")) score += 2;
      if (ev.category === "persistence") score += 3;
      if (ev.category === "execution") score += 3;
      if (ev.category === "exfil") score += 3;
      if (ev.category === "suspiciousPaths") score += 1;
      if (EXT_RISK.has((ev.extension || "").toLowerCase())) score += 2;
      if ((ev.heuristicRisk || 0) >= 4) score += 3;
      else if ((ev.heuristicRisk || 0) >= 2) score += 2;
      else if (SUSP_PATH_PAT.test(ev.parentPath || "")) score += 1;
      if (ev.tags?.includes("downloaded")) score += 2;
      if (ev.tags?.includes("timestomp")) score += 2;
      if (ev.tags?.includes("deleted-in-mft")) score += 2;
      if (ev.tags?.includes("persistence-related")) score += 3;
      if (ev.tags?.includes("executable-or-script")) score += 2;
      if (ev.tags?.includes("archive-staging")) score += 2;
      if (ev.tags?.includes("startup-folder")) score += 3;
      if (ev.tags?.includes("scheduled-task")) score += 3;
      if (ev.tags?.includes("gpo-script")) score += 3;
      if (ev.tags?.includes("wmi-persistence")) score += 3;
      if (ev.tags?.includes("temp-executable")) score += 3;
      if (ev.tags?.includes("public-drop")) score += 2;
      if (ev.tags?.includes("programdata-drop")) score += 2;
      if (ev.tags?.includes("recycle-bin-artifact")) score += 2;
      if (ev.tags?.includes("media-folder-payload")) score += 2;
      if (ev.tags?.includes("recovery-artifact")) score += 2;
      return score;
    };
    const eventNeedsTwoSignals = (ev) => {
      const tags = new Set(ev.tags || []);
      return TWO_SIGNAL_EVENT_CATEGORIES.has(ev.category) || [...TWO_SIGNAL_LOCATION_TAGS].some((tag) => tags.has(tag));
    };
    const deriveEventPromotionSignals = (ev) => {
      const tags = new Set(ev.tags || []);
      const reasons = new Set(ev.reasonBuckets || []);
      const out = new Set();
      const extension = (ev.extension || "").toLowerCase();
      const parentLower = String(ev.parentPath || "").toLowerCase();

      if (tags.has("downloaded")) out.add("downloaded");
      if (tags.has("timestomp")) out.add("timestomp");
      if (tags.has("deleted-in-mft")) out.add("deleted");
      if ([...OUTLIER_TAGS].some((tag) => tags.has(tag))) out.add("outlier");
      if ([...DESTRUCTIVE_REASON_BUCKETS].some((bucket) => reasons.has(bucket))) out.add("destructive");
      if ((ev.reasonBuckets || []).length >= 2) out.add("multi-reason");
      if ([...STRONG_PATH_TAGS].some((tag) => tags.has(tag))) out.add("risky-location");
      if (STARTUP_PATH_PAT.test(parentLower) || SCHEDULED_TASK_PATH_PAT.test(parentLower) || LEGACY_TASK_PATH_PAT.test(parentLower) || GPO_SCRIPT_PATH_PAT.test(parentLower) || WMI_MOF_PATH_PAT.test(parentLower)) out.add("persistence-path");
      if (TEMP_PATH_PAT.test(parentLower) || PUBLIC_PATH_PAT.test(parentLower) || PROGRAMDATA_PATH_PAT.test(parentLower) || RECYCLE_BIN_PATH_PAT.test(parentLower) || MEDIA_PATH_PAT.test(parentLower) || RECOVERY_PATH_PAT.test(parentLower)) out.add("risky-path");
      if ((EXEC_EXTS.has(extension) || SHORTCUT_EXTS.has(extension)) && ev.category !== "execution") out.add("payload-ext");
      if (ARCHIVE_EXTS.has(extension) && ev.category !== "exfil") out.add("archive-ext");
      if ((ev.heuristicRisk || 0) >= 4) out.add("high-risk-heuristic");
      return [...out];
    };
    const evaluateUsnEvent = (ev) => {
      const trustTier = classifyTrustTier(ev.fullPath, ev.parentPath);
      const observedScore = Math.max(0, scoreUsnObservedEvent(ev) - (trustTier.dampening || 0));
      const promotionSignals = deriveEventPromotionSignals(ev);
      if (trustTier.allowlist) {
        return {
          trustTier,
          observedScore,
          promotionSignals,
          requiredSignalCount: Number.MAX_SAFE_INTEGER,
          promotionEligible: false,
          confidence: "trusted",
          riskScore: Math.min(observedScore, 1),
        };
      }
      const gated = eventNeedsTwoSignals(ev);
      const requiredSignalCount = gated ? 2 + (trustTier.key ? 1 : 0) : 1;
      const promotionEligible = promotionSignals.length >= requiredSignalCount;
      let confidence = "observed";
      if (promotionEligible) {
        confidence = promotionSignals.length >= (requiredSignalCount + 1) || promotionSignals.some((sig) => sig === "downloaded" || sig === "timestomp" || sig === "persistence-path")
          ? "high"
          : "medium";
      }
      let riskScore = observedScore;
      if (promotionEligible) riskScore += Math.min(4, promotionSignals.length - requiredSignalCount + 1);
      else riskScore = Math.min(riskScore, gated ? 3 : 4);
      return {
        trustTier,
        observedScore,
        promotionSignals,
        requiredSignalCount,
        promotionEligible,
        confidence,
        riskScore: Math.max(0, riskScore),
      };
    };
    const bucketForDirectory = (ev) => primaryReasonBucket(ev.reasonBuckets);
    const makeIncidentTitle = (bucket, path) => {
      const labels = {
        "acl-change": "Mass permission change",
        overwrite: "Overwrite burst",
        rename: "Rename burst",
        delete: "Deletion burst",
        create: "File creation burst",
        "stream-change": "ADS / stream change burst",
        persistence: "Persistence path activity",
        execution: "Executable drop burst",
        exfil: "Archive staging burst",
        suspicious: "Suspicious path activity",
        metadata: "Metadata change burst",
        close: "Enumeration / close burst",
      };
      return `${labels[bucket] || "USN activity"} in ${path || "(unknown)"}`;
    };

    const correlationLabelMap = {
      downloaded: "ADS download",
      timestomp: "Timestomp indicator",
      "deleted-in-mft": "Deleted in MFT",
      "persistence-related": "Persistence-related",
      "executable-or-script": "Executable/script",
      "archive-staging": "Archive staging",
      "acl-change-burst": "ACL change burst",
      "overwrite-burst": "Overwrite burst",
      "rename-burst": "Rename burst",
      "stream-activity": "ADS/stream activity",
      "startup-folder": "Startup folder",
      "scheduled-task": "Scheduled task",
      "gpo-script": "GPO script",
      "wmi-persistence": "WMI MOF",
      "temp-executable": "Temp payload",
      "temp-archive": "Temp archive",
      "temp-tampering": "Temp tampering",
      "public-drop": "Public path payload",
      "programdata-drop": "ProgramData payload",
      "recycle-bin-artifact": "Recycle Bin artifact",
      "media-folder-payload": "Media folder payload",
      "recovery-artifact": "Recovery/PerfLogs artifact",
      "rare-directory": "Rare directory",
      "rare-extension": "Rare extension",
      "rare-reason-mix": "Rare reason mix",
      "local-burst": "Local burst",
    };
    const correlationWeight = (tag) => ({
      downloaded: 2,
      timestomp: 2,
      "deleted-in-mft": 2,
      "persistence-related": 3,
      "executable-or-script": 2,
      "archive-staging": 2,
      "acl-change-burst": 2,
      "overwrite-burst": 3,
      "rename-burst": 2,
      "stream-activity": 2,
      "startup-folder": 3,
      "scheduled-task": 3,
      "gpo-script": 3,
      "wmi-persistence": 3,
      "temp-executable": 3,
      "temp-archive": 2,
      "temp-tampering": 2,
      "public-drop": 2,
      "programdata-drop": 2,
      "recycle-bin-artifact": 2,
      "media-folder-payload": 2,
      "recovery-artifact": 2,
      "rare-directory": 2,
      "rare-extension": 1,
      "rare-reason-mix": 1,
      "local-burst": 2,
    }[tag] || 0);
    const crossModuleSynergyScore = (tagsLike) => {
      const tags = new Set(tagsLike || []);
      let score = 0;
      if (tags.has("downloaded") && tags.has("executable-or-script")) score += 3;
      if (tags.has("downloaded") && tags.has("persistence-related")) score += 3;
      if (tags.has("downloaded") && (tags.has("temp-executable") || tags.has("public-drop") || tags.has("programdata-drop"))) score += 3;
      if (tags.has("downloaded") && (tags.has("startup-folder") || tags.has("scheduled-task") || tags.has("gpo-script") || tags.has("wmi-persistence"))) score += 4;
      if (tags.has("downloaded") && tags.has("timestomp")) score += 2;
      if (tags.has("persistence-related") && tags.has("timestomp")) score += 3;
      if (tags.has("archive-staging") && tags.has("overwrite-burst")) score += 3;
      if (tags.has("deleted-in-mft") && tags.has("timestomp")) score += 2;
      if (tags.has("deleted-in-mft") && tags.has("archive-staging")) score += 2;
      if (tags.has("rare-directory") && (tags.has("executable-or-script") || tags.has("persistence-related"))) score += 2;
      if (tags.has("rare-extension") && tags.has("downloaded")) score += 2;
      return score;
    };
    const severityForPriority = (score) => score >= 14 ? "critical" : score >= 10 ? "high" : score >= 6 ? "medium" : "low";
    const findingDurationMinutes = (start, end) => {
      const startMs = parseTs(start);
      const endMs = parseTs(end);
      if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return null;
      return Math.max(1, Math.round((endMs - startMs) / 60000));
    };
    const pushUnique = (arr, value) => {
      if (!value || arr.includes(value)) return;
      arr.push(value);
    };
    const buildEvidenceList = ({ reasonBuckets = [], tags = [], topExtensions = [], categories = [] }) => {
      const out = [];
      reasonBuckets.forEach((bucket) => pushUnique(out, REASON_LABELS[bucket] || ""));
      tags.forEach((tag) => pushUnique(out, correlationLabelMap[tag] || ""));
      topExtensions.forEach((item) => {
        const ext = item?.ext || item;
        if (ext && ext !== "(none)") pushUnique(out, `${ext} activity`);
      });
      categories.forEach((cat) => pushUnique(out, cat));
      return out.slice(0, 4);
    };
    const explainIncidentFinding = (inc) => {
      const tags = new Set(inc.tags || []);
      if (tags.has("overwrite-burst")) return "Mass overwrite activity is consistent with encryption, wiping, or bulk content tampering.";
      if (tags.has("rename-burst")) return "Burst rename activity can indicate staging, masquerading, or ransomware rename phases.";
      if (tags.has("acl-change-burst")) return "Bulk ACL changes can indicate permission tampering or archive extraction staging.";
      if (tags.has("stream-activity")) return "ADS or stream changes clustered in one directory can indicate hidden data or Mark-of-the-Web manipulation.";
      if (tags.has("startup-folder")) return "Writes inside a Startup folder can indicate logon persistence and merit immediate validation.";
      if (tags.has("scheduled-task")) return "Task-definition activity can indicate scheduled-task persistence or task tampering.";
      if (tags.has("gpo-script")) return "Group Policy logon/startup script changes can indicate policy-based persistence.";
      if (tags.has("wmi-persistence")) return "MOF or AutoRecover writes can indicate WMI event-consumer persistence.";
      if (tags.has("temp-executable")) return "Executable/script activity in temp locations is higher signal than routine temporary file churn.";
      if (tags.has("public-drop")) return "Payload-like activity in a Public path is a common staging pattern because the location is broadly writable.";
      if (tags.has("programdata-drop")) return "Payload-like activity in ProgramData can indicate masquerading, service-style staging, or follow-on persistence.";
      if (tags.has("local-burst")) return "This incident spikes above its local baseline in the selected window and should be triaged first.";
      if (inc.reasonFamily === "execution") return "Executable/script activity clustered in one directory can reveal payload staging or tool drops.";
      if (inc.reasonFamily === "persistence") return "Repeated activity in a persistence-related directory can indicate foothold establishment.";
      if (inc.reasonFamily === "close") return "Close-only bursts often reflect rapid file enumeration or reconnaissance.";
      if (inc.reasonFamily === "exfil") return "Archive staging activity can indicate data collection and exfil preparation.";
      return `Clustered ${String(REASON_LABELS[inc.reasonFamily] || inc.reasonFamily || "activity").toLowerCase()} in one directory stands out from routine file churn.`;
    };
    const explainChainFinding = (ch) => {
      const tags = new Set(ch.tags || []);
      const reasons = new Set(ch.reasonBuckets || []);
      if (tags.has("downloaded") && tags.has("executable-or-script")) return "A downloaded executable/script is a strong payload indicator and should be validated first.";
      if (tags.has("downloaded") && tags.has("persistence-related")) return "A downloaded artifact touching persistence locations is a strong foothold indicator.";
      if (tags.has("startup-folder")) return "This file chain touches a Startup folder and may represent logon persistence.";
      if (tags.has("scheduled-task")) return "This file chain touches a scheduled-task path and may represent task-based persistence.";
      if (tags.has("gpo-script")) return "This file chain touches Group Policy script paths and may represent policy-based persistence.";
      if (tags.has("wmi-persistence")) return "This file chain touches WMI MOF paths and may represent event-based persistence.";
      if (tags.has("temp-executable")) return "Payload-like activity in temp paths is stronger signal than generic temp churn and should be triaged early.";
      if (tags.has("public-drop")) return "Payload-like activity in a Public path is a common staging and execution pattern.";
      if (tags.has("programdata-drop")) return "ProgramData payload activity can indicate masquerading or service-style staging.";
      if (tags.has("rare-directory")) return "This artifact appears in a directory that is rare in the selected dataset, which increases triage value.";
      if (tags.has("rare-extension")) return "This extension is unusually rare in the selected dataset and may represent a stand-out artifact.";
      if (tags.has("persistence-related")) return "This artifact touches a persistence-related path and may represent a survival mechanism.";
      if (tags.has("timestomp")) return "MFT metadata indicates timestomping, which is consistent with anti-forensics.";
      if (tags.has("deleted-in-mft")) return "The artifact is already deleted in MFT, which can indicate cleanup after execution.";
      if (tags.has("archive-staging")) return "Archive staging activity can indicate collection and exfil preparation.";
      if (reasons.has("stream-change")) return "ADS or stream changes can indicate hidden data or Mark-of-the-Web manipulation.";
      if (reasons.has("rename") && (ch.pathTransitions?.length || 0) > 1) return "Repeated rename or path transitions can indicate masquerading or staging.";
      if (reasons.has("overwrite")) return "Content overwrite activity against one file chain can indicate payload modification or destructive behavior.";
      return "This file chain combines multiple suspicious changes closely enough to merit immediate review.";
    };
    const dominantTrustTier = (trustTierCounts) => {
      const top = [...(trustTierCounts?.entries?.() || [])].sort((a, b) => b[1] - a[1])[0];
      if (!top || !TRUST_TIER_META[top[0]]) return { key: "", label: "", dampening: 0 };
      return { key: top[0], ...TRUST_TIER_META[top[0]] };
    };
    const aggregateNeedsTwoSignals = ({ categoryKeys = [], reasonFamily = "", tags = [] }) => {
      const tagSet = new Set(tags || []);
      return (categoryKeys || []).some((key) => TWO_SIGNAL_EVENT_CATEGORIES.has(key))
        || (reasonFamily && TWO_SIGNAL_REASON_BUCKETS.has(reasonFamily))
        || [...TWO_SIGNAL_LOCATION_TAGS].some((tag) => tagSet.has(tag));
    };
    const deriveAggregatePromotionSignals = ({ tags = [], reasonBuckets = [], extensions = [], path = "", eventCount = 0, uniqueFiles = 0, promotedEventCount = 0, pathVariants = 0 }) => {
      const tagSet = new Set(tags || []);
      const reasonSet = new Set(reasonBuckets || []);
      const extList = (extensions || []).map((ext) => String(ext || "").toLowerCase());
      const pathLower = String(path || "").toLowerCase();
      const out = new Set();
      if ([...STRONG_MFT_TAGS].some((tag) => tagSet.has(tag))) out.add("mft-corroboration");
      if ([...OUTLIER_TAGS].some((tag) => tagSet.has(tag))) out.add("outlier");
      if ([...STRONG_PATH_TAGS].some((tag) => tagSet.has(tag))) out.add("risky-location");
      if ([...DESTRUCTIVE_REASON_BUCKETS].some((bucket) => reasonSet.has(bucket)) || reasonSet.has("acl-change")) out.add("destructive");
      if (reasonSet.size >= 2) out.add("multi-reason");
      if (STARTUP_PATH_PAT.test(pathLower) || SCHEDULED_TASK_PATH_PAT.test(pathLower) || LEGACY_TASK_PATH_PAT.test(pathLower) || GPO_SCRIPT_PATH_PAT.test(pathLower) || WMI_MOF_PATH_PAT.test(pathLower)) out.add("persistence-path");
      if (TEMP_PATH_PAT.test(pathLower) || PUBLIC_PATH_PAT.test(pathLower) || PROGRAMDATA_PATH_PAT.test(pathLower) || RECYCLE_BIN_PATH_PAT.test(pathLower) || MEDIA_PATH_PAT.test(pathLower) || RECOVERY_PATH_PAT.test(pathLower)) out.add("risky-path");
      if (extList.some((ext) => EXEC_EXTS.has(ext) || SHORTCUT_EXTS.has(ext))) out.add("payload-ext");
      if (extList.some((ext) => ARCHIVE_EXTS.has(ext))) out.add("archive-ext");
      if (promotedEventCount > 0) out.add("event-corroboration");
      if (eventCount >= 8 || uniqueFiles >= 5) out.add("volume");
      if (pathVariants > 1) out.add("path-variation");
      return [...out];
    };
    const evaluateAggregateConfidence = ({ tags = [], categoryKeys = [], reasonFamily = "", trustTierCounts = new Map(), reasonBuckets = [], extensions = [], path = "", eventCount = 0, uniqueFiles = 0, promotedEventCount = 0, pathVariants = 0, observedRiskScore = 0, baseCorrelationScore = 0, baseCrossModuleScore = 0, eventRateScore = 0, fileCountScore = 0, tagCountScore = 0, reasonCountScore = 0 }) => {
      const trustTier = dominantTrustTier(trustTierCounts);
      const promotionSignals = deriveAggregatePromotionSignals({ tags, reasonBuckets, extensions, path, eventCount, uniqueFiles, promotedEventCount, pathVariants });
      const observedPriorityScore = Math.max(0, observedRiskScore) + Math.max(0, baseCorrelationScore) + Math.max(0, baseCrossModuleScore);
      if (trustTier.allowlist) {
        return {
          trustTier,
          promotionSignals,
          requiredSignalCount: Number.MAX_SAFE_INTEGER,
          highConfidence: false,
          confidence: "trusted",
          observedPriorityScore,
          priorityScore: Math.min(observedPriorityScore, 2),
        };
      }
      const gated = aggregateNeedsTwoSignals({ categoryKeys, reasonFamily, tags });
      const requiredSignalCount = gated ? 2 + (trustTier.key ? 1 : 0) : 1;
      const highConfidence = promotionSignals.length >= requiredSignalCount;
      const confidence = highConfidence
        ? (promotionSignals.length >= (requiredSignalCount + 1) || promotionSignals.includes("mft-corroboration") || promotionSignals.includes("persistence-path") ? "high" : "medium")
        : "observed";
      let priorityScore = observedPriorityScore;
      if (highConfidence) {
        priorityScore += eventRateScore + fileCountScore + tagCountScore + reasonCountScore + Math.min(4, promotionSignals.length - requiredSignalCount + 1);
      } else {
        priorityScore = Math.min(observedPriorityScore, gated ? 5 : 6);
      }
      return {
        trustTier,
        promotionSignals,
        requiredSignalCount,
        highConfidence,
        confidence,
        observedPriorityScore,
        priorityScore: Math.max(0, priorityScore),
      };
    };

    const result = { ...empty };

    try {
      // ── Q1: Rename Activity ──
      if (analyses.renames) {
        const renameRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name, ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons,
                 ${usnCol ? usnCol + " as usn" : "rowid as usn"}
          FROM data
          WHERE ${timeFilter}
            AND (${reasonCol} LIKE '%RenameOldName%' OR ${reasonCol} LIKE '%RenameNewName%')
            ${pathLike}
          ORDER BY ${entryCol}, CAST(${usnCol || "rowid"} AS INTEGER)
        `).all(...baseParams);

        const renameGroups = new Map();
        for (const row of renameRows) {
          const refKey = `${String(row.entryNumber || "")}:${String(row.sequenceNumber || "")}`;
          if (!renameGroups.has(refKey)) renameGroups.set(refKey, []);
          renameGroups.get(refKey).push(row);
        }
        const pairs = [];
        let unmatchedOldCount = 0;
        let unmatchedNewCount = 0;
        for (const rows of renameGroups.values()) {
          const pendingOlds = [];
          rows.sort((a, b) => {
            const au = Number(a.usn);
            const bu = Number(b.usn);
            if (Number.isFinite(au) && Number.isFinite(bu) && au !== bu) return au - bu;
            const at = parseTs(a.timestamp);
            const bt = parseTs(b.timestamp);
            if (Number.isFinite(at) && Number.isFinite(bt) && at !== bt) return at - bt;
            return String(a.name || "").localeCompare(String(b.name || ""));
          });
          rows.forEach((row, idx) => {
            const hasOld = /RenameOldName/i.test(row.reasons || "");
            const hasNew = /RenameNewName/i.test(row.reasons || "");
            if (hasOld) {
              pendingOlds.push({
                name: row.name,
                parentPath: row.parentPath || "",
                timestamp: row.timestamp,
                entryNumber: row.entryNumber,
                sequenceNumber: row.sequenceNumber || "",
                usn: row.usn,
                rowIndex: idx,
              });
            }
            if (hasNew) {
              let matchIdx = -1;
              for (let j = pendingOlds.length - 1; j >= 0; j--) {
                const cand = pendingOlds[j];
                if (cand.rowIndex === idx) continue;
                matchIdx = j;
                if ((cand.parentPath || "") === (row.parentPath || "")) break;
              }
              if (matchIdx >= 0) {
                const oldRow = pendingOlds.splice(matchIdx, 1)[0];
                pairs.push({
                  entryNumber: row.entryNumber,
                  sequenceNumber: row.sequenceNumber || oldRow.sequenceNumber || "",
                  timestamp: row.timestamp || oldRow.timestamp,
                  oldName: oldRow.name,
                  newName: row.name,
                  parentPath: row.parentPath || oldRow.parentPath || "",
                });
              } else {
                unmatchedNewCount += 1;
              }
            }
          });
          unmatchedOldCount += pendingOlds.length;
        }
        result.renames = {
          count: pairs.length,
          events: pairs.slice(0, 2000),
          unmatchedCount: unmatchedOldCount + unmatchedNewCount,
          unmatchedOldCount,
          unmatchedNewCount,
        };
      }

      // ── Q2: Deletion Activity ──
      if (analyses.deletions) {
        const deleteRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${attrsCol ? attrsCol + " as fileAttributes" : "'' as fileAttributes"}
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} LIKE '%FileDelete%'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 5000
        `).all(...baseParams);
        result.deletions = { count: deleteRows.length, events: deleteRows };
      }

      // ── Q3: File Creation ──
      if (analyses.creations) {
        const createRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} LIKE '%FileCreate%'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 5000
        `).all(...baseParams);
        result.creations = { count: createRows.length, events: createRows };
      }

      // ── Q4: Data Exfiltration Tracking ──
      if (analyses.exfil) {
        const archiveExts = [".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".bz2"];
        const extPlaceholders = archiveExts.map(() => "?").join(",");
        const archiveRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND (${reasonCol} LIKE '%FileCreate%' OR ${reasonCol} LIKE '%DataExtend%')
            AND LOWER(${extCol || "''"}) IN (${extPlaceholders})
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 1000
        `).all(...baseParams, ...archiveExts);

        // For each unique archive parent path, find child file activity
        const archiveDirs = [...new Set(archiveRows.map((r) => r.parentPath).filter(Boolean))];
        const dirActivity = [];
        for (const dir of archiveDirs.slice(0, 20)) {
          const childRows = db.prepare(`
            SELECT ${nameCol} as name, ${tsCol} as timestamp, ${reasonCol} as reasons
            FROM data
            WHERE ${timeFilter} AND ${parentPathCol} = ?
              AND ${reasonCol} LIKE '%FileCreate%' ${notDir}
            ORDER BY sort_datetime(${tsCol}) ASC
            LIMIT 100
          `).all(startTime, effectiveEnd, dir);
          dirActivity.push({ directory: dir, fileCount: childRows.length, files: childRows.slice(0, 50) });
        }
        result.exfil = { archiveCount: archiveRows.length, archives: archiveRows, stagingDirectories: dirActivity };
      }

      // ── Q5: Execution Artifacts ──
      if (analyses.execution) {
        const execExts = [".exe", ".dll", ".ps1", ".bat", ".vbs", ".cmd", ".js", ".hta", ".msi", ".scr"];
        const extPlaceholders = execExts.map(() => "?").join(",");
        const execRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND (${reasonCol} LIKE '%FileCreate%' OR ${reasonCol} LIKE '%DataOverwrite%' OR ${reasonCol} LIKE '%DataExtend%')
            AND LOWER(${extCol || "''"}) IN (${extPlaceholders})
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 3000
        `).all(...baseParams, ...execExts);

        const extBreakdown = {};
        for (const r of execRows) {
          const ext = (r.extension || "").toLowerCase();
          extBreakdown[ext] = (extBreakdown[ext] || 0) + 1;
        }
        result.execution = {
          count: execRows.length, events: execRows,
          extensionBreakdown: Object.entries(extBreakdown).map(([ext, count]) => ({ ext, count })).sort((a, b) => b.count - a.count),
        };
      }

      // ── Q6: Persistence Paths ──
      if (analyses.persistence && parentPathCol) {
        const persistPatterns = [
          "%\\Start Menu\\Programs\\Startup%",
          "%\\Windows\\System32\\Tasks%",
          "%\\Windows\\Tasks%",
          "%\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup%",
          "%\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown%",
          "%\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Logon%",
          "%\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Logoff%",
          "%\\Windows\\System32\\wbem\\mof%",
          "%\\Windows\\System32\\wbem\\AutoRecover%",
          "%\\Windows\\SysWOW64\\wbem\\mof%",
          "%\\Windows\\SysWOW64\\wbem\\AutoRecover%",
        ];
        const patternConditions = persistPatterns.map(() => `${parentPathCol} LIKE ?`).join(" OR ");
        const rawPersistRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol} as parentPath,
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND (${patternConditions})
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 3000
        `).all(startTime, effectiveEnd, ...persistPatterns, ...(normPath ? [`%${normPath}%`] : []));

        const persistRows = [];
        const suppressedRows = [];
        const categories = {};
        for (const r of rawPersistRows) {
          const classification = classifyPersistenceRow(r);
          if (!classification.include) {
            if (classification.suppressionReason && classification.suppressionReason !== "Outside persistence scope") {
              suppressedRows.push({ ...r, suppressionReason: classification.suppressionReason });
            }
            continue;
          }
          persistRows.push({
            ...r,
            heuristicCategory: classification.category,
            heuristicTags: classification.tags,
            heuristicRisk: classification.heuristicRisk,
          });
          categories[classification.category] = (categories[classification.category] || 0) + 1;
        }
        result.persistence = {
          count: persistRows.length, events: persistRows,
          categories: Object.entries(categories).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
          suppressedCount: suppressedRows.length,
          suppressedEvents: suppressedRows,
          suppressionSummary: summarizeUsnSuppressions(suppressedRows),
        };
      }

      // ── Q7: Suspicious Paths ──
      if (analyses.suspiciousPaths && parentPathCol) {
        const suspPatterns = [
          "%\\Temp\\%", "%\\Tmp\\%", "%\\PerfLogs\\%", "%\\Public\\%",
          "%$Recycle.Bin%", "%\\Windows\\Temp\\%", "%\\AppData\\Local\\Temp\\%",
          "%\\ProgramData\\%", "%\\Recovery\\%",
          "%\\Videos%", "%\\Music%", "%\\Pictures%",
        ];
        const patternConditions = suspPatterns.map(() => `${parentPathCol} LIKE ?`).join(" OR ");
        const rawSuspRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol} as parentPath,
                 ${tsCol} as timestamp, ${reasonCol} as reasons,
                 ${attrsCol ? attrsCol + " as fileAttributes" : "'' as fileAttributes"}
          FROM data
          WHERE ${timeFilter}
            AND (${patternConditions})
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 3000
        `).all(startTime, effectiveEnd, ...suspPatterns, ...(normPath ? [`%${normPath}%`] : []));

        const suspRows = [];
        const suppressedRows = [];
        const dirCounts = {};
        const categories = {};
        for (const r of rawSuspRows) {
          const classification = classifySuspiciousPathRow(r);
          if (!classification.include) {
            if (classification.suppressionReason && classification.suppressionReason !== "Outside suspicious path scope") {
              suppressedRows.push({ ...r, suppressionReason: classification.suppressionReason });
            }
            continue;
          }
          const enriched = {
            ...r,
            heuristicCategory: classification.category,
            heuristicTags: classification.tags,
            heuristicRisk: classification.heuristicRisk,
          };
          suspRows.push(enriched);
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
          categories[classification.category] = (categories[classification.category] || 0) + 1;
        }
        result.suspiciousPaths = {
          count: suspRows.length, events: suspRows,
          categories: Object.entries(categories).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
          directoryBreakdown: Object.entries(dirCounts).map(([path, count]) => ({ path, count })).sort((a, b) => b.count - a.count).slice(0, 30),
          suppressedCount: suppressedRows.length,
          suppressedEvents: suppressedRows,
          suppressionSummary: summarizeUsnSuppressions(suppressedRows),
        };
      }

      // ── Q8: Security Changes ──
      if (analyses.securityChanges) {
        const secRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons,
                 ${attrsCol ? attrsCol + " as fileAttributes" : "'' as fileAttributes"}
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} LIKE '%SecurityChange%'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 3000
        `).all(...baseParams);

        // Group by directory to find bulk permission changes (TA staging indicator)
        const dirCounts = {};
        const dirFiles = {};
        for (const r of secRows) {
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
          if (!dirFiles[pp]) dirFiles[pp] = new Set();
          dirFiles[pp].add(r.name);
        }
        const directoryBreakdown = Object.entries(dirCounts)
          .map(([path, count]) => ({ path, count, uniqueFiles: dirFiles[path]?.size || 0 }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 30);

        result.securityChanges = {
          count: secRows.length, events: secRows,
          directoryBreakdown,
          hotspotCount: directoryBreakdown.filter((d) => d.uniqueFiles >= 5).length,
        };
      }

      // ── Q9: Data Overwrite (ransomware / wiper indicator) ──
      if (analyses.dataOverwrite) {
        const owRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND (${reasonCol} LIKE '%DataOverwrite%' OR ${reasonCol} LIKE '%DataExtend%')
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 3000
        `).all(...baseParams);

        // Group by extension to detect mass-overwrite patterns
        const extCounts = {};
        const dirCounts = {};
        for (const r of owRows) {
          const ext = (r.extension || "(none)").toLowerCase();
          extCounts[ext] = (extCounts[ext] || 0) + 1;
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
        }
        result.dataOverwrite = {
          count: owRows.length, events: owRows,
          extensionBreakdown: Object.entries(extCounts).map(([ext, count]) => ({ ext, count })).sort((a, b) => b.count - a.count).slice(0, 20),
          directoryBreakdown: Object.entries(dirCounts).map(([path, count]) => ({ path, count })).sort((a, b) => b.count - a.count).slice(0, 20),
        };
      }

      // ── Q10: Stream Changes (ADS modifications) ──
      if (analyses.streamChanges) {
        const stRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} LIKE '%StreamChange%'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 2000
        `).all(...baseParams);

        const dirCounts = {};
        for (const r of stRows) {
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
        }
        result.streamChanges = {
          count: stRows.length, events: stRows,
          directoryBreakdown: Object.entries(dirCounts).map(([path, count]) => ({ path, count })).sort((a, b) => b.count - a.count).slice(0, 20),
        };
      }

      // ── Q11: Close-only Patterns (bulk enumeration / recon fingerprinting) ──
      if (analyses.closePatterns) {
        const clRows = db.prepare(`
          SELECT ${entryCol} as entryNumber, ${seqCol ? seqCol + " as sequenceNumber" : "'' as sequenceNumber"},
                 ${nameCol} as name,
                 ${extCol ? extCol + " as extension" : "'' as extension"},
                 ${parentPathCol ? parentPathCol + " as parentPath" : "'' as parentPath"},
                 ${tsCol} as timestamp, ${reasonCol} as reasons
          FROM data
          WHERE ${timeFilter}
            AND ${reasonCol} = 'Close'
            ${notDir}
            ${pathLike}
          ORDER BY sort_datetime(${tsCol}) ASC
          LIMIT 3000
        `).all(...baseParams);

        // Directories with high close-only counts = recon/enumeration
        const dirCounts = {};
        for (const r of clRows) {
          const pp = r.parentPath || "(unknown)";
          dirCounts[pp] = (dirCounts[pp] || 0) + 1;
        }
        const directoryBreakdown = Object.entries(dirCounts)
          .map(([path, count]) => ({ path, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 30);

        result.closePatterns = {
          count: clRows.length, events: clRows,
          directoryBreakdown,
          hotspotCount: directoryBreakdown.filter((d) => d.count >= 10).length,
        };
      }

      // ── Summary (always) ──
      const totalEvents = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${timeFilter} ${pathLike}`).get(...baseParams)?.cnt || 0;
      result.summary = { totalEvents, startTime, endTime, pathFilter: pathFilter || null };

      // ── MFT Cross-Artifact Correlation ──
      if (mftTabId) {
        const mftMeta = this.databases.get(mftTabId);
        if (mftMeta) {
          try {
            const mftDb = mftMeta.db;
            const mc = (name) => mftMeta.colMap[name];
            const mEntry = mc("EntryNumber"), mSeq = mc("SequenceNumber"), mName = mc("FileName"), mSize = mc("FileSize");
            const mInUse = mc("InUse"), mSiFn = mc("SI<FN"), mFlags = mc("SiFlags");
            const mZone = mc("ZoneIdContents"), mCreated = mc("Created0x10");
            const mPath = mc("ParentPath"), mIsDir = mc("IsDirectory"), mExt = mc("Extension");

            if (mEntry) {
              const categories = ["renames", "deletions", "creations", "exfil", "execution",
                "persistence", "suspiciousPaths", "securityChanges", "dataOverwrite", "streamChanges", "closePatterns"];
              const entryNums = new Set();
              const refMap = new Map();
              const normalizeRef = (entryNumber, sequenceNumber) => {
                const entryStr = entryNumber != null ? String(entryNumber) : "";
                if (!entryStr) return null;
                const seqStr = sequenceNumber != null ? String(sequenceNumber).trim() : "";
                return { entry: entryStr, sequence: seqStr, hasSequence: seqStr !== "" };
              };

              // Collect all unique file references from results
              const registerRef = (ev) => {
                const ref = normalizeRef(ev?.entryNumber, ev?.sequenceNumber);
                if (!ref) return;
                entryNums.add(ref.entry);
                const key = ref.hasSequence ? `${ref.entry}:${ref.sequence}` : `${ref.entry}:`;
                if (!refMap.has(key)) refMap.set(key, ref);
              };

              for (const cat of categories) {
                const sData = result[cat];
                if (!sData) continue;
                const events = cat === "exfil" ? sData.archives : sData.events;
                if (events) for (const ev of events) registerRef(ev);
              }

              const preferMftRow = (current, candidate) => {
                if (!current) return candidate;
                if (candidate.inUse === "True" && current.inUse !== "True") return candidate;
                if (candidate.isDir !== "True" && current.isDir === "True") return candidate;
                if (candidate.zoneId && !current.zoneId) return candidate;
                return current;
              };

              // Query MFT for those entries
              if (entryNums.size > 0) {
                const mftByEntry = new Map();
                const mftByEntrySeq = new Map();

                // Query in batches of 500 to avoid SQL variable limits
                const entryArr = [...entryNums];
                for (let i = 0; i < entryArr.length; i += 500) {
                  const batch = entryArr.slice(i, i + 500);
                  const placeholders = batch.map(() => "?").join(",");
                  const selectCols = [
                    `${mEntry} as entryNumber`,
                    mSeq ? `${mSeq} as sequenceNumber` : "'' as sequenceNumber",
                    mName ? `${mName} as fileName` : "'' as fileName",
                    mSize ? `${mSize} as fileSize` : "'' as fileSize",
                    mInUse ? `${mInUse} as inUse` : "'' as inUse",
                    mSiFn ? `${mSiFn} as siFn` : "'' as siFn",
                    mFlags ? `${mFlags} as siFlags` : "'' as siFlags",
                    mZone ? `${mZone} as zoneId` : "'' as zoneId",
                    mCreated ? `${mCreated} as created` : "'' as created",
                    mPath ? `${mPath} as parentPath` : "'' as parentPath",
                    mIsDir ? `${mIsDir} as isDir` : "'' as isDir",
                    mExt ? `${mExt} as extension` : "'' as extension",
                  ].join(", ");
                  const rows = mftDb.prepare(
                    `SELECT ${selectCols} FROM data WHERE ${mEntry} IN (${placeholders})`
                  ).all(...batch);
                  for (const r of rows) {
                    const entryKey = String(r.entryNumber);
                    const seqKey = r.sequenceNumber != null && String(r.sequenceNumber).trim() !== ""
                      ? `${entryKey}:${String(r.sequenceNumber).trim()}`
                      : null;
                    mftByEntry.set(entryKey, preferMftRow(mftByEntry.get(entryKey), r));
                    if (seqKey) {
                      mftByEntrySeq.set(seqKey, preferMftRow(mftByEntrySeq.get(seqKey), r));
                    }
                  }
                }

                const matchedRefs = new Set();
                const exactMatchedRefs = new Set();
                const fallbackMatchedRefs = new Set();
                const matchedArtifacts = new Map();
                const findMftMatch = (ev) => {
                  const ref = normalizeRef(ev?.entryNumber, ev?.sequenceNumber);
                  if (!ref) return { row: null, mode: null, refKey: null };
                  const refKey = ref.hasSequence ? `${ref.entry}:${ref.sequence}` : `${ref.entry}:`;
                  if (ref.hasSequence && mSeq) {
                    const exact = mftByEntrySeq.get(`${ref.entry}:${ref.sequence}`);
                    return { row: exact || null, mode: exact ? "exact" : null, refKey };
                  }
                  const fallback = mftByEntry.get(ref.entry);
                  return { row: fallback || null, mode: fallback ? "entry-only" : null, refKey };
                };

                // Enrich events with MFT data
                for (const cat of categories) {
                  const sData = result[cat];
                  if (!sData) continue;
                  const events = cat === "exfil" ? sData.archives : sData.events;
                  if (events) for (const ev of events) {
                    const match = findMftMatch(ev);
                    const mft = match.row;
                    if (!mft) continue;
                    matchedRefs.add(match.refKey);
                    if (match.mode === "exact") exactMatchedRefs.add(match.refKey);
                    if (match.mode === "entry-only") fallbackMatchedRefs.add(match.refKey);
                    matchedArtifacts.set(match.mode === "exact"
                      ? `${String(mft.entryNumber)}:${String(mft.sequenceNumber).trim()}`
                      : `${String(mft.entryNumber)}:`, mft);
                    ev._mft = {
                      fileSize: mft.fileSize || "",
                      inUse: mft.inUse || "",
                      siFn: mft.siFn || "",
                      siFlags: mft.siFlags || "",
                      zoneId: mft.zoneId || "",
                      created: mft.created || "",
                      mftPath: mft.parentPath || "",
                      sequenceNumber: mft.sequenceNumber != null ? String(mft.sequenceNumber) : "",
                      matchMode: match.mode,
                    };
                  }
                }

                // Build correlation summary
                const matchedRows = [...matchedArtifacts.values()];
                result.correlation = {
                  mftTabId,
                  totalUsnEntries: refMap.size,
                  matched: matchedRefs.size,
                  unmatched: Math.max(0, refMap.size - matchedRefs.size),
                  exactMatched: exactMatchedRefs.size,
                  fallbackMatched: fallbackMatchedRefs.size,
                  deleted: matchedRows.filter((r) => r.inUse === "False").length,
                  timestomped: matchedRows.filter((r) => r.siFn === "True").length,
                  downloaded: matchedRows.filter((r) => r.zoneId && r.zoneId.trim()).length,
                };
              }
            }
          } catch (mftErr) {
            result.correlationError = mftErr.message;
          }
        }
      }

      // ── Post-processing: normalized suspicious storyline, file chains, directory incidents ──
      const categoryMeta = {
        renames: "Rename Activity",
        deletions: "Deletion Activity",
        creations: "File Creation",
        exfil: "Data Exfiltration",
        execution: "Execution Artifacts",
        persistence: "Persistence Paths",
        suspiciousPaths: "Suspicious Paths",
        securityChanges: "Security Changes",
        dataOverwrite: "Data Overwrite",
        streamChanges: "Stream Changes",
        closePatterns: "Close Patterns",
      };
      const allEvents = [];
      const addEvent = (secKey, ev, extra = {}) => {
        if (!ev) return;
        const name = extra.name || ev.name || ev.newName || ev.oldName || "";
        const parentPath = extra.parentPath ?? ev.parentPath ?? "";
        const extension = deriveExtension(name, extra.extension ?? ev.extension ?? "");
        const rawReasons = extra.rawReasons ?? ev.reasons ?? "";
        const reasonBuckets = normalizeUsnReasons(rawReasons, secKey);
        const tags = [];
        if (ev._mft?.zoneId?.trim()) tags.push("downloaded");
        if (ev._mft?.siFn === "True") tags.push("timestomp");
        if (ev._mft?.inUse === "False") tags.push("deleted-in-mft");
        if (secKey === "persistence") tags.push("persistence-related");
        if (secKey === "execution") tags.push("executable-or-script");
        if (secKey === "exfil") tags.push("archive-staging");
        for (const tag of ev.heuristicTags || []) {
          if (!tags.includes(tag)) tags.push(tag);
        }
        const normalized = {
          id: `${secKey}:${ev.entryNumber || ""}:${ev.sequenceNumber || ""}:${ev.timestamp || ""}:${ev.usn || ""}:${extra.kind || ""}:${name}`,
          category: secKey,
          categoryLabel: categoryMeta[secKey] || secKey,
          timestamp: ev.timestamp || "",
          tsMs: parseTs(ev.timestamp),
          entryNumber: ev.entryNumber != null ? String(ev.entryNumber) : "",
          sequenceNumber: ev.sequenceNumber != null ? String(ev.sequenceNumber) : "",
          name,
          oldName: ev.oldName || "",
          newName: ev.newName || "",
          parentPath,
          fullPath: joinPath(parentPath, name),
          extension,
          rawReasons,
          reasonBuckets,
          primaryReason: primaryReasonBucket(reasonBuckets),
          reasonLabel: REASON_LABELS[primaryReasonBucket(reasonBuckets)] || "Activity",
          tags,
          heuristicRisk: Number(ev.heuristicRisk || 0),
          heuristicCategory: ev.heuristicCategory || "",
          _mft: ev._mft || null,
          _src: ev,
        };
        normalized.observedScore = scoreUsnObservedEvent(normalized);
        normalized.riskScore = normalized.observedScore;
        normalized.trustTier = { key: "", label: "", dampening: 0 };
        normalized.promotionSignals = [];
        normalized.requiredSignalCount = 1;
        normalized.promotionEligible = false;
        normalized.confidence = "observed";
        allEvents.push(normalized);
      };
      for (const [secKey, secLabel] of Object.entries(categoryMeta)) {
        const sec = result[secKey];
        if (!sec) continue;
        const sourceEvents = secKey === "exfil" ? sec.archives : sec.events;
        if (!Array.isArray(sourceEvents)) continue;
        if (secKey === "renames") {
          for (const ev of sourceEvents) {
            addEvent(secKey, ev, {
              name: ev.newName || ev.oldName || "",
              rawReasons: "RenameOldName|RenameNewName",
              kind: "rename-pair",
            });
          }
        } else {
          for (const ev of sourceEvents) addEvent(secKey, ev);
        }
      }
      allEvents.sort((a, b) => (a.tsMs || 0) - (b.tsMs || 0));

      const outlierHeavyCategories = new Set(["execution", "persistence", "suspiciousPaths", "exfil"]);
      const dirEventCounts = new Map();
      const extEventCounts = new Map();
      const reasonSigCounts = new Map();
      for (const ev of allEvents) {
        const dirKey = ev.parentPath || "(unknown)";
        dirEventCounts.set(dirKey, (dirEventCounts.get(dirKey) || 0) + 1);
        if (ev.extension) extEventCounts.set(ev.extension, (extEventCounts.get(ev.extension) || 0) + 1);
        const reasonSig = [...(ev.reasonBuckets || [])].sort().join("|");
        if (reasonSig) reasonSigCounts.set(reasonSig, (reasonSigCounts.get(reasonSig) || 0) + 1);
      }
      for (const ev of allEvents) {
        const outlierTags = [];
        const dirCount = dirEventCounts.get(ev.parentPath || "(unknown)") || 0;
        const extCount = ev.extension ? (extEventCounts.get(ev.extension) || 0) : 0;
        const reasonSig = [...(ev.reasonBuckets || [])].sort().join("|");
        const reasonSigCount = reasonSig ? (reasonSigCounts.get(reasonSig) || 0) : 0;
        if (ev.parentPath && ev.parentPath !== "(unknown)" && dirCount <= 2 && (outlierHeavyCategories.has(ev.category) || EXT_RISK.has(ev.extension))) {
          outlierTags.push("rare-directory");
        }
        if (ev.extension && extCount > 0 && extCount <= 2 && (EXT_RISK.has(ev.extension) || outlierHeavyCategories.has(ev.category))) {
          outlierTags.push("rare-extension");
        }
        if (reasonSig && reasonSigCount <= 2 && (ev.reasonBuckets.length > 1 || DESTRUCTIVE_REASON_BUCKETS.has(ev.primaryReason) || outlierHeavyCategories.has(ev.category))) {
          outlierTags.push("rare-reason-mix");
        }
        ev.outlierTags = outlierTags;
        outlierTags.forEach((tag) => {
          if (!ev.tags.includes(tag)) ev.tags.push(tag);
        });
        Object.assign(ev, evaluateUsnEvent(ev));
      }

      const fileChainMap = new Map();
      for (const ev of allEvents) {
        const key = ev.entryNumber || `${ev.parentPath}|${ev.name}`;
        if (!fileChainMap.has(key)) {
          fileChainMap.set(key, {
            key,
            entryNumber: ev.entryNumber || "",
            firstSeen: ev.timestamp || "",
            lastSeen: ev.timestamp || "",
            firstTsMs: ev.tsMs,
            lastTsMs: ev.tsMs,
            eventCount: 0,
            paths: new Set(),
            names: new Set(),
            reasonBuckets: new Set(),
            categories: new Set(),
            categoryKeys: new Set(),
            extensions: new Set(),
            tags: new Set(),
            promotionSignals: new Set(),
            trustTierCounts: new Map(),
            parentCounts: new Map(),
            fullPathCounts: new Map(),
            renamePairs: [],
            events: [],
            riskScore: 0,
            observedRiskScore: 0,
            promotedEventCount: 0,
          });
        }
        const chain = fileChainMap.get(key);
        chain.eventCount += 1;
        chain.firstTsMs = Math.min(chain.firstTsMs || ev.tsMs || Infinity, ev.tsMs || Infinity);
        chain.lastTsMs = Math.max(chain.lastTsMs || 0, ev.tsMs || 0);
        chain.firstSeen = chain.firstTsMs === ev.tsMs ? ev.timestamp : chain.firstSeen;
        chain.lastSeen = chain.lastTsMs === ev.tsMs ? ev.timestamp : chain.lastSeen;
        if (ev.fullPath) chain.paths.add(ev.fullPath);
        if (ev.fullPath) chain.fullPathCounts.set(ev.fullPath, (chain.fullPathCounts.get(ev.fullPath) || 0) + 1);
        if (ev.name) chain.names.add(ev.name);
        if (ev.extension) chain.extensions.add(ev.extension);
        if (ev.parentPath) chain.parentCounts.set(ev.parentPath, (chain.parentCounts.get(ev.parentPath) || 0) + 1);
        chain.reasonBuckets.add(ev.primaryReason);
        chain.categories.add(ev.categoryLabel);
        chain.categoryKeys.add(ev.category);
        ev.tags.forEach((t) => chain.tags.add(t));
        (ev.promotionSignals || []).forEach((sig) => chain.promotionSignals.add(sig));
        if (ev.trustTier?.key) chain.trustTierCounts.set(ev.trustTier.key, (chain.trustTierCounts.get(ev.trustTier.key) || 0) + 1);
        chain.riskScore = Math.max(chain.riskScore, ev.riskScore || 0);
        chain.observedRiskScore = Math.max(chain.observedRiskScore, ev.observedScore || ev.riskScore || 0);
        if (ev.promotionEligible) chain.promotedEventCount += 1;
        if (ev.oldName || ev.newName) chain.renamePairs.push({ oldName: ev.oldName, newName: ev.newName, timestamp: ev.timestamp, parentPath: ev.parentPath });
        if (chain.events.length < 200) chain.events.push(ev);
      }
      result.fileChains = [...fileChainMap.values()].map((ch) => {
        const correlationScore = [...ch.tags].reduce((sum, t) => sum + correlationWeight(t), 0);
        const crossModuleScore = crossModuleSynergyScore(ch.tags);
        const primaryDirectory = [...ch.parentCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "";
        const primaryPath = [...ch.fullPathCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || [...ch.paths][0] || "";
        const pathTransitions = [...new Set((ch.events || []).map((ev) => ev.fullPath).filter(Boolean))];
        const aggregateEval = evaluateAggregateConfidence({
          tags: [...ch.tags],
          categoryKeys: [...ch.categoryKeys],
          reasonBuckets: [...ch.reasonBuckets],
          path: primaryDirectory || primaryPath,
          extensions: [...ch.extensions],
          eventCount: ch.eventCount,
          uniqueFiles: ch.names.size || ch.paths.size || ch.eventCount,
          promotedEventCount: ch.promotedEventCount,
          pathVariants: pathTransitions.length,
          trustTierCounts: ch.trustTierCounts,
          observedRiskScore: ch.observedRiskScore,
          baseCorrelationScore: correlationScore,
          baseCrossModuleScore: crossModuleScore,
          eventRateScore: Math.min(4, ch.eventCount >= 10 ? 4 : Math.floor(ch.eventCount / 3)),
          fileCountScore: Math.min(3, ch.reasonBuckets.size),
        });
        return {
          key: ch.key,
          entryNumber: ch.entryNumber,
          title: [...ch.names][0] || [...ch.paths][0] || "(unknown)",
          firstSeen: ch.firstSeen,
          lastSeen: ch.lastSeen,
          durationMs: Math.max(0, (ch.lastTsMs || 0) - (ch.firstTsMs || 0)),
          eventCount: ch.eventCount,
          paths: [...ch.paths],
          categories: [...ch.categories],
          categoryKeys: [...ch.categoryKeys],
          reasonBuckets: [...ch.reasonBuckets],
          tags: [...ch.tags],
          correlationTags: [...ch.tags].map((t) => ({ key: t, label: correlationLabelMap[t] || t })),
          renamePairs: ch.renamePairs,
          riskScore: ch.riskScore,
          observedRiskScore: ch.observedRiskScore,
          correlationScore,
          crossModuleScore,
          priorityScore: aggregateEval.priorityScore,
          observedPriorityScore: aggregateEval.observedPriorityScore,
          promotionSignals: aggregateEval.promotionSignals,
          requiredSignalCount: aggregateEval.requiredSignalCount,
          promotedEventCount: ch.promotedEventCount,
          highConfidence: aggregateEval.highConfidence,
          confidence: aggregateEval.confidence,
          trustTier: aggregateEval.trustTier,
          primaryDirectory,
          primaryPath,
          events: ch.events.sort((a, b) => (a.tsMs || 0) - (b.tsMs || 0)),
          extensions: [...ch.extensions],
          pathTransitions,
        };
      }).sort((a, b) => (b.priorityScore - a.priorityScore) || (b.riskScore - a.riskScore) || (b.eventCount - a.eventCount) || a.firstSeen.localeCompare(b.firstSeen));

      const chainsByDirectory = new Map();
      for (const ch of result.fileChains) {
        if (!ch.primaryDirectory) continue;
        if (!chainsByDirectory.has(ch.primaryDirectory)) chainsByDirectory.set(ch.primaryDirectory, []);
        chainsByDirectory.get(ch.primaryDirectory).push(ch);
      }
      result.fileChains = result.fileChains.map((ch) => {
        const peers = chainsByDirectory.get(ch.primaryDirectory) || [];
        const siblingArtifacts = peers
          .filter((p) => p.key !== ch.key)
          .sort((a, b) => b.priorityScore - a.priorityScore)
          .slice(0, 5)
          .map((p) => ({
            key: p.key,
            title: p.title,
            eventCount: p.eventCount,
            priorityScore: p.priorityScore,
            tags: p.tags,
          }));
        return {
          ...ch,
          sameDirectoryChainCount: Math.max(0, peers.length - 1),
          siblingArtifacts,
        };
      });

      const DIR_GAP_MS = 5 * 60 * 1000;
      const incidentMap = new Map();
      for (const ev of allEvents) {
        const baseKey = `${ev.parentPath || "(unknown)"}|${bucketForDirectory(ev)}`;
        if (!incidentMap.has(baseKey)) incidentMap.set(baseKey, []);
        const windows = incidentMap.get(baseKey);
        const last = windows[windows.length - 1];
        if (!last || !Number.isFinite(ev.tsMs) || !Number.isFinite(last.lastTsMs) || ev.tsMs - last.lastTsMs > DIR_GAP_MS) {
          windows.push({
            key: `${baseKey}|w${windows.length}`,
            path: ev.parentPath || "(unknown)",
            bucket: bucketForDirectory(ev),
            start: ev.timestamp,
            end: ev.timestamp,
            startTsMs: ev.tsMs,
            lastTsMs: ev.tsMs,
            eventCount: 0,
            files: new Set(),
            reasons: new Set(),
            categories: new Set(),
            categoryKeys: new Set(),
            tags: new Set(),
            promotionSignals: new Set(),
            trustTierCounts: new Map(),
            extensions: new Map(),
            events: [],
            riskScore: 0,
            observedRiskScore: 0,
            promotedEventCount: 0,
          });
        }
        const cur = windows[windows.length - 1];
        cur.eventCount += 1;
        cur.lastTsMs = Math.max(cur.lastTsMs || 0, ev.tsMs || 0);
        cur.end = cur.lastTsMs === ev.tsMs ? ev.timestamp : cur.end;
        if (ev.name) cur.files.add(ev.name);
        cur.reasons.add(ev.reasonLabel);
        cur.categories.add(ev.categoryLabel);
        cur.categoryKeys.add(ev.category);
        ev.tags.forEach((t) => cur.tags.add(t));
        (ev.promotionSignals || []).forEach((sig) => cur.promotionSignals.add(sig));
        if (ev.trustTier?.key) cur.trustTierCounts.set(ev.trustTier.key, (cur.trustTierCounts.get(ev.trustTier.key) || 0) + 1);
        if (ev.extension) cur.extensions.set(ev.extension, (cur.extensions.get(ev.extension) || 0) + 1);
        cur.riskScore = Math.max(cur.riskScore, ev.riskScore || 0);
        cur.observedRiskScore = Math.max(cur.observedRiskScore, ev.observedScore || ev.riskScore || 0);
        if (ev.promotionEligible) cur.promotedEventCount += 1;
        if (cur.events.length < 150) cur.events.push(ev);
      }
      for (const windows of incidentMap.values()) {
        const avgCount = windows.length > 0 ? (windows.reduce((sum, w) => sum + (w.eventCount || 0), 0) / windows.length) : 0;
        for (const win of windows) {
          const peers = windows.filter((other) => other !== win);
          const peerAvg = peers.length > 0 ? (peers.reduce((sum, other) => sum + (other.eventCount || 0), 0) / peers.length) : 0;
          win.localBaselineAvg = avgCount;
          win.localPeerAvg = peerAvg;
          win.localWindowCount = windows.length;
        }
      }
      result.directoryIncidents = [...incidentMap.values()].flat().map((inc) => {
        const durationMin = Math.max(1 / 60, ((inc.lastTsMs || 0) - (inc.startTsMs || 0)) / 60000);
        const eventsPerMinute = inc.eventCount / durationMin;
        const topExtensions = [...inc.extensions.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ext, count]) => ({ ext, count }));
        if (inc.bucket === "acl-change" && inc.files.size >= 5) inc.tags.add("acl-change-burst");
        if (inc.bucket === "overwrite" && inc.files.size >= 5) inc.tags.add("overwrite-burst");
        if (inc.bucket === "rename" && inc.files.size >= 3) inc.tags.add("rename-burst");
        if (inc.bucket === "stream-change") inc.tags.add("stream-activity");
        if ((inc.localWindowCount || 0) > 1) {
          if (inc.eventCount >= Math.max(5, Math.ceil((inc.localPeerAvg || inc.localBaselineAvg || 0) * 2))) inc.tags.add("local-burst");
        } else if (inc.eventCount >= 8 && eventsPerMinute >= 2) {
          inc.tags.add("local-burst");
        }
        const correlationScore = [...inc.tags].reduce((sum, t) => sum + correlationWeight(t), 0);
        const crossModuleScore = crossModuleSynergyScore(inc.tags);
        const aggregateEval = evaluateAggregateConfidence({
          tags: [...inc.tags],
          categoryKeys: [...inc.categoryKeys],
          reasonFamily: inc.bucket,
          reasonBuckets: [inc.bucket],
          path: inc.path,
          extensions: topExtensions.map((item) => item.ext),
          eventCount: inc.eventCount,
          uniqueFiles: inc.files.size,
          promotedEventCount: inc.promotedEventCount,
          trustTierCounts: inc.trustTierCounts,
          observedRiskScore: inc.observedRiskScore,
          baseCorrelationScore: correlationScore,
          baseCrossModuleScore: crossModuleScore,
          eventRateScore: Math.min(5, Math.round(eventsPerMinute)),
          fileCountScore: Math.min(4, inc.files.size >= 10 ? 4 : Math.floor(inc.files.size / 3)),
          tagCountScore: Math.min(3, inc.tags.size),
        });
        return {
          key: inc.key,
          title: makeIncidentTitle(inc.bucket, inc.path),
          path: inc.path,
          reasonFamily: inc.bucket,
          start: inc.start,
          end: inc.end,
          eventCount: inc.eventCount,
          uniqueFiles: inc.files.size,
          eventsPerMinute: Number(eventsPerMinute.toFixed(1)),
          categories: [...inc.categories],
          categoryKeys: [...inc.categoryKeys],
          reasons: [...inc.reasons],
          tags: [...inc.tags],
          correlationTags: [...inc.tags].map((t) => ({ key: t, label: correlationLabelMap[t] || t })),
          topExtensions,
          riskScore: inc.riskScore,
          observedRiskScore: inc.observedRiskScore,
          correlationScore,
          crossModuleScore,
          priorityScore: aggregateEval.priorityScore,
          observedPriorityScore: aggregateEval.observedPriorityScore,
          promotionSignals: aggregateEval.promotionSignals,
          requiredSignalCount: aggregateEval.requiredSignalCount,
          promotedEventCount: inc.promotedEventCount,
          highConfidence: aggregateEval.highConfidence,
          confidence: aggregateEval.confidence,
          trustTier: aggregateEval.trustTier,
          events: inc.events.sort((a, b) => (a.tsMs || 0) - (b.tsMs || 0)),
        };
      }).sort((a, b) => (b.priorityScore - a.priorityScore) || (b.eventCount - a.eventCount));

      result.timeline = allEvents.slice(0, 5000).map((ev) => ({
        key: ev.id,
        category: ev.category,
        categoryLabel: ev.categoryLabel,
        timestamp: ev.timestamp,
        entryNumber: ev.entryNumber,
        name: ev.name,
        displayName: ev.oldName && ev.newName ? `${ev.oldName} → ${ev.newName}` : ev.name,
        parentPath: ev.parentPath,
        fullPath: ev.fullPath,
        reasonLabel: ev.reasonLabel,
        reasonBuckets: ev.reasonBuckets,
        rawReasons: ev.rawReasons,
        tags: ev.tags,
        correlationTags: ev.tags.map((t) => ({ key: t, label: correlationLabelMap[t] || t })),
        riskScore: ev.riskScore,
        observedScore: ev.observedScore,
        promotionEligible: ev.promotionEligible,
        confidence: ev.confidence,
        trustTier: ev.trustTier,
        correlationScore: (ev.tags || []).reduce((sum, t) => sum + correlationWeight(t), 0),
        crossModuleScore: crossModuleSynergyScore(ev.tags || []),
      }));

      const correlationCounts = {};
      for (const ev of allEvents) {
        for (const t of ev.tags || []) correlationCounts[t] = (correlationCounts[t] || 0) + 1;
      }
      result.correlationSummary = Object.entries(correlationCounts)
        .map(([key, count]) => ({ key, label: correlationLabelMap[key] || key, count }))
        .sort((a, b) => b.count - a.count);

      result.sectionStats = {};
      for (const [secKey, secLabel] of Object.entries(categoryMeta)) {
        const secEvents = allEvents.filter((ev) => ev.category === secKey);
        if (secEvents.length === 0) continue;
        const highConfidenceEvents = secEvents.filter((ev) => ev.promotionEligible);
        const uniqueFiles = new Set(secEvents.map((ev) => ev.entryNumber || ev.fullPath || `${ev.parentPath}|${ev.name}`));
        const uniqueDirs = new Set(secEvents.map((ev) => ev.parentPath || "(unknown)"));
        const dirCounts = new Map();
        const reasonCounts = new Map();
        const extCounts = new Map();
        let firstTsMs = Infinity;
        let lastTsMs = 0;
        let maxRisk = 0;
        let maxObservedRisk = 0;
        let corrScore = 0;
        for (const ev of secEvents) {
          const dir = ev.parentPath || "(unknown)";
          dirCounts.set(dir, (dirCounts.get(dir) || 0) + 1);
          reasonCounts.set(ev.reasonLabel, (reasonCounts.get(ev.reasonLabel) || 0) + 1);
          if (ev.extension) extCounts.set(ev.extension, (extCounts.get(ev.extension) || 0) + 1);
          firstTsMs = Math.min(firstTsMs, ev.tsMs || Infinity);
          lastTsMs = Math.max(lastTsMs, ev.tsMs || 0);
          maxRisk = Math.max(maxRisk, ev.riskScore || 0);
          maxObservedRisk = Math.max(maxObservedRisk, ev.observedScore || ev.riskScore || 0);
          corrScore = Math.max(corrScore, (ev.tags || []).reduce((sum, t) => sum + correlationWeight(t), 0) + crossModuleSynergyScore(ev.tags || []));
        }
        const durationMin = Math.max(1 / 60, (lastTsMs - firstTsMs) / 60000 || 1 / 60);
        const eventsPerMinute = secEvents.length / durationMin;
        const topDirectory = [...dirCounts.entries()].sort((a, b) => b[1] - a[1])[0] || ["(unknown)", 0];
        const topReasons = [...reasonCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([label, count]) => ({ label, count }));
        const topExtensions = [...extCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([ext, count]) => ({ ext, count }));
        const sectionIncidents = result.directoryIncidents.filter((inc) => (inc.categories || []).includes(secLabel));
        const strongestIncident = sectionIncidents.sort((a, b) => b.priorityScore - a.priorityScore)[0] || null;
        const corroboratedPriority = Math.max(
          maxRisk + corrScore + Math.min(4, Math.round(eventsPerMinute)) + Math.min(4, Math.floor(uniqueFiles.size / 3)),
          strongestIncident?.priorityScore || 0
        );
        const observedPriority = Math.max(maxObservedRisk + Math.min(2, Math.round(eventsPerMinute)), strongestIncident?.observedPriorityScore || 0);
        const priorityScore = highConfidenceEvents.length > 0 || strongestIncident?.highConfidence ? corroboratedPriority : Math.min(observedPriority, 5);
        const severity = (highConfidenceEvents.length > 0 || strongestIncident?.highConfidence)
          ? (priorityScore >= 10 ? "high" : priorityScore >= 6 ? "medium" : "low")
          : (secEvents.length > 0 ? "low" : "low");
        result.sectionStats[secKey] = {
          key: secKey,
          label: secLabel,
          severity,
          priorityScore,
          observedPriorityScore: observedPriority,
          eventCount: secEvents.length,
          highConfidenceCount: highConfidenceEvents.length,
          uniqueFiles: uniqueFiles.size,
          uniqueDirs: uniqueDirs.size,
          eventsPerMinute: Number(eventsPerMinute.toFixed(1)),
          topDirectory: { path: topDirectory[0], count: topDirectory[1] },
          topReasons,
          topExtensions,
          strongestIncidentKey: strongestIncident?.key || "",
        };
      }

      const incidentFindings = result.directoryIncidents.filter((inc) => inc.highConfidence).slice(0, 4).map((inc) => {
        const durationMin = findingDurationMinutes(inc.start, inc.end);
        const entryNumber = inc.events?.find((ev) => ev.entryNumber)?.entryNumber;
        return {
          key: `incident:${inc.key}`,
          sourceType: "directoryIncident",
          sourceKey: inc.key,
          title: inc.title,
          summary: [
            `${inc.eventCount} events across ${inc.uniqueFiles} files`,
            inc.path && inc.path !== "(unknown)" ? `under ${inc.path}` : "in an unresolved directory",
            durationMin ? `over ${durationMin} minute(s)` : null,
          ].filter(Boolean).join(" "),
          rationale: explainIncidentFinding(inc),
          severity: severityForPriority(inc.priorityScore || inc.riskScore || 0),
          priorityScore: inc.priorityScore || inc.riskScore || 0,
          path: inc.path || "",
          primaryPath: inc.path || "",
          entryNumber: entryNumber != null ? String(entryNumber) : "",
          start: inc.start || "",
          end: inc.end || "",
          eventCount: inc.eventCount || 0,
          uniqueFiles: inc.uniqueFiles || 0,
          reasonFamily: inc.reasonFamily || "",
          categories: inc.categories || [],
          tags: inc.tags || [],
          confidence: inc.confidence || "medium",
          correlationTags: inc.correlationTags || [],
          evidence: buildEvidenceList({
            reasonBuckets: inc.reasonFamily ? [inc.reasonFamily] : [],
            tags: inc.tags || [],
            topExtensions: inc.topExtensions || [],
            categories: inc.categories || [],
          }),
        };
      });
      const chainFindings = result.fileChains.filter((ch) => ch.highConfidence).slice(0, 4).map((ch) => {
        const durationMin = Number.isFinite(ch.durationMs) ? Math.max(1, Math.round(ch.durationMs / 60000)) : null;
        return {
          key: `chain:${ch.key}`,
          sourceType: "fileChain",
          sourceKey: ch.key,
          title: ch.title,
          summary: [
            `${ch.eventCount} events touching ${ch.primaryPath || ch.title || "(unknown)"}`,
            (ch.pathTransitions?.length || 0) > 1 ? `across ${ch.pathTransitions.length} path variants` : null,
            durationMin ? `over ${durationMin} minute(s)` : null,
          ].filter(Boolean).join(" "),
          rationale: explainChainFinding(ch),
          severity: severityForPriority(ch.priorityScore || ch.riskScore || 0),
          priorityScore: ch.priorityScore || ch.riskScore || 0,
          path: ch.primaryDirectory || "",
          primaryPath: ch.primaryPath || "",
          entryNumber: ch.entryNumber != null ? String(ch.entryNumber) : "",
          start: ch.firstSeen || "",
          end: ch.lastSeen || "",
          eventCount: ch.eventCount || 0,
          pathVariants: ch.pathTransitions?.length || 0,
          sameDirectoryChainCount: ch.sameDirectoryChainCount || 0,
          categories: ch.categories || [],
          reasonBuckets: ch.reasonBuckets || [],
          tags: ch.tags || [],
          confidence: ch.confidence || "medium",
          correlationTags: ch.correlationTags || [],
          evidence: buildEvidenceList({
            reasonBuckets: ch.reasonBuckets || [],
            tags: ch.tags || [],
            topExtensions: ch.extensions || [],
            categories: ch.categories || [],
          }),
        };
      });
      result.likelyFindings = [...incidentFindings, ...chainFindings]
        .sort((a, b) => (b.priorityScore - a.priorityScore)
          || ((b.eventCount || 0) - (a.eventCount || 0))
          || (a.sourceType === b.sourceType ? 0 : (a.sourceType === "directoryIncident" ? -1 : 1)))
        .slice(0, 8);

      const topIncident = result.directoryIncidents[0];
      const topExec = result.execution?.events?.length || 0;
      const highConfidenceExec = allEvents.filter((ev) => ev.category === "execution" && ev.promotionEligible).length;
      const topExfil = result.exfil?.archives?.length || 0;
      const highConfidenceExfil = allEvents.filter((ev) => ev.category === "exfil" && ev.promotionEligible).length;
      const topPersist = result.persistence?.events?.length || 0;
      const topRename = result.renames?.events?.length || 0;
      result.narrative = [
        topIncident && topIncident.highConfidence ? `${topIncident.uniqueFiles} files had corroborated ${topIncident.reasonFamily.replace("-", " ")} activity under ${topIncident.path} in ${Math.max(1, Math.round((parseTs(topIncident.end) - parseTs(topIncident.start)) / 60000))} minute(s)` : null,
        topExec > 0 ? `${topExec} executable/script artifacts were observed; ${highConfidenceExec} met the corroborated suspicious threshold` : null,
        topExfil > 0 ? `${topExfil} archive artifacts were observed; ${highConfidenceExfil} met the corroborated exfil/staging threshold` : null,
        topPersist > 0 ? `${topPersist} events touched persistence-related paths` : null,
        result.correlationSummary?.length > 0 ? `${result.correlationSummary.slice(0, 3).map((c) => `${c.count} ${c.label.toLowerCase()}`).join(", ")}` : null,
        result.likelyFindings.length === 0 && totalEvents > 0 ? "Observed activity did not produce corroborated high-confidence intrusion findings in this window" : null,
        topRename > 0 ? `${topRename} rename pairs were observed in this window` : "No meaningful rename activity in the selected window",
      ].filter(Boolean);

      return result;
    } catch (err) {
      return { ...empty, error: err.message };
    }
  }

  /**
   * USN Journal Rewind — resolve ParentPath from the journal's own directory records.
   * Processes directory entries in reverse chronological order (newest first) to build
   * a directory tree, then chain-walks parent references to reconstruct full paths.
   * When mftTabId is provided, uses MFT directory data as fallback for unresolved entries.
   */
  resolveUsnPaths(tabId, mftTabId) {
    const meta = this.databases.get(tabId);
    if (!meta) return { resolved: 0, total: 0 };

    const col = (name) => meta.colMap[name];
    const nameCol = col("Name");
    const entryCol = col("EntryNumber");
    const seqCol = col("SequenceNumber");
    const parentEntryCol = col("ParentEntryNumber");
    const parentSeqCol = col("ParentSequenceNumber");
    const parentPathCol = col("ParentPath");
    const attrsCol = col("FileAttributes");
    const tsCol = col("UpdateTimestamp");

    if (!nameCol || !entryCol || !parentEntryCol || !parentPathCol || !attrsCol) {
      return { resolved: 0, total: 0, error: "Missing required columns" };
    }

    try {
      // Step 1: Query all directory records, newest first (rewind order)
      let dirRecords;
      try {
        dirRecords = meta.db.prepare(`
          SELECT ${entryCol} as entry, ${seqCol} as seq, ${nameCol} as name,
                 ${parentEntryCol} as parentEntry, ${parentSeqCol} as parentSeq
          FROM data WHERE ${attrsCol} LIKE '%Directory%'
          ORDER BY sort_datetime(${tsCol}) DESC
        `).all();
      } catch (e) {
        dbg("DB", `USN rewind: $J directory query fallback`, { error: e.message });
        // Fallback: try without ORDER BY (sort_datetime might fail)
        try {
          dirRecords = meta.db.prepare(`
            SELECT ${entryCol} as entry, ${seqCol} as seq, ${nameCol} as name,
                   ${parentEntryCol} as parentEntry, ${parentSeqCol} as parentSeq
            FROM data WHERE ${attrsCol} LIKE '%Directory%'
          `).all();
        } catch (e2) {
          return { resolved: 0, total: 0, error: "$J query failed: " + e2.message };
        }
      }

      // Build dirMap — first seen (= most recent) wins per entry-seq pair
      // Keys must be strings — SQLite may return numbers for numeric values
      const dirMap = new Map();
      for (const r of dirRecords) {
        const key = String(r.entry) + "-" + String(r.seq || 0);
        if (!dirMap.has(key)) {
          dirMap.set(key, {
            name: r.name,
            parentEntry: String(r.parentEntry),
            parentSeq: String(r.parentSeq || 0),
          });
        }
      }

      // Step 2: MFT augmentation (when available — skip if MFT db is busy building indexes)
      const mftPathMap = new Map();
      if (mftTabId) {
        const mftMeta = this.databases.get(mftTabId);
        if (mftMeta && !mftMeta.indexesBuilding) {
          try {
            const mEntry = mftMeta.colMap["EntryNumber"];
            const mName = mftMeta.colMap["FileName"];
            const mPath = mftMeta.colMap["ParentPath"];
            const mIsDir = mftMeta.colMap["IsDirectory"];
            if (mEntry && mName && mPath && mIsDir) {
              const mftDirs = mftMeta.db.prepare(
                `SELECT ${mEntry} as entry, ${mName} as name, ${mPath} as parentPath
                 FROM data WHERE ${mIsDir} = 'True'`
              ).all();
              for (const d of mftDirs) {
                const fullPath = d.parentPath
                  ? d.parentPath + "\\" + d.name
                  : ".\\" + d.name;
                mftPathMap.set(String(d.entry), fullPath);
              }
            }
          } catch (e) {
            dbg("DB", `USN rewind: MFT query skipped`, { error: e.message });
            // Continue without MFT — self-resolution still works
          }
        } else if (mftMeta?.indexesBuilding) {
          dbg("DB", `USN rewind: MFT still building indexes — deferring augmentation`);
        }
      }

      // Step 3: Resolve paths via chain walk
      const pathCache = new Map();
      function resolvePath(entry, seq) {
        const key = String(entry) + "-" + String(seq);
        if (pathCache.has(key)) return pathCache.get(key);

        const parts = [];
        let current = key;
        const visited = new Set();

        while (current) {
          if (visited.has(current)) break;
          visited.add(current);

          const dir = dirMap.get(current);
          if (!dir) {
            // Try MFT fallback for the current entry number
            const entryOnly = current.split("-")[0];
            const mftPath = mftPathMap.get(entryOnly);
            if (mftPath) {
              parts.unshift(mftPath);
            }
            break;
          }

          if (dir.name !== "." && dir.name !== "..") {
            parts.unshift(dir.name);
          }

          // Root directory (entry 5) = NTFS root
          if (dir.parentEntry === "5") break;
          const parentKey = dir.parentEntry + "-" + dir.parentSeq;
          if (parentKey === current) break;
          current = parentKey;
        }

        const resolved = parts.length > 0 ? ".\\" + parts.join("\\") : "";
        pathCache.set(key, resolved);
        return resolved;
      }

      // Step 4: Resolve paths and batch UPDATE
      // IMPORTANT: better-sqlite3 cannot run write operations while an .iterate()
      // cursor is active on the same connection. So we SELECT all rows first, then UPDATE.
      const allRows = meta.db.prepare(
        `SELECT rowid, ${parentEntryCol} as parentEntry, ${parentSeqCol} as parentSeq FROM data`
      ).all();

      const updateStmt = meta.db.prepare(
        `UPDATE data SET ${parentPathCol} = ? WHERE rowid = ?`
      );
      const updateBatch = meta.db.transaction((updates) => {
        for (const u of updates) updateStmt.run(u.path, u.rowid);
      });

      let resolved = 0, mftResolved = 0;
      const total = allRows.length;
      const batch = [];

      for (const row of allRows) {
        const pe = String(row.parentEntry);
        const ps = String(row.parentSeq || 0);
        const path = resolvePath(pe, ps);
        if (path) {
          batch.push({ path, rowid: row.rowid });
          resolved++;
          if (!dirMap.has(pe + "-" + ps) && mftPathMap.size > 0) {
            mftResolved++;
          }
        }
        if (batch.length >= 10000) {
          updateBatch(batch);
          batch.length = 0;
        }
      }
      if (batch.length > 0) updateBatch(batch);

      const stats = {
        resolved,
        total,
        mftResolved,
        selfResolved: resolved - mftResolved,
        unresolved: total - resolved,
        resolvedPercent: total > 0 ? Math.round((resolved / total) * 100) : 0,
        directoriesFound: dirMap.size,
        mftEntriesUsed: mftPathMap.size,
      };
      return stats;
    } catch (err) {
      return { resolved: 0, total: 0, error: err.message };
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // IQL — IRFlow Query Language execution
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Execute a parsed IQL command list against a tab's database.
   *
   * For STATS queries  → returns all result rows in memory (typically small).
   * For filter queries → returns the WHERE SQL + params so queryRows can use
   *   them as an extra filter on top of normal column/search filters.
   *
   * @param {string}   tabId
   * @param {Object[]} commands  – AST from queryEngine.parseIql()
   * @returns {{ queryType, rows?, headers?, totalRows, extraWhereSql?, extraWhereParams?, selectCols?, sql?, error? }}
   */
  runIqlQuery(tabId, commands) {
    const meta = this.databases.get(tabId);
    if (!meta) return { error: "Tab not found or not yet loaded" };
    if (!Array.isArray(commands) || commands.length === 0) return { error: "Empty query" };

    try {
      const statsCmd  = commands.find((c) => c.type === "STATS");
      const whereCmd  = commands.find((c) => c.type === "WHERE");
      const selectCmd = commands.find((c) => c.type === "SELECT");
      const sortCmd   = commands.find((c) => c.type === "SORT");
      const limitCmd  = commands.find((c) => c.type === "LIMIT");

      if (statsCmd) {
        return this._iqlRunStats(meta, whereCmd, statsCmd, sortCmd, limitCmd);
      } else {
        return this._iqlRunFilter(meta, whereCmd, selectCmd);
      }
    } catch (e) {
      return { error: e.message };
    }
  }

  /** Execute a STATS (GROUP BY + aggregate) query and return all rows. */
  _iqlRunStats(meta, whereCmd, statsCmd, sortCmd, limitCmd) {
    const params = [];
    const whereParts = [];

    if (whereCmd) {
      const res = this._iqlExprToSql(whereCmd.expr, meta, params);
      if (res.error) return { error: res.error };
      if (res.sql) whereParts.push(res.sql);
    }

    const whereClause = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";

    // Resolve GROUP BY columns
    const groupCols = statsCmd.groupBy.map((col) => {
      const sc = meta.colMap[col];
      if (!sc) throw new Error(`Unknown column: "${col}"`);
      return { original: col, safe: sc };
    });

    // Build aggregate expressions
    const aggExprs = statsCmd.aggs.map((agg) => {
      if (agg.func === "COUNT" && !agg.col) {
        return { expr: `COUNT(*) AS "${agg.alias}"`, alias: agg.alias };
      }
      const sc = agg.col ? meta.colMap[agg.col] : null;
      if (agg.col && !sc) throw new Error(`Unknown column: "${agg.col}"`);
      let sqlExpr;
      switch (agg.func) {
        case "COUNT": sqlExpr = `COUNT(${sc})`;                          break;
        case "SUM":   sqlExpr = `SUM(CAST(${sc} AS REAL))`;              break;
        case "AVG":   sqlExpr = `ROUND(AVG(CAST(${sc} AS REAL)), 4)`;    break;
        case "MIN":   sqlExpr = `MIN(${sc})`;                             break;
        case "MAX":   sqlExpr = `MAX(${sc})`;                             break;
        case "DC":    sqlExpr = `COUNT(DISTINCT ${sc})`;                  break;
        default: throw new Error(`Unknown aggregate function: ${agg.func}`);
      }
      return { expr: `${sqlExpr} AS "${agg.alias}"`, alias: agg.alias };
    });

    // Column headers: group cols first, then agg aliases
    const headers = [
      ...groupCols.map((c) => c.original),
      ...aggExprs.map((a) => a.alias),
    ];

    // SELECT list
    const selectParts = [
      ...groupCols.map((c) => `${c.safe} AS "${c.original}"`),
      ...aggExprs.map((a) => a.expr),
    ];

    const groupByClause = groupCols.length
      ? `GROUP BY ${groupCols.map((c) => c.safe).join(", ")}`
      : "";

    // ORDER BY — defaults to first agg DESC when no SORT given
    let orderClause = aggExprs.length ? `ORDER BY "${aggExprs[0].alias}" DESC` : "";
    if (sortCmd) {
      const parts = sortCmd.items.map((item) => {
        const gc = groupCols.find((c) => c.original === item.col || c.original.toLowerCase() === item.col.toLowerCase());
        if (gc) {
          if (meta.numericColumns.has(gc.original)) return `CAST(${gc.safe} AS REAL) ${item.dir}`;
          return `${gc.safe} COLLATE NOCASE ${item.dir}`;
        }
        const ac = aggExprs.find((a) => a.alias === item.col || a.alias.toLowerCase() === item.col.toLowerCase());
        if (ac) return `"${ac.alias}" ${item.dir}`;
        return null;
      }).filter(Boolean);
      if (parts.length) orderClause = `ORDER BY ${parts.join(", ")}`;
    }

    const limitClause = limitCmd ? `LIMIT ${limitCmd.n}` : "LIMIT 50000";
    const sql = [
      `SELECT ${selectParts.join(", ")}`,
      `FROM data`,
      whereClause,
      groupByClause,
      orderClause,
      limitClause,
    ].filter(Boolean).join(" ");

    const rawRows = meta.db.prepare(sql).all(...params);
    const rows = rawRows.map((raw, i) => {
      const row = { __idx: i + 1 };
      for (const h of headers) row[h] = raw[h] ?? "";
      return row;
    });

    return { queryType: "stats", rows, headers, totalRows: rows.length, sql, error: null };
  }

  /**
   * Validate a filter/SELECT query and return the WHERE SQL fragment +
   * resolved SELECT columns so queryRows can use them as an extra filter.
   */
  _iqlRunFilter(meta, whereCmd, selectCmd) {
    const params = [];
    let extraWhereSql = null;

    if (whereCmd) {
      const res = this._iqlExprToSql(whereCmd.expr, meta, params);
      if (res.error) return { error: res.error };
      extraWhereSql = res.sql || null;
    }

    // Validate SELECT columns
    let selectCols = null;
    if (selectCmd && selectCmd.cols.length > 0) {
      for (const col of selectCmd.cols) {
        if (!meta.colMap[col]) return { error: `Unknown column: "${col}"` };
      }
      selectCols = selectCmd.cols;
    }

    // Count matching rows for the status bar
    const countSql = `SELECT COUNT(*) AS cnt FROM data${extraWhereSql ? ` WHERE ${extraWhereSql}` : ""}`;
    const totalRows = meta.db.prepare(countSql).get(...params)?.cnt ?? 0;

    return {
      queryType: "filter",
      extraWhereSql,
      extraWhereParams: params,
      selectCols,
      totalRows,
      error: null,
    };
  }

  /** Recursively translate an IQL expression AST node to a SQL fragment. */
  _iqlExprToSql(expr, meta, params) {
    switch (expr.type) {
      case "AND": {
        const l = this._iqlExprToSql(expr.left,  meta, params);
        const r = this._iqlExprToSql(expr.right, meta, params);
        if (l.error) return l;
        if (r.error) return r;
        return { sql: `(${l.sql} AND ${r.sql})` };
      }
      case "OR": {
        const l = this._iqlExprToSql(expr.left,  meta, params);
        const r = this._iqlExprToSql(expr.right, meta, params);
        if (l.error) return l;
        if (r.error) return r;
        return { sql: `(${l.sql} OR ${r.sql})` };
      }
      case "NOT": {
        const inner = this._iqlExprToSql(expr.expr, meta, params);
        if (inner.error) return inner;
        return { sql: `NOT (${inner.sql})` };
      }
      case "IS_NULL": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };
        return { sql: `(${sc} IS NULL OR ${sc} = '')` };
      }
      case "IS_NOT_NULL": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };
        return { sql: `(${sc} IS NOT NULL AND ${sc} != '')` };
      }
      case "IN": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };
        const hasNull = expr.values.some((v) => v.kind === "null");
        const nonNull = expr.values.filter((v) => v.kind !== "null").map((v) => String(v.value));
        const parts = [];
        if (hasNull)       parts.push(`(${sc} IS NULL OR ${sc} = '')`);
        if (nonNull.length === 1) { parts.push(`${sc} = ?`); params.push(nonNull[0]); }
        else if (nonNull.length > 1) {
          params.push(...nonNull);
          parts.push(`${sc} IN (${nonNull.map(() => "?").join(",")})`);
        }
        return { sql: parts.length > 1 ? `(${parts.join(" OR ")})` : (parts[0] || "0=1") };
      }
      case "NOT_IN": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };
        const vals = expr.values.filter((v) => v.kind !== "null").map((v) => String(v.value));
        if (!vals.length) return { sql: "1=1" };
        params.push(...vals);
        return { sql: `${sc} NOT IN (${vals.map(() => "?").join(",")})` };
      }
      case "CONTAINS": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };
        // Escape LIKE special chars in the value
        params.push(`%${expr.value.replace(/[%_\\]/g, "\\$&")}%`);
        return { sql: `${sc} LIKE ? ESCAPE '\\'` };
      }
      case "STARTSWITH": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };
        params.push(`${expr.value.replace(/[%_\\]/g, "\\$&")}%`);
        return { sql: `${sc} LIKE ? ESCAPE '\\'` };
      }
      case "ENDSWITH": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };
        params.push(`%${expr.value.replace(/[%_\\]/g, "\\$&")}`);
        return { sql: `${sc} LIKE ? ESCAPE '\\'` };
      }
      case "MATCHES": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };
        params.push(expr.value);
        return { sql: `REGEXP(?, ${sc})` };
      }
      case "CMP": {
        const sc = meta.colMap[expr.col];
        if (!sc) return { error: `Unknown column: "${expr.col}"` };

        // Normalise operator
        let op = expr.op;
        if (op === "==") op = "=";
        if (op === "<>") op = "!=";

        const { kind, value } = expr.value;

        // NULL literal
        if (kind === "null") {
          return { sql: op === "=" ? `(${sc} IS NULL OR ${sc} = '')` : `(${sc} IS NOT NULL AND ${sc} != '')` };
        }

        // Numeric value: use CAST comparison for correct ordering/equality
        if (kind === "number") {
          if (meta.tsColumns.has(expr.col)) {
            // Timestamp: compare with sort_datetime helper
            params.push(String(value));
            return { sql: `sort_datetime(${sc}) ${op} sort_datetime(?)` };
          }
          params.push(value);
          return { sql: `CAST(${sc} AS REAL) ${op} ?` };
        }

        // String value
        const strVal = String(value);
        params.push(strVal);
        // For = and != use case-insensitive comparison; for range ops use raw collation
        if (op === "=" || op === "!=") return { sql: `${sc} ${op} ? COLLATE NOCASE` };
        return { sql: `${sc} ${op} ?` };
      }
      default:
        return { error: `Unknown expression type: ${expr.type}` };
    }
  }

  /**
   * Close all databases
   */
  closeAll() {
    if (this._walInterval) { clearInterval(this._walInterval); this._walInterval = null; }
    for (const tabId of this.databases.keys()) {
      this.closeTab(tabId);
    }
  }
}

module.exports = TimelineDB;
