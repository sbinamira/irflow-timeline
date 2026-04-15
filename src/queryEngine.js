/**
 * queryEngine.js — IQL (IRFlow Query Language) Parser
 *
 * Syntax (pipe-delimited commands, inspired by ES|QL / Splunk SPL):
 *   FROM <source> | WHERE <expr> | STATS <aggs> [BY <cols>] | SORT <col> [ASC|DESC] | LIMIT <n> | SELECT <cols>
 *
 * Examples:
 *   FROM security.evtx | WHERE EventID == 4624
 *   FROM file | WHERE EventID IN (4624, 4625) | STATS COUNT() BY LogonType | SORT count() DESC
 *   FROM file | WHERE Level == "Error" AND Channel == "Security" | SORT TimeCreated DESC | LIMIT 500
 *   FROM file | SELECT EventID, TimeCreated, Message | WHERE EventID != 4634
 */

// ── Token types ─────────────────────────────────────────────────────────────
const T = {
  KEYWORD: "KEYWORD",
  IDENT:   "IDENT",
  STRING:  "STRING",
  NUMBER:  "NUMBER",
  OP:      "OP",
  LPAREN:  "LPAREN",
  RPAREN:  "RPAREN",
  COMMA:   "COMMA",
  PIPE:    "PIPE",
  EOF:     "EOF",
};

const KEYWORDS = new Set([
  "FROM", "WHERE", "STATS", "SORT", "LIMIT", "SELECT",
  "BY", "AS", "AND", "OR", "NOT",
  "IN", "IS", "NULL", "ASC", "DESC",
  "CONTAINS", "STARTSWITH", "ENDSWITH", "MATCHES",
  "COUNT", "SUM", "AVG", "MIN", "MAX", "DC",
  "TRUE", "FALSE",
]);

// ── Tokenizer ────────────────────────────────────────────────────────────────
function tokenize(input) {
  const tokens = [];
  let i = 0;
  const len = input.length;

  while (i < len) {
    // Whitespace
    if (/\s/.test(input[i])) { i++; continue; }

    // Line comment
    if (input[i] === "/" && input[i + 1] === "/") {
      while (i < len && input[i] !== "\n") i++;
      continue;
    }

    const pos = i;

    // Pipe
    if (input[i] === "|") { tokens.push({ type: T.PIPE,   value: "|", pos }); i++; continue; }
    if (input[i] === "(") { tokens.push({ type: T.LPAREN, value: "(", pos }); i++; continue; }
    if (input[i] === ")") { tokens.push({ type: T.RPAREN, value: ")", pos }); i++; continue; }
    if (input[i] === ",") { tokens.push({ type: T.COMMA,  value: ",", pos }); i++; continue; }

    // Two-char operators
    if (input[i] === "=" && input[i+1] === "=") { tokens.push({ type: T.OP, value: "==", pos }); i+=2; continue; }
    if (input[i] === "!" && input[i+1] === "=") { tokens.push({ type: T.OP, value: "!=", pos }); i+=2; continue; }
    if (input[i] === "<" && input[i+1] === ">") { tokens.push({ type: T.OP, value: "<>", pos }); i+=2; continue; }
    if (input[i] === "<" && input[i+1] === "=") { tokens.push({ type: T.OP, value: "<=", pos }); i+=2; continue; }
    if (input[i] === ">" && input[i+1] === "=") { tokens.push({ type: T.OP, value: ">=", pos }); i+=2; continue; }
    // Single-char operators
    if (input[i] === "<") { tokens.push({ type: T.OP, value: "<", pos }); i++; continue; }
    if (input[i] === ">") { tokens.push({ type: T.OP, value: ">", pos }); i++; continue; }
    if (input[i] === "=") { tokens.push({ type: T.OP, value: "=",  pos }); i++; continue; }

    // Quoted strings (single or double)
    if (input[i] === '"' || input[i] === "'") {
      const q = input[i]; let s = ""; i++;
      while (i < len && input[i] !== q) {
        if (input[i] === "\\" && i + 1 < len) { i++; s += input[i]; }
        else s += input[i];
        i++;
      }
      i++; // closing quote
      tokens.push({ type: T.STRING, value: s, pos });
      continue;
    }

    // Backtick-quoted identifiers (for column names with spaces)
    if (input[i] === "`") {
      let s = ""; i++;
      while (i < len && input[i] !== "`") { s += input[i]; i++; }
      i++;
      tokens.push({ type: T.IDENT, value: s, pos, quoted: true });
      continue;
    }

    // Numbers (including negatives at the start of expression context)
    if (/\d/.test(input[i])) {
      let s = "";
      while (i < len && /[\d.]/.test(input[i])) { s += input[i]; i++; }
      tokens.push({ type: T.NUMBER, value: parseFloat(s), raw: s, pos });
      continue;
    }

    // Identifiers and keywords (allow dots for filename.ext style sources)
    if (/[a-zA-Z_$]/.test(input[i])) {
      let s = "";
      while (i < len && /[a-zA-Z0-9_$./-]/.test(input[i])) { s += input[i]; i++; }
      const upper = s.toUpperCase();
      if (KEYWORDS.has(upper)) {
        tokens.push({ type: T.KEYWORD, value: upper, raw: s, pos });
      } else {
        tokens.push({ type: T.IDENT, value: s, pos });
      }
      continue;
    }

    // Unknown — skip
    i++;
  }

  tokens.push({ type: T.EOF, value: null, pos: i });
  return tokens;
}

// ── Recursive descent parser ─────────────────────────────────────────────────
class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek()  { return this.tokens[this.pos]; }
  next()  { const t = this.tokens[this.pos]; if (t.type !== T.EOF) this.pos++; return t; }

  expect(type, value) {
    const t = this.next();
    if (t.type !== type || (value !== undefined && t.value !== value)) {
      throw new Error(`Expected ${value !== undefined ? `"${value}"` : type} but got "${t.value}" (pos ${t.pos})`);
    }
    return t;
  }

  match(type, value) {
    const t = this.peek();
    if (t.type === type && (value === undefined || t.value === value)) { this.pos++; return t; }
    return null;
  }

  // ── Top-level ──────────────────────────────────────────────────────────────
  parseQuery() {
    const commands = [this.parseCommand()];
    while (this.peek().type === T.PIPE) {
      this.next();
      commands.push(this.parseCommand());
    }
    if (this.peek().type !== T.EOF) {
      throw new Error(`Unexpected token "${this.peek().value}" at pos ${this.peek().pos}`);
    }
    return commands;
  }

  parseCommand() {
    const t = this.peek();
    if (t.type === T.KEYWORD) {
      switch (t.value) {
        case "FROM":   return this.parseFrom();
        case "WHERE":  return this.parseWhere();
        case "STATS":  return this.parseStats();
        case "SORT":   return this.parseSort();
        case "LIMIT":  return this.parseLimit();
        case "SELECT": return this.parseSelect();
        default: break;
      }
    }
    throw new Error(`Expected command (FROM, WHERE, STATS, SORT, LIMIT, SELECT) but got "${t.value}"`);
  }

  parseFrom() {
    this.expect(T.KEYWORD, "FROM");
    const source = this.parseName();
    return { type: "FROM", source };
  }

  parseWhere() {
    this.expect(T.KEYWORD, "WHERE");
    const expr = this.parseExpr();
    return { type: "WHERE", expr };
  }

  parseStats() {
    this.expect(T.KEYWORD, "STATS");
    const aggs = this.parseAggList();
    let groupBy = [];
    if (this.match(T.KEYWORD, "BY")) groupBy = this.parseNameList();
    return { type: "STATS", aggs, groupBy };
  }

  parseAggList() {
    const list = [this.parseAgg()];
    while (this.peek().type === T.COMMA) {
      // Peek ahead: if next after comma is an agg keyword, consume
      const saved = this.pos;
      this.next(); // consume comma
      const next = this.peek();
      const AGG_KWS = ["COUNT","SUM","AVG","MIN","MAX","DC"];
      if (next.type === T.KEYWORD && AGG_KWS.includes(next.value)) {
        list.push(this.parseAgg());
      } else {
        this.pos = saved; // backtrack — comma belongs to BY col list
        break;
      }
    }
    return list;
  }

  parseAgg() {
    const AGG_KWS = ["COUNT","SUM","AVG","MIN","MAX","DC"];
    const t = this.peek();
    if (t.type !== T.KEYWORD || !AGG_KWS.includes(t.value)) {
      throw new Error(`Expected aggregate function (COUNT/SUM/AVG/MIN/MAX/DC) but got "${t.value}"`);
    }
    const func = t.value; this.next();
    this.expect(T.LPAREN);
    let col = null;
    if (this.peek().type !== T.RPAREN) col = this.parseName();
    this.expect(T.RPAREN);
    let alias = null;
    if (this.match(T.KEYWORD, "AS")) alias = this.parseName();
    if (!alias) alias = col ? `${func.toLowerCase()}(${col})` : `${func.toLowerCase()}()`;
    return { func, col, alias };
  }

  parseSort() {
    this.expect(T.KEYWORD, "SORT");
    const items = [this.parseSortItem()];
    while (this.match(T.COMMA)) items.push(this.parseSortItem());
    return { type: "SORT", items };
  }

  parseSortItem() {
    const col = this.parseName();
    let dir = "DESC"; // default sort descending (most useful for STATS results)
    if      (this.match(T.KEYWORD, "ASC"))  dir = "ASC";
    else if (this.match(T.KEYWORD, "DESC")) dir = "DESC";
    return { col, dir };
  }

  parseLimit() {
    this.expect(T.KEYWORD, "LIMIT");
    const t = this.expect(T.NUMBER);
    return { type: "LIMIT", n: Math.max(1, Math.floor(t.value)) };
  }

  parseSelect() {
    this.expect(T.KEYWORD, "SELECT");
    const cols = this.parseNameList();
    return { type: "SELECT", cols };
  }

  // Comma-separated name list (stops at | or EOF or non-name token)
  parseNameList() {
    const list = [this.parseName()];
    while (this.peek().type === T.COMMA) {
      const saved = this.pos; this.next();
      const next = this.peek();
      if (next.type === T.EOF || next.type === T.PIPE || next.type === T.KEYWORD && ["FROM","WHERE","STATS","SORT","LIMIT","SELECT","BY"].includes(next.value)) {
        this.pos = saved; break;
      }
      list.push(this.parseName());
    }
    return list;
  }

  // A name: identifier, backtick-quoted, or bare keyword used as column name
  parseName() {
    const t = this.peek();
    if (t.type === T.IDENT)    { this.next(); return t.value; }
    if (t.type === T.KEYWORD)  { this.next(); return t.value; } // allow keywords as col names
    if (t.type === T.STRING)   { this.next(); return t.value; }
    throw new Error(`Expected column name but got "${t.value}" (pos ${t.pos})`);
  }

  // ── Boolean expression parser (OR > AND > NOT > comparison) ──────────────
  parseExpr()  { return this.parseOr(); }

  parseOr() {
    let left = this.parseAnd();
    while (this.match(T.KEYWORD, "OR")) {
      left = { type: "OR", left, right: this.parseAnd() };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseNot();
    while (this.match(T.KEYWORD, "AND")) {
      left = { type: "AND", left, right: this.parseNot() };
    }
    return left;
  }

  parseNot() {
    if (this.match(T.KEYWORD, "NOT")) return { type: "NOT", expr: this.parseNot() };
    return this.parseComparison();
  }

  parseComparison() {
    // Parenthesized sub-expression
    if (this.match(T.LPAREN)) {
      const expr = this.parseExpr();
      this.expect(T.RPAREN);
      return expr;
    }

    const col = this.parseName();
    const t   = this.peek();

    // IS [NOT] NULL
    if (t.type === T.KEYWORD && t.value === "IS") {
      this.next();
      const negated = !!this.match(T.KEYWORD, "NOT");
      this.expect(T.KEYWORD, "NULL");
      return { type: negated ? "IS_NOT_NULL" : "IS_NULL", col };
    }

    // [NOT] IN (...)
    if (t.type === T.KEYWORD && t.value === "NOT") {
      const saved = this.pos; this.next();
      if (this.match(T.KEYWORD, "IN")) {
        this.expect(T.LPAREN);
        const values = [this.parseValue()];
        while (this.match(T.COMMA)) values.push(this.parseValue());
        this.expect(T.RPAREN);
        return { type: "NOT_IN", col, values };
      }
      this.pos = saved; // backtrack — NOT belongs to outer context
    }

    if (t.type === T.KEYWORD && t.value === "IN") {
      this.next();
      this.expect(T.LPAREN);
      const values = [this.parseValue()];
      while (this.match(T.COMMA)) values.push(this.parseValue());
      this.expect(T.RPAREN);
      return { type: "IN", col, values };
    }

    // String-match operators
    for (const kw of ["CONTAINS","STARTSWITH","ENDSWITH","MATCHES"]) {
      if (t.type === T.KEYWORD && t.value === kw) {
        this.next();
        return { type: kw, col, value: this.parseStringValue() };
      }
    }

    // Comparison operators
    if (t.type === T.OP) {
      const op = t.value; this.next();
      return { type: "CMP", col, op, value: this.parseValue() };
    }

    throw new Error(`Expected operator after column "${col}" but got "${t.value}" (pos ${t.pos})`);
  }

  parseValue() {
    const t = this.peek();
    if (t.type === T.STRING)  { this.next(); return { kind: "string", value: t.value }; }
    if (t.type === T.NUMBER)  { this.next(); return { kind: "number", value: t.value }; }
    if (t.type === T.KEYWORD && t.value === "NULL")  { this.next(); return { kind: "null",   value: null  }; }
    if (t.type === T.KEYWORD && t.value === "TRUE")  { this.next(); return { kind: "bool",   value: true  }; }
    if (t.type === T.KEYWORD && t.value === "FALSE") { this.next(); return { kind: "bool",   value: false }; }
    if (t.type === T.IDENT)   { this.next(); return { kind: "string", value: t.value }; }
    // Negative numbers: "-" followed by NUMBER in token stream appears as IDENT/OP
    throw new Error(`Expected value but got "${t.value}" (pos ${t.pos})`);
  }

  parseStringValue() {
    const t = this.peek();
    if (t.type === T.STRING) { this.next(); return t.value; }
    if (t.type === T.IDENT)  { this.next(); return t.value; }
    throw new Error(`Expected string value but got "${t.value}" (pos ${t.pos})`);
  }
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Parse an IQL query string into an array of command AST nodes.
 * @returns {{ commands: Object[]|null, error: string|null }}
 */
export function parseIql(input) {
  if (!input || !input.trim()) return { commands: [], error: null };
  try {
    const tokens = tokenize(input.trim());
    const parser = new Parser(tokens);
    const commands = parser.parseQuery();
    return { commands, error: null };
  } catch (e) {
    return { commands: null, error: e.message };
  }
}

/**
 * Return autocomplete suggestions for the word currently being typed.
 * @param {string} input  - full query text up to cursor
 * @param {string[]} columns - available column names in current tab
 * @returns {string[]}
 */
export function getAutocompleteSuggestions(input, columns = []) {
  const trimmed = input.trimEnd();
  const lower   = trimmed.toLowerCase();

  // After a pipe — suggest next command
  if (/\|\s*$/.test(trimmed)) return ["WHERE", "STATS", "SORT", "LIMIT", "SELECT"];

  // After command keyword — suggest column names or agg functions
  if (/\bwhere\s+$/i.test(lower) || /\b(and|or|not)\s+$/i.test(lower))  return columns;
  if (/\bstats\s+$/i.test(lower)) return ["COUNT()", "SUM(", "AVG(", "MIN(", "MAX(", "DC("];
  if (/\bby\s+$/i.test(lower))    return columns;
  if (/\bsort\s+$/i.test(lower))  return columns;
  if (/\bselect\s+$/i.test(lower))return columns;

  // After an operator — suggest nothing (user types a value)
  if (/[=<>!]=?\s*$/.test(trimmed)) return [];

  // Partial word — suggest matching keywords + columns
  const wordMatch = trimmed.match(/[\w`]+$/);
  const partial   = wordMatch ? wordMatch[0].replace(/`/g, "").toLowerCase() : "";
  if (!partial) return [];

  const kwSuggestions = ["FROM","WHERE","STATS","SORT","LIMIT","SELECT","BY","AND","OR","NOT","IN","IS","NULL","ASC","DESC","CONTAINS","STARTSWITH","ENDSWITH","MATCHES"];
  return [
    ...kwSuggestions.filter(k => k.toLowerCase().startsWith(partial)),
    ...columns.filter(c => c.toLowerCase().startsWith(partial)),
  ].slice(0, 20);
}

/**
 * Syntax-highlight an IQL query string.
 * Returns an array of { text, type } tokens for rendering.
 * Types: "keyword" | "string" | "number" | "operator" | "ident" | "plain"
 */
export function highlightIql(input) {
  if (!input) return [{ text: "", type: "plain" }];
  try {
    const tokens = tokenize(input);
    const result = [];
    let lastPos = 0;

    for (const tok of tokens) {
      if (tok.type === T.EOF) break;
      // Gap between tokens (whitespace/punctuation we didn't tokenize)
      if (tok.pos > lastPos) {
        result.push({ text: input.slice(lastPos, tok.pos), type: "plain" });
      }
      const text = tok.raw || (typeof tok.value === "string" ? tok.value : String(tok.value ?? ""));
      // Reconstruct original text including quotes for strings
      let rawText = text;
      if (tok.type === T.STRING) {
        // Find the quoted string in source
        const before = input.slice(lastPos, tok.pos + text.length + 10);
        const qm = before.match(/^(['"])(.*?)\1/s);
        rawText = qm ? qm[0] : `"${text}"`;
      }
      const typeMap = {
        [T.KEYWORD]: "keyword",
        [T.STRING]:  "string",
        [T.NUMBER]:  "number",
        [T.OP]:      "operator",
        [T.PIPE]:    "operator",
        [T.LPAREN]:  "plain",
        [T.RPAREN]:  "plain",
        [T.COMMA]:   "plain",
        [T.IDENT]:   "ident",
      };
      result.push({ text: rawText, type: typeMap[tok.type] || "plain" });
      lastPos = tok.pos + rawText.length;
    }

    // Any trailing characters
    if (lastPos < input.length) {
      result.push({ text: input.slice(lastPos), type: "plain" });
    }
    return result;
  } catch {
    return [{ text: input, type: "plain" }];
  }
}
