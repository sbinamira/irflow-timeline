<template>
  <div class="demo-wrapper">
    <div class="demo-graphic" ref="container">
      <!-- Scan line effect -->
      <div class="scan-line" :style="{ background: `linear-gradient(180deg, transparent ${scanLine - 1}%, #E8613A08 ${scanLine}%, transparent ${scanLine + 1}%)` }" />

      <!-- Title bar -->
      <div class="demo-title-bar">
        <div class="title-left">
          <div class="traffic-lights">
            <span class="dot dot-red" />
            <span class="dot dot-yellow" />
            <span class="dot dot-green" />
          </div>
          <span class="title-text">IRFlow Timeline — interactive_demo.csv</span>
        </div>
        <div class="title-right">
          <span class="brand-name">IRFlow</span>
          <span class="brand-version">LIVE DEMO</span>
        </div>
      </div>

      <!-- Search bar -->
      <div class="search-bar">
        <div class="search-input-wrap">
          <span class="search-icon">&#x1F50D;</span>
          <input
            ref="searchInput"
            v-model="searchQuery"
            class="search-input"
            :placeholder="searchPlaceholder"
            aria-label="Search forensic events"
            @keydown.escape="clearSearch"
          />
          <button v-if="searchQuery" class="search-clear" @click="clearSearch" aria-label="Clear search">&times;</button>
        </div>
        <div class="search-modes">
          <button
            v-for="mode in modes"
            :key="mode.value"
            class="mode-btn"
            :class="{ 'mode-active': searchMode === mode.value }"
            @click="searchMode = mode.value"
            :aria-label="`Search mode: ${mode.label}`"
          >
            <span class="mode-icon">{{ mode.icon }}</span>
            <span class="mode-label">{{ mode.label }}</span>
          </button>
        </div>
      </div>

      <!-- Search chips -->
      <div class="search-chips">
        <span class="chips-label">Try:</span>
        <button
          v-for="chip in searchChips"
          :key="chip.query"
          class="chip"
          :class="{ 'chip-active': searchQuery === chip.query && searchMode === chip.mode }"
          @click="applyChip(chip)"
        >{{ chip.label }}</button>
      </div>

      <!-- Results info -->
      <div class="results-bar">
        <div class="results-left">
          <span class="results-count">{{ filteredRows.length }}<span class="results-dim"> / {{ SAMPLE_DATA.length }} events</span></span>
          <span v-if="searchQuery" class="results-timing">{{ queryTime }}</span>
        </div>
        <div class="results-right">
          <!-- Mini sparkline -->
          <svg v-if="sparklinePoints.length" class="sparkline-svg" :viewBox="`0 0 ${sparklineWidth} 24`" preserveAspectRatio="none">
            <polyline
              :points="sparklinePoints"
              fill="none"
              stroke="#E8613A"
              stroke-width="1.5"
              stroke-linejoin="round"
            />
            <polyline
              :points="sparklineAreaPoints"
              fill="url(#sparkGrad)"
              stroke="none"
            />
            <defs>
              <linearGradient id="sparkGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#E8613A" stop-opacity="0.3" />
                <stop offset="100%" stop-color="#E8613A" stop-opacity="0" />
              </linearGradient>
            </defs>
          </svg>
        </div>
      </div>

      <!-- Data grid -->
      <div class="grid-container">
        <div class="grid-header">
          <button
            v-for="col in visibleColumns"
            :key="col.key"
            class="grid-header-cell"
            :class="[`col-${col.key}`, { 'sort-active': sortColumn === col.key }]"
            @click="toggleSort(col.key)"
            :aria-label="`Sort by ${col.label}`"
          >
            {{ col.label }}
            <span class="sort-arrow" v-if="sortColumn === col.key">{{ sortDir === 'asc' ? '\u25B2' : '\u25BC' }}</span>
            <span class="sort-arrow sort-inactive" v-else>\u25B2</span>
          </button>
        </div>
        <div class="grid-body">
          <template v-for="(row, i) in sortedRows" :key="row.id">
            <div
              class="grid-row"
              :class="{
                'row-critical': row.severity === 'critical',
                'row-high': row.severity === 'high',
                'row-expanded': expandedRow === row.id,
                'row-animate': animatedRows > i,
              }"
              :style="{ transitionDelay: animatedRows > i ? '0ms' : `${i * 20}ms` }"
              @click="toggleExpand(row.id)"
              role="row"
              :aria-expanded="expandedRow === row.id"
              tabindex="0"
              @keydown.enter="toggleExpand(row.id)"
            >
              <span class="grid-cell col-timestamp" v-html="highlight(row.Timestamp)"></span>
              <span class="grid-cell col-source" v-html="highlight(row.Source)"></span>
              <span class="grid-cell col-eventid" v-html="highlight(String(row.EventID))"></span>
              <span class="grid-cell col-computer" v-html="highlight(row.Computer)"></span>
              <span class="grid-cell col-detail">
                <span class="severity-dot" :class="`sev-${row.severity}`" />
                <span v-html="highlight(row.Detail)"></span>
              </span>
            </div>
            <!-- Expanded detail (mobile) -->
            <div v-if="expandedRow === row.id" class="row-detail">
              <div class="detail-field"><span class="detail-label">Timestamp</span><span>{{ row.Timestamp }}</span></div>
              <div class="detail-field"><span class="detail-label">Source</span><span>{{ row.Source }}</span></div>
              <div class="detail-field"><span class="detail-label">EventID</span><span>{{ row.EventID }}</span></div>
              <div class="detail-field"><span class="detail-label">Computer</span><span>{{ row.Computer }}</span></div>
              <div class="detail-field"><span class="detail-label">Detail</span><span>{{ row.Detail }}</span></div>
              <div class="detail-field"><span class="detail-label">Severity</span><span class="sev-badge" :class="`sev-badge-${row.severity}`">{{ row.severity }}</span></div>
            </div>
          </template>
          <div v-if="sortedRows.length === 0" class="grid-empty">
            No events match your search.
          </div>
        </div>
      </div>

      <!-- Lateral Movement Tracker -->
      <div class="lateral-section" :style="{ opacity: showLateral ? 1 : 0, transform: showLateral ? 'translateY(0)' : 'translateY(10px)' }">
        <div class="lateral-header">
          <div class="lateral-title-row">
            <span class="lateral-title">LATERAL MOVEMENT TRACKER</span>
            <span class="lateral-badge badge-red">OUTLIER DETECTED</span>
          </div>
          <div class="lateral-stats">
            <div class="lat-stat">
              <span class="lat-stat-val" style="color: #E8613A;">6</span>
              <span class="lat-stat-label">HOSTS</span>
            </div>
            <div class="lat-stat">
              <span class="lat-stat-val" style="color: #58a6ff;">6</span>
              <span class="lat-stat-label">CONNECTIONS</span>
            </div>
            <div class="lat-stat">
              <span class="lat-stat-val" style="color: #FFB020;">4</span>
              <span class="lat-stat-label">CHAIN DEPTH</span>
            </div>
            <div class="lat-stat">
              <span class="lat-stat-val lat-stat-danger">1</span>
              <span class="lat-stat-label">OUTLIERS</span>
            </div>
          </div>
        </div>

        <!-- Network Graph SVG -->
        <div class="lateral-graph-wrap">
          <svg viewBox="0 0 700 250" class="lateral-svg" aria-label="Lateral movement network graph">
            <defs>
              <marker id="arrowBlue" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#58a6ff" />
              </marker>
              <marker id="arrowGreen" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#3fb950" />
              </marker>
              <marker id="arrowRed" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#FF3B3B" />
              </marker>
            </defs>

            <!-- Edges -->
            <g v-for="(edge, i) in latEdges" :key="'le' + i">
              <line
                :x1="latNodes[edge.from].x" :y1="latNodes[edge.from].y"
                :x2="latNodes[edge.to].x" :y2="latNodes[edge.to].y"
                :stroke="edge.color" :stroke-width="edge.w || 1.5"
                :stroke-opacity="selectedNode && selectedNode !== latNodes[edge.from].id && selectedNode !== latNodes[edge.to].id ? 0.15 : 0.6"
                :stroke-dasharray="edge.dashed ? '4 3' : 'none'"
                :marker-end="`url(#arrow${edge.arrowColor})`"
              />
              <text
                :x="(latNodes[edge.from].x + latNodes[edge.to].x) / 2 + (edge.labelOff?.[0] || 0)"
                :y="(latNodes[edge.from].y + latNodes[edge.to].y) / 2 + (edge.labelOff?.[1] || -6)"
                :fill="edge.color" font-size="8" text-anchor="middle" font-family="monospace"
                :opacity="selectedNode && selectedNode !== latNodes[edge.from].id && selectedNode !== latNodes[edge.to].id ? 0.2 : 0.8"
              >{{ edge.label }}</text>
            </g>

            <!-- Nodes -->
            <g v-for="(node, i) in latNodes" :key="'ln' + i"
              @click.stop="selectNode(node.id)"
              style="cursor: pointer;"
            >
              <!-- Outlier node (KALI) — red pulsing dashed ring -->
              <template v-if="node.type === 'outlier'">
                <circle :cx="node.x" :cy="node.y" r="26" fill="#FF3B3B" opacity="0.06" />
                <circle :cx="node.x" :cy="node.y" r="26" fill="none" stroke="#FF3B3B" stroke-width="1.5"
                  stroke-dasharray="5 3" class="outlier-pulse"
                  :opacity="selectedNode === node.id ? 0.9 : 0.5" />
                <rect :x="node.x - 14" :y="node.y - 10" width="28" height="20" rx="3"
                  :fill="selectedNode === node.id ? '#FF3B3B35' : '#FF3B3B18'"
                  stroke="#FF3B3B" :stroke-width="selectedNode === node.id ? 1.5 : 0.8" />
                <text :x="node.x" :y="node.y + 4" fill="#FF3B3B" font-size="11" text-anchor="middle"
                  font-family="monospace" font-weight="700">{{ node.label }}</text>
                <!-- Warning triangle -->
                <polygon :points="`${node.x+18},${node.y-18} ${node.x+14},${node.y-10} ${node.x+22},${node.y-10}`"
                  fill="#FF3B3B" />
                <text :x="node.x+18" :y="node.y-13" fill="#0D0D0D" font-size="7" text-anchor="middle"
                  font-weight="800">!</text>
                <!-- Label below -->
                <text :x="node.x" :y="node.y + 42" fill="#FF3B3B" font-size="8" text-anchor="middle"
                  font-family="monospace" font-weight="600" opacity="0.9">OUTLIER</text>
                <text :x="node.x" :y="node.y + 52" fill="#888" font-size="7" text-anchor="middle"
                  font-family="monospace">Kali Linux default</text>
              </template>

              <!-- Pivot node (both source & target) — purple -->
              <template v-else-if="node.type === 'pivot'">
                <rect :x="node.x - 18" :y="node.y - 10" width="36" height="20" rx="3"
                  :fill="selectedNode === node.id ? '#a371f725' : '#a371f712'"
                  stroke="#a371f7" :stroke-width="selectedNode === node.id ? 1.5 : 0.8" />
                <text :x="node.x" :y="node.y + 4" fill="#CCC" font-size="9" text-anchor="middle"
                  font-family="monospace">{{ node.label }}</text>
                <text :x="node.x" :y="node.y + 28" fill="#a371f7" font-size="7" text-anchor="middle"
                  font-family="monospace" opacity="0.7">PIVOT</text>
              </template>

              <!-- DC node — square, blue -->
              <template v-else-if="node.type === 'dc'">
                <rect :x="node.x - 14" :y="node.y - 10" width="28" height="20" rx="2"
                  :fill="selectedNode === node.id ? '#58a6ff25' : '#58a6ff12'"
                  stroke="#58a6ff" :stroke-width="selectedNode === node.id ? 1.5 : 0.8" />
                <text :x="node.x" :y="node.y + 4" fill="#CCC" font-size="9" text-anchor="middle"
                  font-family="monospace">{{ node.label }}</text>
                <text :x="node.x" :y="node.y + 28" fill="#58a6ff" font-size="7" text-anchor="middle"
                  font-family="monospace" opacity="0.7">{{ node.role }}</text>
              </template>

              <!-- Server node — rounded rect, green -->
              <template v-else>
                <rect :x="node.x - 22" :y="node.y - 10" width="44" height="20" rx="3"
                  :fill="selectedNode === node.id ? '#3fb95025' : '#3fb95012'"
                  stroke="#3fb950" :stroke-width="selectedNode === node.id ? 1.5 : 0.8" />
                <text :x="node.x" :y="node.y + 4" fill="#CCC" font-size="8" text-anchor="middle"
                  font-family="monospace">{{ node.label }}</text>
                <text :x="node.x" :y="node.y + 28" fill="#3fb950" font-size="7" text-anchor="middle"
                  font-family="monospace" opacity="0.7">{{ node.role }}</text>
              </template>
            </g>

            <!-- Legend -->
            <g transform="translate(10, 215)">
              <rect x="0" y="0" width="200" height="28" rx="4" fill="#16161680" stroke="#333" stroke-width="0.5" />
              <circle cx="14" cy="14" r="4" fill="none" stroke="#FF3B3B" stroke-width="1" stroke-dasharray="2 1" />
              <text x="24" y="18" fill="#888" font-size="7" font-family="monospace">Outlier</text>
              <rect x="64" y="10" width="8" height="8" rx="1" fill="none" stroke="#a371f7" stroke-width="0.8" />
              <text x="77" y="18" fill="#888" font-size="7" font-family="monospace">Pivot</text>
              <line x1="112" y1="14" x2="126" y2="14" stroke="#58a6ff" stroke-width="1.5" />
              <text x="131" y="18" fill="#888" font-size="7" font-family="monospace">RDP</text>
              <line x1="156" y1="14" x2="170" y2="14" stroke="#3fb950" stroke-width="1.5" />
              <text x="175" y="18" fill="#888" font-size="7" font-family="monospace">Net</text>
            </g>
          </svg>
        </div>

        <!-- Outlier finding callout -->
        <div class="lateral-finding">
          <div class="finding-icon">&#x26A0;</div>
          <div class="finding-content">
            <div class="finding-title">
              <span class="finding-sev">CRITICAL</span>
              Outlier Host Detected — Possible Threat Actor Workstation
            </div>
            <div class="finding-detail">
              Hostname <span class="finding-hl">KALI</span> matches Kali Linux default naming pattern.
              This machine initiated the RDP session to <span class="finding-hl">WS-PC01</span> and is likely
              the attacker's workstation. IRFlow flags these automatically using hostname pattern matching.
            </div>
            <div class="finding-chain">
              <span class="chain-label">ATTACK CHAIN</span>
              <span class="chain-node chain-outlier">KALI</span>
              <span class="chain-arrow">&rarr;</span>
              <span class="chain-node chain-pivot">WS-PC01</span>
              <span class="chain-arrow">&rarr;</span>
              <span class="chain-node chain-dc">DC01</span>
              <span class="chain-arrow">&rarr;</span>
              <span class="chain-node chain-srv">SRV-DB01</span>
            </div>
          </div>
        </div>

        <!-- Detection patterns callout -->
        <div class="lateral-patterns">
          <span class="patterns-title">OUTLIER PATTERNS</span>
          <div class="patterns-grid">
            <span class="pattern-chip pattern-match">KALI</span>
            <span class="pattern-chip">PARROT</span>
            <span class="pattern-chip">DESKTOP-XXXXX</span>
            <span class="pattern-chip">WIN-XXXXX</span>
            <span class="pattern-chip">HACKER</span>
            <span class="pattern-chip">ATTACKER</span>
          </div>
        </div>
      </div>

      <!-- Status bar -->
      <div class="demo-status-bar">
        <div class="status-left">
          <span class="status-item"><span class="status-green">&#x25CF;</span> In-Browser Demo</span>
          <span class="status-item">{{ filteredRows.length }} rows</span>
          <span class="status-item">{{ searchMode }} search</span>
        </div>
        <div class="status-right">
          <span v-if="searchQuery" class="status-accent">&#x26A1; {{ queryTime }}</span>
          <span class="status-item">50 sample events</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'

// ── Search modes ──
const modes = [
  { value: 'text', label: 'Text', icon: 'Aa' },
  { value: 'regex', label: 'Regex', icon: '.*' },
  { value: 'fuzzy', label: 'Fuzzy', icon: '~' },
]

const searchChips = [
  { label: 'mimikatz', query: 'mimikatz', mode: 'text' },
  { label: '4624', query: '4624', mode: 'text' },
  { label: '\\d+\\.\\d+', query: '\\d+\\.\\d+', mode: 'regex' },
  { label: 'powrshell (fuzzy)', query: 'powrshell', mode: 'fuzzy' },
]

// ── State ──
const searchQuery = ref('')
const searchMode = ref('text')
const sortColumn = ref(null)
const sortDir = ref('asc')
const expandedRow = ref(null)
const scanLine = ref(0)
const animatedRows = ref(0)
const searchInput = ref(null)
const isMobile = ref(false)
const showLateral = ref(false)
const selectedNode = ref(null)

// ── Lateral Movement Graph Data ──
const latNodes = [
  { id: 'KALI',       x: 80,  y: 90,  label: 'KALI',       type: 'outlier' },
  { id: 'WS-PC01',    x: 250, y: 110, label: 'WS-PC01',    type: 'pivot' },
  { id: 'DC01',       x: 420, y: 60,  label: 'DC01',        type: 'dc', role: 'Domain Controller' },
  { id: 'SRV-DB01',   x: 590, y: 60,  label: 'SRV-DB01',   type: 'server', role: 'Database' },
  { id: 'SRV-WEB01',  x: 420, y: 170, label: 'SRV-WEB01',  type: 'server', role: 'Web Server' },
  { id: 'SRV-FILE02', x: 590, y: 170, label: 'SRV-FILE02', type: 'server', role: 'File Server' },
]

const latEdges = [
  { from: 0, to: 1, color: '#58a6ff', arrowColor: 'Blue', w: 2,   label: 'RDP ×1',     labelOff: [0, -8] },
  { from: 1, to: 2, color: '#3fb950', arrowColor: 'Green', w: 2.5, label: 'PsExec ×12', labelOff: [0, -8] },
  { from: 1, to: 4, color: '#3fb950', arrowColor: 'Green', w: 1.5, label: 'WMIC ×2',    labelOff: [-15, 0] },
  { from: 1, to: 5, color: '#3fb950', arrowColor: 'Green', w: 1.5, label: 'SMB ×5',     labelOff: [0, 12] },
  { from: 2, to: 3, color: '#58a6ff', arrowColor: 'Blue', w: 1.5,  label: 'RDP ×3',     labelOff: [0, -8] },
  { from: 2, to: 5, color: '#3fb950', arrowColor: 'Green', w: 1.5, label: 'WinRM ×4',   labelOff: [15, 0] },
]

function selectNode(id) {
  selectedNode.value = selectedNode.value === id ? null : id
}

// ── Sample Data: 50 rows telling an attack story ──
const SAMPLE_DATA = [
  // Phase 1: Initial Access (1-5)
  { id: 1,  Timestamp: '2025-02-14 03:10:01', Source: 'Security.evtx', EventID: 4624, Computer: 'WS-PC01', Detail: 'Logon Type 3 - user: jsmith@corp.local', severity: 'low' },
  { id: 2,  Timestamp: '2025-02-14 03:10:15', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'outlook.exe spawned WINWORD.EXE', severity: 'medium' },
  { id: 3,  Timestamp: '2025-02-14 03:10:22', Source: 'Sysmon.evtx',   EventID: 11,   Computer: 'WS-PC01', Detail: 'FileCreate: C:\\Users\\jsmith\\Q4-Report.docm', severity: 'high' },
  { id: 4,  Timestamp: '2025-02-14 03:10:30', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'WINWORD.EXE spawned cmd.exe /c macro', severity: 'critical' },
  { id: 5,  Timestamp: '2025-02-14 03:10:45', Source: 'Security.evtx', EventID: 4624, Computer: 'WS-PC01', Detail: 'Logon Type 10 - RDP from 10.0.1.50 (WorkstationName: KALI)', severity: 'high' },

  // Phase 2: Execution (6-12)
  { id: 6,  Timestamp: '2025-02-14 03:11:02', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'cmd.exe spawned powershell.exe -enc base64blob', severity: 'critical' },
  { id: 7,  Timestamp: '2025-02-14 03:11:18', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'powershell.exe -ep bypass -nop IEX(download)', severity: 'critical' },
  { id: 8,  Timestamp: '2025-02-14 03:11:33', Source: 'Sysmon.evtx',   EventID: 3,    Computer: 'WS-PC01', Detail: 'powershell.exe → 185.220.101.42:443 (C2 beacon)', severity: 'critical' },
  { id: 9,  Timestamp: '2025-02-14 03:11:45', Source: 'Sysmon.evtx',   EventID: 7,    Computer: 'WS-PC01', Detail: 'ImageLoad: amsi.dll in powershell.exe (bypass attempt)', severity: 'high' },
  { id: 10, Timestamp: '2025-02-14 03:11:58', Source: 'Hayabusa',      EventID: 0,    Computer: 'WS-PC01', Detail: 'ALERT: Suspicious PowerShell execution detected', severity: 'critical' },
  { id: 11, Timestamp: '2025-02-14 03:12:10', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'powershell.exe spawned rundll32.exe', severity: 'high' },
  { id: 12, Timestamp: '2025-02-14 03:12:22', Source: 'Sysmon.evtx',   EventID: 11,   Computer: 'WS-PC01', Detail: 'FileCreate: C:\\Windows\\Temp\\stager.ps1', severity: 'critical' },

  // Phase 3: Discovery (13-18)
  { id: 13, Timestamp: '2025-02-14 03:13:01', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'powershell.exe spawned whoami.exe /all', severity: 'medium' },
  { id: 14, Timestamp: '2025-02-14 03:13:12', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'net.exe group "Domain Admins" /domain', severity: 'high' },
  { id: 15, Timestamp: '2025-02-14 03:13:25', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'nltest.exe /dclist:corp.local', severity: 'high' },
  { id: 16, Timestamp: '2025-02-14 03:13:38', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'systeminfo.exe → output piped to file', severity: 'medium' },
  { id: 17, Timestamp: '2025-02-14 03:13:50', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'ipconfig.exe /all', severity: 'low' },
  { id: 18, Timestamp: '2025-02-14 03:14:02', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'arp.exe -a (network mapping)', severity: 'medium' },

  // Phase 4: Credential Access (19-25)
  { id: 19, Timestamp: '2025-02-14 03:15:01', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'mimikatz.exe sekurlsa::logonpasswords', severity: 'critical' },
  { id: 20, Timestamp: '2025-02-14 03:15:15', Source: 'Sysmon.evtx',   EventID: 10,   Computer: 'WS-PC01', Detail: 'LSASS.exe accessed by mimikatz.exe (0x1010)', severity: 'critical' },
  { id: 21, Timestamp: '2025-02-14 03:15:28', Source: 'Security.evtx', EventID: 4648, Computer: 'WS-PC01', Detail: 'Explicit credentials used: admin@corp.local', severity: 'critical' },
  { id: 22, Timestamp: '2025-02-14 03:15:40', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'procdump.exe -ma lsass.exe lsass.dmp', severity: 'critical' },
  { id: 23, Timestamp: '2025-02-14 03:15:55', Source: 'Sysmon.evtx',   EventID: 11,   Computer: 'WS-PC01', Detail: 'FileCreate: C:\\Windows\\Temp\\lsass.dmp', severity: 'critical' },
  { id: 24, Timestamp: '2025-02-14 03:16:08', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'secretsdump.py → NTDS.dit extraction', severity: 'critical' },
  { id: 25, Timestamp: '2025-02-14 03:16:20', Source: 'Hayabusa',      EventID: 0,    Computer: 'WS-PC01', Detail: 'ALERT: Credential dumping tool detected', severity: 'critical' },

  // Phase 5: Lateral Movement (26-35)
  { id: 26, Timestamp: '2025-02-14 03:18:01', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'PsExec.exe \\\\DC01 -s cmd.exe', severity: 'critical' },
  { id: 27, Timestamp: '2025-02-14 03:18:15', Source: 'Security.evtx', EventID: 4624, Computer: 'DC01',    Detail: 'Logon Type 3 - pass-the-hash from WS-PC01', severity: 'critical' },
  { id: 28, Timestamp: '2025-02-14 03:18:30', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'DC01',    Detail: 'PSEXESVC.exe spawned cmd.exe on DC01', severity: 'critical' },
  { id: 29, Timestamp: '2025-02-14 03:18:45', Source: 'Security.evtx', EventID: 4624, Computer: 'SRV-DB01', Detail: 'Logon Type 10 - RDP from DC01', severity: 'critical' },
  { id: 30, Timestamp: '2025-02-14 03:19:00', Source: 'Sysmon.evtx',   EventID: 3,    Computer: 'WS-PC01', Detail: 'SMB connection → SRV-FILE02:445', severity: 'high' },
  { id: 31, Timestamp: '2025-02-14 03:19:15', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'WS-PC01', Detail: 'wmic.exe /node:SRV-WEB01 process call create', severity: 'critical' },
  { id: 32, Timestamp: '2025-02-14 03:19:30', Source: 'Security.evtx', EventID: 4624, Computer: 'SRV-WEB01', Detail: 'Logon Type 3 from WS-PC01 (wmic)', severity: 'high' },
  { id: 33, Timestamp: '2025-02-14 03:19:45', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'DC01',    Detail: 'winrm.cmd → Invoke-Command on SRV-FILE02', severity: 'high' },
  { id: 34, Timestamp: '2025-02-14 03:20:00', Source: 'Sysmon.evtx',   EventID: 18,   Computer: 'SRV-DB01', Detail: 'PipeConnected: \\\\pipe\\atsvc (schtasks)', severity: 'high' },
  { id: 35, Timestamp: '2025-02-14 03:20:15', Source: 'Hayabusa',      EventID: 0,    Computer: 'DC01',    Detail: 'ALERT: Lateral movement detected - 4 hops', severity: 'critical' },

  // Phase 6: Persistence (36-40)
  { id: 36, Timestamp: '2025-02-14 03:22:01', Source: 'Sysmon.evtx',   EventID: 13,   Computer: 'DC01',    Detail: 'Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost_update', severity: 'critical' },
  { id: 37, Timestamp: '2025-02-14 03:22:15', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'DC01',    Detail: 'sc.exe create UpdateSvc binPath= C:\\Windows\\Temp\\svc.exe', severity: 'critical' },
  { id: 38, Timestamp: '2025-02-14 03:22:30', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'SRV-DB01', Detail: 'schtasks.exe /create /tn Updater /sc ONLOGON', severity: 'high' },
  { id: 39, Timestamp: '2025-02-14 03:22:45', Source: 'Security.evtx', EventID: 4698, Computer: 'DC01',    Detail: 'Scheduled task created: \\Microsoft\\WindowsUpdate', severity: 'high' },
  { id: 40, Timestamp: '2025-02-14 03:23:00', Source: 'Sysmon.evtx',   EventID: 11,   Computer: 'DC01',    Detail: 'FileCreate: C:\\Windows\\System32\\malware.dll', severity: 'critical' },

  // Phase 7: Impact (41-50)
  { id: 41, Timestamp: '2025-02-14 03:25:01', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'DC01',    Detail: 'vssadmin.exe delete shadows /all /quiet', severity: 'critical' },
  { id: 42, Timestamp: '2025-02-14 03:25:15', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'DC01',    Detail: 'bcdedit.exe /set {default} recoveryenabled no', severity: 'critical' },
  { id: 43, Timestamp: '2025-02-14 03:25:30', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'SRV-DB01', Detail: 'cipher.exe /w:C:\\ (anti-forensics)', severity: 'critical' },
  { id: 44, Timestamp: '2025-02-14 03:25:45', Source: 'Sysmon.evtx',   EventID: 11,   Computer: 'SRV-FILE02', Detail: 'FileCreate: README-RECOVER.txt (ransom note)', severity: 'critical' },
  { id: 45, Timestamp: '2025-02-14 03:26:00', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'SRV-FILE02', Detail: 'encrypt.exe processing *.docx *.xlsx *.pdf', severity: 'critical' },
  { id: 46, Timestamp: '2025-02-14 03:26:15', Source: 'Sysmon.evtx',   EventID: 3,    Computer: 'SRV-FILE02', Detail: 'encrypt.exe → 45.33.32.156:8443 (exfil)', severity: 'critical' },
  { id: 47, Timestamp: '2025-02-14 03:26:30', Source: 'Security.evtx', EventID: 1102, Computer: 'DC01',    Detail: 'Security event log cleared', severity: 'critical' },
  { id: 48, Timestamp: '2025-02-14 03:26:45', Source: 'Sysmon.evtx',   EventID: 1,    Computer: 'DC01',    Detail: 'wevtutil.exe cl System', severity: 'critical' },
  { id: 49, Timestamp: '2025-02-14 03:27:00', Source: 'Hayabusa',      EventID: 0,    Computer: 'DC01',    Detail: 'ALERT: Mass log clearing detected', severity: 'critical' },
  { id: 50, Timestamp: '2025-02-14 03:27:15', Source: 'Hayabusa',      EventID: 0,    Computer: 'SRV-FILE02', Detail: 'ALERT: Ransomware behavior - 847 files encrypted', severity: 'critical' },
]

// ── Fuzzy matching (bigram similarity) ──
function bigrams(str) {
  const s = str.toLowerCase()
  const b = new Set()
  for (let i = 0; i < s.length - 1; i++) b.add(s.slice(i, i + 2))
  return b
}

function fuzzyScore(query, text) {
  const qBigrams = bigrams(query)
  const tBigrams = bigrams(text)
  if (qBigrams.size === 0 || tBigrams.size === 0) return 0
  let intersection = 0
  for (const b of qBigrams) if (tBigrams.has(b)) intersection++
  return (2 * intersection) / (qBigrams.size + tBigrams.size)
}

// ── Search placeholder ──
const searchPlaceholder = computed(() => {
  if (searchMode.value === 'regex') return 'Enter regex pattern...'
  if (searchMode.value === 'fuzzy') return 'Fuzzy search (typo-tolerant)...'
  return 'Search events...'
})

// ── Columns ──
const allColumns = [
  { key: 'timestamp', label: 'TIMESTAMP' },
  { key: 'source', label: 'SOURCE' },
  { key: 'eventid', label: 'ID' },
  { key: 'computer', label: 'COMPUTER' },
  { key: 'detail', label: 'DETAIL' },
]

const visibleColumns = computed(() => {
  if (isMobile.value) return allColumns.filter(c => c.key === 'timestamp' || c.key === 'detail')
  return allColumns
})

// ── Filtering ──
const filteredRows = computed(() => {
  const q = searchQuery.value.trim()
  if (!q) return [...SAMPLE_DATA]

  if (searchMode.value === 'text') {
    const lower = q.toLowerCase()
    return SAMPLE_DATA.filter(row =>
      row.Timestamp.toLowerCase().includes(lower) ||
      row.Source.toLowerCase().includes(lower) ||
      String(row.EventID).includes(lower) ||
      row.Computer.toLowerCase().includes(lower) ||
      row.Detail.toLowerCase().includes(lower)
    )
  }

  if (searchMode.value === 'regex') {
    try {
      const re = new RegExp(q, 'i')
      return SAMPLE_DATA.filter(row =>
        re.test(row.Timestamp) ||
        re.test(row.Source) ||
        re.test(String(row.EventID)) ||
        re.test(row.Computer) ||
        re.test(row.Detail)
      )
    } catch {
      return [...SAMPLE_DATA]
    }
  }

  // Fuzzy
  const threshold = 0.3
  return SAMPLE_DATA.filter(row => {
    const fields = [row.Timestamp, row.Source, String(row.EventID), row.Computer, row.Detail]
    return fields.some(f => fuzzyScore(q, f) >= threshold)
  })
})

// ── Sorting ──
const sortedRows = computed(() => {
  if (!sortColumn.value) return filteredRows.value

  const keyMap = { timestamp: 'Timestamp', source: 'Source', eventid: 'EventID', computer: 'Computer', detail: 'Detail' }
  const key = keyMap[sortColumn.value]
  const dir = sortDir.value === 'asc' ? 1 : -1

  return [...filteredRows.value].sort((a, b) => {
    let va = a[key], vb = b[key]
    if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir
    va = String(va).toLowerCase()
    vb = String(vb).toLowerCase()
    if (va < vb) return -1 * dir
    if (va > vb) return 1 * dir
    return 0
  })
})

function toggleSort(col) {
  if (sortColumn.value === col) {
    if (sortDir.value === 'asc') sortDir.value = 'desc'
    else { sortColumn.value = null; sortDir.value = 'asc' }
  } else {
    sortColumn.value = col
    sortDir.value = 'asc'
  }
}

// ── Highlighting ──
function highlight(text) {
  const q = searchQuery.value.trim()
  if (!q || searchMode.value === 'fuzzy') return escapeHtml(text)

  try {
    const re = searchMode.value === 'regex' ? new RegExp(`(${q})`, 'gi') : new RegExp(`(${escapeRegex(q)})`, 'gi')
    return escapeHtml(text).replace(re, '<mark class="hl">$1</mark>')
  } catch {
    return escapeHtml(text)
  }
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// ── Row expansion ──
function toggleExpand(id) {
  expandedRow.value = expandedRow.value === id ? null : id
}

// ── Search chips ──
function applyChip(chip) {
  searchMode.value = chip.mode
  searchQuery.value = chip.query
  expandedRow.value = null
}

function clearSearch() {
  searchQuery.value = ''
  expandedRow.value = null
}

// ── Query timing (fake) ──
const queryTime = computed(() => {
  if (!searchQuery.value) return ''
  const ms = (0.3 + Math.random() * 2.5).toFixed(1)
  return `${ms}ms`
})

// ── Sparkline ──
const sparklineWidth = 120

const sparklineBuckets = computed(() => {
  const buckets = new Array(20).fill(0)
  const rows = filteredRows.value
  if (rows.length === 0) return buckets

  // Map rows into buckets based on their index in SAMPLE_DATA
  rows.forEach(row => {
    const idx = Math.floor(((row.id - 1) / SAMPLE_DATA.length) * 20)
    buckets[Math.min(idx, 19)]++
  })
  return buckets
})

const sparklinePoints = computed(() => {
  const b = sparklineBuckets.value
  const max = Math.max(...b, 1)
  const w = sparklineWidth
  const h = 20
  return b.map((v, i) => `${(i / (b.length - 1)) * w},${h - (v / max) * h + 2}`).join(' ')
})

const sparklineAreaPoints = computed(() => {
  const b = sparklineBuckets.value
  const max = Math.max(...b, 1)
  const w = sparklineWidth
  const h = 20
  const top = b.map((v, i) => `${(i / (b.length - 1)) * w},${h - (v / max) * h + 2}`).join(' ')
  return `0,${h + 2} ${top} ${w},${h + 2}`
})

// ── Scan line animation ──
let scanIv = null
let resizeHandler = null

onMounted(() => {
  // Check mobile
  isMobile.value = window.innerWidth < 641
  resizeHandler = () => { isMobile.value = window.innerWidth < 641 }
  window.addEventListener('resize', resizeHandler)

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

  if (prefersReducedMotion) {
    animatedRows.value = SAMPLE_DATA.length
    showLateral.value = true
    return
  }

  // Stagger row entry
  let count = 0
  const rowTimer = setInterval(() => {
    count += 5
    animatedRows.value = Math.min(count, SAMPLE_DATA.length)
    if (count >= SAMPLE_DATA.length) clearInterval(rowTimer)
  }, 30)

  // Show lateral movement panel after rows load
  setTimeout(() => { showLateral.value = true }, 800)

  // Scan line
  let scanPos = 0
  scanIv = setInterval(() => {
    scanPos = (scanPos + 0.3) % 100
    scanLine.value = scanPos
  }, 30)
})

onUnmounted(() => {
  if (scanIv) clearInterval(scanIv)
  if (resizeHandler) window.removeEventListener('resize', resizeHandler)
})

// Reset expansion when search changes
watch(searchQuery, () => { expandedRow.value = null })
</script>

<style scoped>
.demo-wrapper {
  width: 100%;
  max-width: 1200px;
  margin: 24px auto;
}

.demo-graphic {
  width: 100%;
  background: #0D0D0D;
  border-radius: 16px;
  overflow: hidden;
  font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', monospace;
  position: relative;
  border: 1px solid #222;
  line-height: 1.3;
  box-sizing: border-box;
  text-align: left;
  color: #CCC;
}
.demo-graphic *,
.demo-graphic *::before,
.demo-graphic *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
  line-height: inherit;
  font-family: inherit;
}

.scan-line {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  pointer-events: none;
  z-index: 20;
}

/* ── Title bar ── */
.demo-title-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 24px !important;
  border-bottom: 1px solid #222;
  background: #161616;
}
.title-left { display: flex; align-items: center; gap: 12px; }
.traffic-lights { display: flex; gap: 6px; }
.dot { width: 12px; height: 12px; border-radius: 50%; }
.dot-red { background: #FF5F57; }
.dot-yellow { background: #FFBD2E; }
.dot-green { background: #28C840; }
.title-text { color: #999; font-size: 12px; margin-left: 8px !important; line-height: 1; }
.title-right { display: flex; align-items: center; gap: 16px; }
.brand-name { color: #E8613A; font-size: 11px; font-weight: 700; letter-spacing: 1.5px; line-height: 1; }
.brand-version { color: #28C840; font-size: 10px; font-weight: 600; letter-spacing: 1px; line-height: 1; }

/* ── Search bar ── */
.search-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 24px !important;
  border-bottom: 1px solid #222;
  background: #161616;
}
.search-input-wrap {
  flex: 1;
  display: flex;
  align-items: center;
  background: #1C1C1C;
  border: 1px solid #333;
  border-radius: 6px;
  padding: 0 12px !important;
  transition: border-color 0.2s;
}
.search-input-wrap:focus-within {
  border-color: #E8613A;
}
.search-icon {
  font-size: 12px;
  margin-right: 8px !important;
  opacity: 0.5;
}
.search-input {
  flex: 1;
  background: none;
  border: none;
  color: #F5F5F5;
  font-size: 13px;
  font-family: inherit;
  padding: 8px 0 !important;
  outline: none;
}
.search-input::placeholder { color: #555; }
.search-clear {
  background: none;
  border: none;
  color: #777;
  font-size: 18px;
  cursor: pointer;
  padding: 0 4px !important;
  line-height: 1;
}
.search-clear:hover { color: #E8613A; }

.search-modes {
  display: flex;
  gap: 4px;
}
.mode-btn {
  display: flex;
  align-items: center;
  gap: 4px;
  background: #1C1C1C;
  border: 1px solid #333;
  border-radius: 4px;
  color: #888;
  font-size: 11px;
  font-family: inherit;
  padding: 6px 10px !important;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}
.mode-btn:hover { border-color: #555; color: #CCC; }
.mode-active {
  background: #E8613A18;
  border-color: #E8613A;
  color: #E8613A;
}
.mode-icon { font-weight: 700; font-size: 11px; }
.mode-label { font-size: 10px; }

/* ── Search chips ── */
.search-chips {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 24px !important;
  border-bottom: 1px solid #222;
  background: #131313;
  overflow-x: auto;
}
.chips-label { font-size: 10px; color: #555; white-space: nowrap; }
.chip {
  font-size: 11px;
  font-family: inherit;
  color: #AAA;
  background: #1C1C1C;
  border: 1px solid #333;
  border-radius: 12px;
  padding: 4px 12px !important;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}
.chip:hover { border-color: #E8613A; color: #E8613A; }
.chip-active { background: #E8613A18; border-color: #E8613A; color: #E8613A; }

/* ── Results bar ── */
.results-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 24px !important;
  border-bottom: 1px solid #222;
  background: #161616;
}
.results-left { display: flex; align-items: center; gap: 12px; }
.results-count { font-size: 12px; color: #E8613A; font-weight: 600; }
.results-dim { color: #555; font-weight: 400; }
.results-timing { font-size: 10px; color: #28C840; }
.results-right { display: flex; align-items: center; }
.sparkline-svg { width: 120px; height: 24px; }

/* ── Grid ── */
.grid-container {
  max-height: 500px;
  overflow-y: auto;
  overflow-x: hidden;
}
.grid-header {
  display: grid;
  grid-template-columns: 160px 110px 50px 110px 1fr;
  padding: 8px 16px !important;
  border-bottom: 1px solid #222;
  background: #1C1C1C;
  position: sticky;
  top: 0;
  z-index: 5;
}
.grid-header-cell {
  font-size: 9px;
  color: #777;
  letter-spacing: 1.2px;
  font-weight: 600;
  line-height: 1;
  background: none;
  border: none;
  font-family: inherit;
  cursor: pointer;
  text-align: left;
  padding: 4px 0 !important;
  display: flex;
  align-items: center;
  gap: 4px;
  transition: color 0.15s;
  white-space: nowrap;
}
.grid-header-cell:hover { color: #CCC; }
.sort-active { color: #E8613A !important; }
.sort-arrow { font-size: 8px; }
.sort-inactive { opacity: 0.2; }

.grid-body { position: relative; }
.grid-row {
  display: grid;
  grid-template-columns: 160px 110px 50px 110px 1fr;
  padding: 5px 16px !important;
  border-bottom: 1px solid #1A1A1A;
  border-left: 2px solid transparent;
  cursor: pointer;
  transition: all 0.2s ease;
  align-items: center;
  opacity: 0;
  transform: translateX(-8px);
}
.row-animate {
  opacity: 1;
  transform: translateX(0);
}
.grid-row:hover { background: #1C1C1C; }
.row-critical {
  background: #E8613A08;
  border-left-color: #E8613A;
}
.row-high {
  border-left-color: #FFB020;
}
.row-expanded {
  background: #1A1A1A;
  border-left-color: #E8613A;
}

.grid-cell {
  font-size: 11px;
  line-height: 1.3;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.col-timestamp { color: #AAA; font-variant-numeric: tabular-nums; }
.col-source { color: #6BA3E8; }
.col-eventid { color: #888; }
.col-computer { color: #9B59B6; }
.col-detail { display: flex; align-items: center; color: #CCC; min-width: 0; }
.col-detail span:last-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.severity-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  margin-right: 8px;
  flex-shrink: 0;
}
.sev-critical { background: #FF3B3B; }
.sev-high { background: #E8613A; }
.sev-medium { background: #FFB020; }
.sev-low { background: #888; }

/* ── Highlight ── */
.demo-graphic :deep(.hl) {
  background: #E8613A33;
  color: #E8613A;
  border-radius: 2px;
  padding: 0 1px !important;
}

/* ── Row detail (expansion) ── */
.row-detail {
  padding: 8px 16px 12px 32px !important;
  background: #151515;
  border-bottom: 1px solid #222;
  border-left: 2px solid #E8613A;
}
.detail-field {
  display: flex;
  gap: 12px;
  padding: 3px 0 !important;
  font-size: 11px;
}
.detail-label {
  color: #555;
  min-width: 80px;
  font-weight: 600;
}
.sev-badge {
  font-size: 9px;
  padding: 1px 8px !important;
  border-radius: 3px;
  font-weight: 600;
  text-transform: uppercase;
}
.sev-badge-critical { color: #FF3B3B; background: #FF3B3B18; }
.sev-badge-high { color: #E8613A; background: #E8613A18; }
.sev-badge-medium { color: #FFB020; background: #FFB02018; }
.sev-badge-low { color: #888; background: #88888818; }

/* ── Empty state ── */
.grid-empty {
  padding: 40px 24px !important;
  text-align: center;
  color: #555;
  font-size: 13px;
}

/* ── Status bar ── */
.demo-status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 24px !important;
  border-top: 1px solid #222;
  background: #161616;
}
.status-left, .status-right { display: flex; align-items: center; gap: 16px; }
.status-right { gap: 12px; }
.status-item { font-size: 9px; color: #777; line-height: 1; white-space: nowrap; }
.status-green { color: #28C840; margin-right: 4px !important; }
.status-accent { font-size: 9px; color: #E8613A; line-height: 1; white-space: nowrap; }

/* ── Lateral Movement Tracker ── */
.lateral-section {
  border-top: 1px solid #222;
  transition: all 0.6s ease;
}
.lateral-header {
  padding: 16px 24px 12px !important;
  background: #161616;
  border-bottom: 1px solid #222;
}
.lateral-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}
.lateral-title {
  font-size: 10px;
  color: #777;
  letter-spacing: 1.5px;
  font-weight: 600;
  line-height: 1;
}
.lateral-badge {
  font-size: 9px;
  padding: 3px 10px !important;
  border-radius: 3px;
  line-height: 1;
  font-weight: 600;
}
.badge-red {
  color: #FF3B3B;
  background: #FF3B3B15;
  animation: badge-pulse 2s ease-in-out infinite;
}
@keyframes badge-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}
.lateral-stats {
  display: flex;
  gap: 0;
}
.lat-stat {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 6px 12px !important;
  border-right: 1px solid #222;
}
.lat-stat:last-child { border-right: none; }
.lat-stat-val {
  font-size: 16px;
  font-weight: 600;
  line-height: 1.2;
}
.lat-stat-danger {
  color: #FF3B3B;
}
.lat-stat-label {
  font-size: 8px;
  color: #555;
  letter-spacing: 1.2px;
  line-height: 1;
}

.lateral-graph-wrap {
  padding: 8px 16px !important;
  background: #0D0D0D;
  border-bottom: 1px solid #222;
}
.lateral-svg {
  width: 100%;
  max-height: 260px;
}

/* Outlier pulse animation */
.outlier-pulse {
  animation: outlier-ring 2s ease-in-out infinite;
}
@keyframes outlier-ring {
  0%, 100% { stroke-opacity: 0.5; r: 26; }
  50% { stroke-opacity: 0.9; r: 29; }
}

/* Finding callout */
.lateral-finding {
  display: flex;
  gap: 12px;
  padding: 14px 24px !important;
  background: #FF3B3B08;
  border-bottom: 1px solid #FF3B3B22;
  border-left: 3px solid #FF3B3B;
}
.finding-icon {
  font-size: 18px;
  flex-shrink: 0;
  line-height: 1.2;
}
.finding-content { flex: 1; }
.finding-title {
  font-size: 11px;
  color: #CCC;
  font-weight: 600;
  margin-bottom: 6px;
  line-height: 1.4;
}
.finding-sev {
  font-size: 9px;
  color: #FF3B3B;
  background: #FF3B3B18;
  padding: 2px 6px !important;
  border-radius: 2px;
  font-weight: 700;
  margin-right: 8px !important;
  vertical-align: middle;
}
.finding-detail {
  font-size: 11px;
  color: #888;
  line-height: 1.5;
  margin-bottom: 10px;
}
.finding-hl {
  color: #E8613A;
  font-weight: 600;
}

/* Attack chain display */
.finding-chain {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.chain-label {
  font-size: 8px;
  color: #555;
  letter-spacing: 1px;
  margin-right: 4px !important;
}
.chain-node {
  font-size: 10px;
  padding: 2px 8px !important;
  border-radius: 3px;
  font-weight: 600;
}
.chain-outlier { color: #FF3B3B; background: #FF3B3B18; border: 1px solid #FF3B3B33; }
.chain-pivot { color: #a371f7; background: #a371f712; border: 1px solid #a371f733; }
.chain-dc { color: #58a6ff; background: #58a6ff12; border: 1px solid #58a6ff33; }
.chain-srv { color: #3fb950; background: #3fb95012; border: 1px solid #3fb95033; }
.chain-arrow { color: #555; font-size: 12px; }

/* Detection patterns */
.lateral-patterns {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 24px !important;
  background: #131313;
  border-bottom: 1px solid #222;
  flex-wrap: wrap;
}
.patterns-title {
  font-size: 8px;
  color: #555;
  letter-spacing: 1.2px;
  white-space: nowrap;
}
.patterns-grid {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.pattern-chip {
  font-size: 10px;
  color: #777;
  background: #1C1C1C;
  border: 1px solid #333;
  border-radius: 3px;
  padding: 2px 8px !important;
  font-family: inherit;
}
.pattern-match {
  color: #FF3B3B;
  background: #FF3B3B12;
  border-color: #FF3B3B44;
  font-weight: 600;
}

/* ── Responsive ── */
@media (max-width: 960px) {
  .grid-header, .grid-row {
    grid-template-columns: 160px 110px 50px 1fr;
  }
  .col-computer { display: none; }
  .mode-label { display: none; }
  .mode-btn { padding: 6px 8px !important; }
  .demo-graphic { border-radius: 8px; }
  .lateral-stats { flex-wrap: wrap; }
  .lat-stat { min-width: 70px; }
}

@media (max-width: 640px) {
  .lateral-finding { flex-direction: column; gap: 6px; }
  .lateral-stats { display: grid; grid-template-columns: 1fr 1fr; }
  .lateral-patterns { overflow-x: auto; flex-wrap: nowrap; }
  .title-text { display: none; }
  .grid-header, .grid-row {
    grid-template-columns: 130px 1fr;
  }
  .col-source, .col-eventid, .col-computer { display: none; }
  .search-bar { flex-direction: column; gap: 8px; }
  .search-modes { width: 100%; justify-content: center; }
  .search-chips { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .demo-status-bar { flex-direction: column; gap: 4px; }
  .status-left, .status-right { width: 100%; justify-content: center; }
  .sparkline-svg { display: none; }
}

/* ── Accessibility ── */
@media (prefers-reduced-motion: reduce) {
  .scan-line { display: none; }
  .grid-row { transition: none !important; opacity: 1 !important; transform: none !important; }
  .lateral-section { transition: none !important; opacity: 1 !important; transform: none !important; }
  .outlier-pulse { animation: none !important; }
  .badge-red { animation: none !important; }
}

/* ── Scrollbar ── */
.grid-container::-webkit-scrollbar { width: 6px; }
.grid-container::-webkit-scrollbar-track { background: #0D0D0D; }
.grid-container::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
.grid-container::-webkit-scrollbar-thumb:hover { background: #555; }
</style>
