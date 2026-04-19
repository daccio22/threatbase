import { useMemo, useState } from 'react'
import { SOURCE_CONFIG, cvssColor } from '../sourceConfig.js'

function buildKillChain(entry, entryMap) {
  function bySource(ids, source) {
    return (ids || []).map(id => entryMap[id]).filter(e => e?.source === source)
  }
  function crossBySource(e, source) {
    return bySource(e?.cross_refs || [], source)
  }
  function dedup(arr) {
    return [...new Map(arr.filter(Boolean).map(e => [e.id, e])).values()]
  }

  let cves = [], cwes = [], techniques = [], defenses = []

  if (entry.source === 'CVE') {
    cves = [entry]
    cwes = crossBySource(entry, 'CWE')
    techniques = dedup(cwes.flatMap(c => crossBySource(c, 'ATT&CK')))
    defenses = dedup(techniques.flatMap(t => crossBySource(t, 'D3FEND')))
  } else if (entry.source === 'ATT&CK') {
    techniques = [entry]
    cves = crossBySource(entry, 'CVE')
    cwes = dedup(cves.flatMap(c => crossBySource(c, 'CWE')))
    defenses = crossBySource(entry, 'D3FEND')
  } else if (entry.source === 'CWE') {
    cwes = [entry]
    cves = crossBySource(entry, 'CVE')
    techniques = dedup([
      ...crossBySource(entry, 'ATT&CK'),
      ...cves.flatMap(c => crossBySource(c, 'ATT&CK')),
    ])
    defenses = dedup(techniques.flatMap(t => crossBySource(t, 'D3FEND')))
  } else if (entry.source === 'D3FEND') {
    defenses = [entry]
    techniques = crossBySource(entry, 'ATT&CK')
    cves = dedup(techniques.flatMap(t => crossBySource(t, 'CVE')))
    cwes = dedup(cves.flatMap(c => crossBySource(c, 'CWE')))
  } else if (entry.source === 'SPARTA') {
    techniques = crossBySource(entry, 'ATT&CK')
    cves = dedup(techniques.flatMap(t => crossBySource(t, 'CVE')))
    cwes = dedup(cves.flatMap(c => crossBySource(c, 'CWE')))
    defenses = dedup(techniques.flatMap(t => crossBySource(t, 'D3FEND')))
  } else {
    // ESA SHIELD or other
    techniques = crossBySource(entry, 'ATT&CK')
    cves = dedup(techniques.flatMap(t => crossBySource(t, 'CVE')))
    cwes = dedup(cves.flatMap(c => crossBySource(c, 'CWE')))
    defenses = dedup(techniques.flatMap(t => crossBySource(t, 'D3FEND')))
  }

  return { cves: dedup(cves), cwes: dedup(cwes), techniques: dedup(techniques), defenses: dedup(defenses) }
}

const COLUMNS = [
  { key: 'cves',       source: 'CVE',     label: 'VULNERABILITY' },
  { key: 'cwes',       source: 'CWE',     label: 'WEAKNESS' },
  { key: 'techniques', source: 'ATT&CK',  label: 'TECHNIQUE' },
  { key: 'defenses',   source: 'D3FEND',  label: 'DEFENSE' },
]

function KillChainColumn({ label, source, entries, onSelect }) {
  const [expanded, setExpanded] = useState(false)
  const cfg = SOURCE_CONFIG[source]
  const visible = expanded ? entries : entries.slice(0, 5)
  const more = entries.length - 5

  return (
    <div className="flex-1 min-w-0">
      <div
        className="text-[10px] font-bold text-center mb-2 py-1 rounded tracking-wide"
        style={{ backgroundColor: cfg?.hex + '25', color: cfg?.hex }}
      >
        {label}
      </div>
      <div className="space-y-1.5">
        {entries.length === 0 ? (
          <div className="text-[10px] text-gray-600 text-center py-3 bg-gray-800/30 rounded border border-gray-700/50">
            None found
          </div>
        ) : (
          <>
            {visible.map(e => (
              <button
                key={e.id}
                onClick={() => onSelect(e)}
                className="w-full text-left text-xs p-1.5 rounded border transition-all hover:scale-[1.02]"
                style={{ backgroundColor: cfg?.hex + '18', borderColor: cfg?.hex + '50', color: '#d1d5db' }}
              >
                <div className="font-mono text-gray-400 text-[9px] truncate">{e.id}</div>
                <div className="truncate text-[10px] leading-tight mt-0.5">{e.name}</div>
                {e.source === 'CVE' && e.cvss_score != null && (
                  <div className="text-[9px] mt-0.5" style={{ color: cvssColor(e.cvss_score) }}>
                    CVSS {e.cvss_score.toFixed(1)}
                  </div>
                )}
              </button>
            ))}
            {!expanded && more > 0 && (
              <button
                onClick={() => setExpanded(true)}
                className="w-full text-[10px] text-center text-gray-500 hover:text-gray-300 py-1 transition-colors"
              >
                +{more} more
              </button>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function Arrow() {
  return (
    <div className="flex items-start justify-center shrink-0 pt-8 text-gray-600">
      <svg viewBox="0 0 24 24" className="w-4 h-4" fill="none" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5l7 7-7 7" />
      </svg>
    </div>
  )
}

export default function KillChainView({ entry, entryMap, onSelect }) {
  const chain = useMemo(() => buildKillChain(entry, entryMap), [entry, entryMap])
  const [copied, setCopied] = useState(false)

  function exportMarkdown() {
    const cve = chain.cves[0]
    const cwe = chain.cwes[0]
    const tech = chain.techniques[0]
    const lines = [
      `## Kill Chain: ${entry.id} — ${entry.name}`,
      '',
      `**Vulnerability:** ${cve ? `${cve.id} — ${cve.name}${cve.cvss_score != null ? ` (CVSS ${cve.cvss_score})` : ''}` : 'N/A'}`,
      `**Weakness:** ${cwe ? `${cwe.id} — ${cwe.name}` : 'N/A'}`,
      `**Technique:** ${tech ? `${tech.id} — ${tech.name}` : 'N/A'}`,
      `**Defenses:** ${chain.defenses.length > 0 ? chain.defenses.slice(0, 5).map(d => `${d.id} (${d.name})`).join(', ') : 'N/A'}`,
    ]
    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const hasData = COLUMNS.some(c => chain[c.key].length > 0)

  return (
    <section>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Kill Chain</h3>
        <button
          onClick={exportMarkdown}
          className="text-[10px] text-gray-500 hover:text-gray-300 transition-colors border border-gray-700 rounded px-2 py-0.5"
        >
          {copied ? '✓ Copied' : 'Export ↗'}
        </button>
      </div>
      {!hasData ? (
        <p className="text-xs text-gray-600">No connected entries found to trace a kill chain.</p>
      ) : (
        <div className="flex items-start gap-1">
          {COLUMNS.map((col, i) => (
            <div key={col.key} className="contents">
              {i > 0 && <Arrow />}
              <KillChainColumn
                label={col.label}
                source={col.source}
                entries={chain[col.key]}
                onSelect={onSelect}
              />
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
