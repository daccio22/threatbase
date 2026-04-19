import { useState, useEffect, useMemo } from 'react'
import { SOURCE_CONFIG, cvssColor } from '../sourceConfig.js'

function fieldRows(entry) {
  const rows = []
  const add = (label, value) => { if (value) rows.push({ label, value }) }
  add('Source', entry.source)
  add('ID', entry.id)
  add('Name', entry.name)
  add('Description', entry.description?.slice(0, 300) + (entry.description?.length > 300 ? '…' : ''))
  if (entry.source === 'CVE') {
    add('CVSS Score', entry.cvss_score != null ? `${entry.cvss_score} (${entry.cvss_severity})` : null)
    add('Published', entry.published ? new Date(entry.published).toLocaleDateString() : null)
    add('CWE IDs', entry.cwe_ids?.join(', '))
  }
  if (entry.source === 'ATT&CK') {
    add('Tactics', entry.tactics?.join(', '))
    add('Platforms', entry.platforms?.join(', '))
  }
  if (entry.source === 'CWE') {
    add('Platforms', entry.platforms?.join(', '))
  }
  if (entry.source === 'D3FEND') {
    add('Category', entry.category)
    add('Counters ATT&CK', entry.counters_attack_ids?.join(', '))
  }
  if (entry.source === 'SPARTA') {
    add('Tactic', entry.tactic)
    add('ATT&CK Mappings', entry.attack_ids?.join(', '))
  }
  if (entry.source === 'ESA SHIELD') {
    add('Category', entry.category)
    add('Related SPARTA', entry.related_sparta_ids?.join(', '))
    add('Related ATT&CK', entry.related_attack_ids?.join(', '))
  }
  add('Tags', entry.tags?.join(', '))
  add('Connections', entry.cross_refs?.length?.toString())
  add('Connection Score', entry.connection_score != null ? `${entry.connection_score}/100 (${entry.connection_rank})` : null)
  return rows
}

export default function CompareView({ entries, entryMap, onClose, onSelect }) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    function onKey(e) { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const [a, b] = entries
  const aRows = useMemo(() => fieldRows(a), [a])
  const bRows = useMemo(() => fieldRows(b), [b])

  const allLabels = useMemo(() => {
    const set = new Set([...aRows.map(r => r.label), ...bRows.map(r => r.label)])
    return [...set]
  }, [aRows, bRows])

  const aMap = Object.fromEntries(aRows.map(r => [r.label, r.value]))
  const bMap = Object.fromEntries(bRows.map(r => [r.label, r.value]))

  const sharedConnections = useMemo(() => {
    const aRefs = new Set(a.cross_refs || [])
    const bRefs = new Set(b.cross_refs || [])
    return [...aRefs].filter(id => bRefs.has(id)).map(id => entryMap[id]).filter(Boolean)
  }, [a, b, entryMap])

  const aCfg = SOURCE_CONFIG[a.source]
  const bCfg = SOURCE_CONFIG[b.source]

  function exportMarkdown() {
    const lines = [
      `## Comparison: ${a.id} vs ${b.id}`,
      '',
      `| Field | ${a.id} | ${b.id} |`,
      `|-------|${'-'.repeat(a.id.length + 2)}|${'-'.repeat(b.id.length + 2)}|`,
      ...allLabels.map(label => `| ${label} | ${aMap[label] || '—'} | ${bMap[label] || '—'} |`),
      '',
      `### Shared Connections (${sharedConnections.length})`,
      ...sharedConnections.slice(0, 10).map(e => `- ${e.id}: ${e.name}`),
    ]
    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="fixed inset-0 z-50 bg-gray-950/95 overflow-y-auto">
      <div className="max-w-5xl mx-auto px-4 py-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-bold text-white">Side-by-Side Comparison</h2>
          <div className="flex items-center gap-3">
            <button
              onClick={exportMarkdown}
              className="text-xs border border-gray-700 rounded px-3 py-1.5 text-gray-400 hover:text-white transition-colors"
            >
              {copied ? '✓ Copied' : 'Export comparison'}
            </button>
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-white transition-colors"
              aria-label="Close"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Column headers */}
        <div className="grid grid-cols-[180px_1fr_1fr] gap-3 mb-1">
          <div />
          {[a, b].map((e, i) => {
            const cfg = i === 0 ? aCfg : bCfg
            return (
              <div
                key={e.id}
                className="p-3 rounded-xl border"
                style={{ borderColor: cfg?.hex + '60', backgroundColor: cfg?.hex + '15' }}
              >
                <div className="text-xs font-bold mb-0.5" style={{ color: cfg?.hex }}>{e.source}</div>
                <div className="font-mono text-xs text-gray-400">{e.id}</div>
                <div className="font-semibold text-gray-100 text-sm mt-0.5 leading-snug">{e.name}</div>
              </div>
            )
          })}
        </div>

        {/* Field rows */}
        <div className="space-y-0.5">
          {allLabels.map(label => {
            const av = aMap[label]
            const bv = bMap[label]
            const same = av && bv && av === bv
            return (
              <div key={label} className="grid grid-cols-[180px_1fr_1fr] gap-3 py-1.5 border-b border-gray-800/50">
                <div className="text-[11px] font-semibold text-gray-500 uppercase tracking-wide self-start pt-0.5">
                  {label}
                </div>
                {[av, bv].map((val, i) => (
                  <div
                    key={i}
                    className="text-sm rounded px-2 py-0.5"
                    style={
                      same
                        ? { backgroundColor: '#14532d33', color: '#86efac' }
                        : val
                        ? { color: '#d1d5db' }
                        : { color: '#4b5563' }
                    }
                  >
                    {val || '—'}
                  </div>
                ))}
              </div>
            )
          })}
        </div>

        {/* Shared connections */}
        <div className="mt-6">
          <h3 className="text-sm font-semibold text-gray-300 mb-3">
            Shared Connections ({sharedConnections.length})
          </h3>
          {sharedConnections.length === 0 ? (
            <p className="text-xs text-gray-600">No shared connections.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {sharedConnections.map(e => {
                const cfg = SOURCE_CONFIG[e.source]
                return (
                  <button
                    key={e.id}
                    onClick={() => onSelect(e)}
                    className="text-xs px-2 py-1 rounded-lg border transition-all hover:scale-105"
                    style={{ backgroundColor: cfg?.hex + '20', borderColor: cfg?.hex + '60', color: cfg?.hex }}
                    title={e.name}
                  >
                    {e.id}
                  </button>
                )
              })}
            </div>
          )}
        </div>

        {/* Unique connections side by side */}
        <div className="grid grid-cols-2 gap-4 mt-6">
          {[a, b].map((e, i) => {
            const cfg = i === 0 ? aCfg : bCfg
            const other = i === 0 ? b : a
            const otherRefs = new Set(other.cross_refs || [])
            const unique = (e.cross_refs || []).filter(id => !otherRefs.has(id)).map(id => entryMap[id]).filter(Boolean)
            return (
              <div key={e.id}>
                <h4 className="text-xs font-semibold mb-2" style={{ color: cfg?.hex }}>
                  Unique to {e.id} ({unique.length})
                </h4>
                <div className="flex flex-wrap gap-1.5">
                  {unique.slice(0, 15).map(rel => {
                    const rc = SOURCE_CONFIG[rel.source]
                    return (
                      <button
                        key={rel.id}
                        onClick={() => onSelect(rel)}
                        className="text-[10px] px-1.5 py-0.5 rounded border transition-all hover:scale-105"
                        style={{ backgroundColor: rc?.hex + '20', borderColor: rc?.hex + '60', color: rc?.hex }}
                        title={rel.name}
                      >
                        {rel.id}
                      </button>
                    )
                  })}
                  {unique.length > 15 && (
                    <span className="text-[10px] text-gray-500 self-center">+{unique.length - 15} more</span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
