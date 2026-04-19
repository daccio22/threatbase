import { useMemo, useState } from 'react'
import { SOURCE_CONFIG } from '../sourceConfig.js'

const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

const SOURCES = ['CVE', 'CWE', 'D3FEND', 'SPARTA', 'ESA SHIELD']

function computeHeatmap(entries) {
  // ATT&CK id → tactics
  const attackTactics = {}
  for (const e of entries) {
    if (e.source === 'ATT&CK' && e.tactics?.length) {
      attackTactics[e.id] = e.tactics
    }
  }

  function entryTactics(entry) {
    if (entry.source === 'ATT&CK') return entry.tactics || []
    const t = new Set()
    for (const refId of entry.cross_refs || []) {
      const ts = attackTactics[refId]
      if (ts) ts.forEach(x => t.add(x))
    }
    return [...t]
  }

  const counts = {}
  const entryIds = {}
  for (const src of SOURCES) {
    counts[src] = {}
    entryIds[src] = {}
    for (const tactic of TACTICS) {
      counts[src][tactic] = 0
      entryIds[src][tactic] = []
    }
  }

  for (const entry of entries) {
    if (!SOURCES.includes(entry.source)) continue
    const tactics = entryTactics(entry)
    for (const tactic of tactics) {
      if (!TACTICS.includes(tactic)) continue
      counts[entry.source][tactic]++
      entryIds[entry.source][tactic].push(entry.id)
    }
  }

  return { counts, entryIds }
}

function cellColor(count, maxCount, sourceHex, isGap) {
  if (isGap) return '#7f1d1d'
  if (count === 0) return '#111827'
  const intensity = Math.min(1, count / Math.max(maxCount, 1))
  const alpha = Math.round(15 + intensity * 220)
  const alphaHex = alpha.toString(16).padStart(2, '0')
  return sourceHex + alphaHex
}

export default function CoverageHeatmap({ entries, onFilter }) {
  const [showGaps, setShowGaps] = useState(false)
  const { counts, entryIds } = useMemo(() => computeHeatmap(entries), [entries])

  const maxBySource = useMemo(() => {
    const m = {}
    for (const src of SOURCES) {
      m[src] = Math.max(1, ...Object.values(counts[src] || {}))
    }
    return m
  }, [counts])

  function handleCellClick(source, tactic) {
    const ids = entryIds[source]?.[tactic] || []
    if (ids.length && onFilter) onFilter(ids)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-bold text-white">Coverage Map</h2>
          <p className="text-xs text-gray-500 mt-0.5">Entries per source mapped to each ATT&CK tactic</p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer select-none text-sm text-gray-400">
          <div
            onClick={() => setShowGaps(v => !v)}
            className={`relative w-10 h-5 rounded-full transition-colors ${showGaps ? 'bg-red-700' : 'bg-gray-700'}`}
          >
            <div className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${showGaps ? 'translate-x-5' : ''}`} />
          </div>
          Highlight undefended gaps
        </label>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs border-collapse min-w-[600px]">
          <thead>
            <tr>
              <th className="text-left text-gray-500 py-2 pr-3 font-medium w-40">Tactic</th>
              {SOURCES.map(src => (
                <th key={src} className="text-center py-2 px-1 font-medium" style={{ color: SOURCE_CONFIG[src]?.hex }}>
                  {src}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {TACTICS.map(tactic => (
              <tr key={tactic} className="border-t border-gray-800">
                <td className="text-gray-400 py-1.5 pr-3 text-[11px] font-medium">{tactic}</td>
                {SOURCES.map(src => {
                  const count = counts[src]?.[tactic] ?? 0
                  const hex = SOURCE_CONFIG[src]?.hex || '#6b7280'
                  const isGap = showGaps && src === 'D3FEND' && count === 0
                  const bg = cellColor(count, maxBySource[src], hex, isGap)
                  return (
                    <td
                      key={src}
                      className="text-center py-1 px-1"
                    >
                      <button
                        onClick={() => count > 0 && handleCellClick(src, tactic)}
                        disabled={count === 0}
                        className="w-full rounded text-[11px] font-mono py-1 transition-all hover:opacity-80 disabled:cursor-default"
                        style={{
                          backgroundColor: bg,
                          color: count === 0 ? '#374151' : '#e5e7eb',
                          minWidth: '36px',
                        }}
                        title={count > 0 ? `${count} ${src} entries mapped to ${tactic} — click to filter` : `No ${src} entries`}
                      >
                        {count || '—'}
                      </button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex flex-wrap gap-3 pt-2">
        {SOURCES.map(src => (
          <div key={src} className="flex items-center gap-1.5 text-xs text-gray-400">
            <div className="w-3 h-3 rounded" style={{ backgroundColor: SOURCE_CONFIG[src]?.hex }} />
            {src}
          </div>
        ))}
        {showGaps && (
          <div className="flex items-center gap-1.5 text-xs text-red-400">
            <div className="w-3 h-3 rounded bg-red-900" />
            No D3FEND coverage
          </div>
        )}
      </div>
    </div>
  )
}
