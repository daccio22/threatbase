import { useState, useEffect, useMemo } from 'react'
import RelatedChips from './RelatedChips.jsx'
import GraphView from './GraphView.jsx'
import { SOURCE_CONFIG, cvssColor } from '../sourceConfig.js'

export default function DetailPanel({ entry, entryMap, onClose, onSelect }) {
  const [graphOpen, setGraphOpen] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => { setGraphOpen(false) }, [entry?.id])

  useEffect(() => {
    function onKey(e) { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  if (!entry) return null
  const cfg = SOURCE_CONFIG[entry.source] || SOURCE_CONFIG['ATT&CK']

  function copyId() {
    navigator.clipboard.writeText(entry.id)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <>
      {/* Backdrop (mobile) */}
      <div
        className="fixed inset-0 bg-black/50 z-30 lg:hidden"
        onClick={onClose}
      />

      <aside className="fixed right-0 top-0 h-full w-full max-w-xl bg-gray-900 border-l border-gray-700 z-40 flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-start gap-3 p-4 border-b border-gray-700">
          <span
            className="text-xs font-bold px-2 py-0.5 rounded-full mt-0.5 shrink-0"
            style={{ backgroundColor: cfg.hex + '25', color: cfg.hex }}
          >
            {entry.source}
          </span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs text-gray-400">{entry.id}</span>
              <button
                onClick={copyId}
                className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
                title="Copy ID"
              >
                {copied ? '✓ copied' : 'copy'}
              </button>
            </div>
            <h2 className="font-semibold text-gray-100 leading-snug mt-0.5">{entry.name}</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-200 transition-colors shrink-0"
            aria-label="Close panel"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto scrollbar-thin p-4 space-y-4">
          {/* CVSS badge for CVE */}
          {entry.source === 'CVE' && entry.cvss_score != null && (
            <div className="flex gap-3 flex-wrap">
              <span
                className="px-3 py-1 rounded-full text-sm font-bold text-white"
                style={{ backgroundColor: cvssColor(entry.cvss_score) }}
              >
                CVSS {entry.cvss_score.toFixed(1)} — {entry.cvss_severity}
              </span>
              {entry.cvss_vector && (
                <span className="font-mono text-xs text-gray-400 self-center">{entry.cvss_vector}</span>
              )}
            </div>
          )}

          {/* Description */}
          <section>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Description</h3>
            <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-line">{entry.description}</p>
          </section>

          {/* Source-specific fields */}
          <SourceFields entry={entry} />

          {/* Tags */}
          {entry.tags?.length > 0 && (
            <section>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Tags</h3>
              <div className="flex flex-wrap gap-1.5">
                {entry.tags.map(tag => (
                  <span key={tag} className="text-xs bg-gray-700/60 text-gray-300 px-2 py-0.5 rounded">
                    {tag}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Cross-refs */}
          <RelatedChips crossRefs={entry.cross_refs} entryMap={entryMap} onSelect={onSelect} />

          {/* Graph toggle */}
          {entry.cross_refs?.length > 0 && (
            <section>
              <button
                onClick={() => setGraphOpen(v => !v)}
                className="text-xs text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1 transition-colors"
              >
                <svg className={`w-3.5 h-3.5 transition-transform ${graphOpen ? 'rotate-90' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
                {graphOpen ? 'Hide' : 'Show'} relationship graph
              </button>
              {graphOpen && <div className="mt-2"><GraphView entry={entry} entryMap={entryMap} /></div>}
            </section>
          )}

          {/* External link */}
          {entry.url && (
            <a
              href={entry.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-sm text-indigo-400 hover:text-indigo-300 transition-colors"
            >
              View on source
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
              </svg>
            </a>
          )}

          <div className="text-xs text-gray-600 pt-2">
            Last updated: {entry.last_updated ? new Date(entry.last_updated).toLocaleDateString() : '—'}
          </div>
        </div>
      </aside>
    </>
  )
}

function SourceFields({ entry }) {
  const { source } = entry
  if (source === 'ATT&CK') return (
    <div className="space-y-3">
      <Field label="Tactics" value={entry.tactics?.join(', ')} />
      <Field label="Platforms" value={entry.platforms?.join(', ')} />
      <Field label="Data Sources" value={entry.data_sources?.join(', ')} />
      {entry.detection && <Field label="Detection" value={entry.detection} />}
      {entry.mitigations?.length > 0 && (
        <Field label="Mitigations" value={entry.mitigations.join(' • ')} />
      )}
      {entry.subtechniques?.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Sub-techniques</div>
          <div className="flex flex-wrap gap-1.5">
            {entry.subtechniques.map(s => (
              <span key={s.id} className="text-xs bg-attack/20 text-purple-300 px-2 py-0.5 rounded">{s.id} {s.name}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )

  if (source === 'D3FEND') return (
    <div className="space-y-3">
      <Field label="Category" value={entry.category} />
      {entry.counters_attack_ids?.length > 0 && (
        <Field label="Counters ATT&CK" value={entry.counters_attack_ids.join(', ')} />
      )}
    </div>
  )

  if (source === 'CVE') return (
    <div className="space-y-3">
      {entry.cwe_ids?.length > 0 && <Field label="CWE IDs" value={entry.cwe_ids.join(', ')} />}
      <Field label="Published" value={entry.published ? new Date(entry.published).toLocaleDateString() : ''} />
      {entry.cpes?.length > 0 && <Field label="Affected CPEs" value={entry.cpes.join('\n')} mono />}
      {entry.references?.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">References</div>
          <ul className="space-y-1">
            {entry.references.map((r, i) => (
              <li key={i}>
                <a href={r} target="_blank" rel="noopener noreferrer"
                  className="text-xs text-indigo-400 hover:underline break-all">
                  {r}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )

  if (source === 'CWE') return (
    <div className="space-y-3">
      {entry.extended_description && <Field label="Extended Description" value={entry.extended_description} />}
      {entry.platforms?.length > 0 && <Field label="Platforms" value={entry.platforms.join(', ')} />}
      {entry.consequences?.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Consequences</div>
          <ul className="space-y-1 text-xs text-gray-300">
            {entry.consequences.slice(0, 5).map((c, i) => (
              <li key={i} className="flex gap-2">
                <span className="text-gray-500">{c.scopes?.join(', ')}</span>
                <span>{c.impacts?.join(', ')}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {entry.mitigations?.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Mitigations</div>
          <ul className="space-y-1">
            {entry.mitigations.slice(0, 3).map((m, i) => (
              <li key={i} className="text-xs text-gray-300">{m.slice(0, 200)}{m.length > 200 ? '…' : ''}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )

  if (source === 'SPARTA') return (
    <div className="space-y-3">
      <Field label="Tactic" value={entry.tactic} />
      {entry.attack_ids?.length > 0 && <Field label="ATT&CK Mappings" value={entry.attack_ids.join(', ')} />}
      {entry.countermeasures?.length > 0 && (
        <Field label="Countermeasures" value={entry.countermeasures.join(' • ')} />
      )}
    </div>
  )

  if (source === 'ESA SHIELD') return (
    <div className="space-y-3">
      <Field label="Category" value={entry.category} />
      {entry.related_sparta_ids?.length > 0 && (
        <Field label="Related SPARTA" value={entry.related_sparta_ids.join(', ')} />
      )}
      {entry.related_attack_ids?.length > 0 && (
        <Field label="Related ATT&CK" value={entry.related_attack_ids.join(', ')} />
      )}
      {entry.seed && (
        <div className="text-xs text-amber-400 bg-amber-900/20 border border-amber-700/50 rounded px-2 py-1">
          Seed data — upstream structured release pending from ESA
        </div>
      )}
    </div>
  )

  return null
}

function Field({ label, value, mono = false }) {
  if (!value) return null
  return (
    <div>
      <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-0.5">{label}</div>
      <p className={`text-sm text-gray-300 ${mono ? 'font-mono text-xs' : ''}`}>{value}</p>
    </div>
  )
}
