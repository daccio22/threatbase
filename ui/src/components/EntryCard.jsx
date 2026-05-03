import { SOURCE_CONFIG, cvssColor } from '../sourceConfig.js'

const RANK_COLOR = {
  critical: '#dc2626',
  high: '#d97706',
  medium: '#2563eb',
  low: '#6b7280',
}

export default function EntryCard({ entry, onClick, onCompare, inCompare }) {
  const cfg = SOURCE_CONFIG[entry.source] || SOURCE_CONFIG['ATT&CK']
  const desc = entry.description?.replace(/\n/g, ' ').slice(0, 180)
  const scoreColor = RANK_COLOR[entry.connection_rank] || '#6b7280'

  return (
    <div className="relative group">
      <button
        onClick={() => onClick(entry)}
        className="w-full text-left bg-gray-800/60 border border-gray-700 rounded-xl p-4 hover:border-gray-500 hover:bg-gray-800 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
      >
        <div className="flex items-start justify-between gap-2 mb-2">
          <span
            className="text-xs font-bold px-2 py-0.5 rounded-full shrink-0"
            style={{ backgroundColor: cfg.hex + '25', color: cfg.hex }}
          >
            {entry.source}
          </span>
          <div className="flex items-center gap-1.5 shrink-0">
            {entry.source === 'CVE' && entry.cvss_score != null && (
              <span
                className="text-xs font-bold px-2 py-0.5 rounded-full text-white"
                style={{ backgroundColor: cvssColor(entry.cvss_score) }}
              >
                {entry.cvss_score.toFixed(1)} {entry.cvss_severity}
              </span>
            )}
            {entry.connection_score != null && (
              <span
                className="text-[10px] font-mono px-1.5 py-0.5 rounded border flex items-center gap-0.5"
                style={{ color: scoreColor, borderColor: scoreColor + '60', backgroundColor: scoreColor + '15' }}
                title={`Connectivity: ${entry.connection_score}/100 (${entry.connection_rank})`}
              >
                ⇄ {entry.connection_score}
              </span>
            )}
          </div>
        </div>

        <div className="font-mono text-xs text-gray-400 mb-1">{entry.id}</div>
        <div className="font-semibold text-gray-100 text-sm leading-snug mb-2 group-hover:text-white">
          {entry.name || entry.description?.slice(0, 120)}
        </div>

        {desc && (
          <p className="text-xs text-gray-400 leading-relaxed line-clamp-3">{desc}</p>
        )}

        {entry.tags?.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {entry.tags.slice(0, 4).map(tag => (
              <span key={tag} className="text-xs bg-gray-700/60 text-gray-400 px-1.5 py-0.5 rounded">{tag}</span>
            ))}
            {entry.tags.length > 4 && (
              <span className="text-xs text-gray-500">+{entry.tags.length - 4}</span>
            )}
          </div>
        )}
      </button>

      {/* Compare button */}
      {onCompare && (
        <button
          onClick={e => { e.stopPropagation(); onCompare(entry) }}
          className={`absolute top-2 right-2 w-5 h-5 rounded text-xs font-bold flex items-center justify-center transition-all z-10
            ${inCompare
              ? 'bg-indigo-600 text-white opacity-100'
              : 'bg-gray-700 text-gray-400 opacity-0 group-hover:opacity-100 hover:bg-gray-600 hover:text-white'
            }`}
          title={inCompare ? 'Remove from compare' : 'Add to compare'}
        >
          {inCompare ? '✓' : '+'}
        </button>
      )}
    </div>
  )
}
