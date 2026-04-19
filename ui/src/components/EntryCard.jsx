import { SOURCE_CONFIG, cvssColor } from '../sourceConfig.js'

export default function EntryCard({ entry, onClick }) {
  const cfg = SOURCE_CONFIG[entry.source] || SOURCE_CONFIG['ATT&CK']
  const desc = entry.description?.replace(/\n/g, ' ').slice(0, 180)

  return (
    <button
      onClick={() => onClick(entry)}
      className="w-full text-left bg-gray-800/60 border border-gray-700 rounded-xl p-4 hover:border-gray-500 hover:bg-gray-800 transition-all group focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400"
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span
          className="text-xs font-bold px-2 py-0.5 rounded-full shrink-0"
          style={{ backgroundColor: cfg.hex + '25', color: cfg.hex }}
        >
          {entry.source}
        </span>
        {entry.source === 'CVE' && entry.cvss_score != null && (
          <span
            className="text-xs font-bold px-2 py-0.5 rounded-full text-white shrink-0"
            style={{ backgroundColor: cvssColor(entry.cvss_score) }}
          >
            {entry.cvss_score.toFixed(1)} {entry.cvss_severity}
          </span>
        )}
      </div>

      <div className="font-mono text-xs text-gray-400 mb-1">{entry.id}</div>
      <div className="font-semibold text-gray-100 text-sm leading-snug mb-2 group-hover:text-white">
        {entry.name}
      </div>

      {desc && (
        <p className="text-xs text-gray-400 leading-relaxed line-clamp-3">{desc}</p>
      )}

      {entry.tags?.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {entry.tags.slice(0, 4).map(tag => (
            <span key={tag} className="text-xs bg-gray-700/60 text-gray-400 px-1.5 py-0.5 rounded">
              {tag}
            </span>
          ))}
          {entry.tags.length > 4 && (
            <span className="text-xs text-gray-500">+{entry.tags.length - 4}</span>
          )}
        </div>
      )}
    </button>
  )
}
