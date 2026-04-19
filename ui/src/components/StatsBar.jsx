import { SOURCE_CONFIG } from '../sourceConfig.js'

export default function StatsBar({ metadata, activeSources, onToggleSource }) {
  if (!metadata) return null
  const counts = metadata.counts_by_source || {}

  return (
    <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
      {Object.entries(SOURCE_CONFIG).map(([source, cfg]) => {
        const count = counts[source] ?? 0
        const active = activeSources.includes(source)
        return (
          <button
            key={source}
            onClick={() => onToggleSource(source)}
            className={`rounded-lg p-3 text-left border transition-all ${
              active
                ? 'border-transparent shadow-lg scale-105'
                : 'bg-gray-800/60 border-gray-700 hover:border-gray-600'
            }`}
            style={active ? { backgroundColor: cfg.hex + '22', borderColor: cfg.hex } : {}}
          >
            <div className="text-xl font-bold tabular-nums" style={{ color: cfg.hex }}>
              {count.toLocaleString()}
            </div>
            <div className="text-xs text-gray-400 mt-0.5 font-medium">{source}</div>
          </button>
        )
      })}
    </div>
  )
}
