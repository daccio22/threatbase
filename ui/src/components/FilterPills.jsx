import { SOURCE_CONFIG, CVSS_SEVERITIES } from '../sourceConfig.js'

export default function FilterPills({ activeSources, onToggleSource, cvssFilter, onCvssFilter }) {
  return (
    <div className="flex flex-wrap gap-2 items-center">
      {Object.entries(SOURCE_CONFIG).map(([source, cfg]) => {
        const active = activeSources.includes(source)
        return (
          <button
            key={source}
            onClick={() => onToggleSource(source)}
            className={`px-3 py-1 rounded-full text-xs font-semibold border transition-all ${
              active
                ? `bg-${cfg.bg} border-${cfg.border} text-${cfg.text}`
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
            }`}
            style={active ? { backgroundColor: cfg.hex, borderColor: cfg.hex, color: '#fff' } : {}}
          >
            {source}
          </button>
        )
      })}

      <div className="w-px h-5 bg-gray-700 mx-1" />

      {CVSS_SEVERITIES.map(sev => {
        const active = cvssFilter === sev.value
        return (
          <button
            key={sev.value}
            onClick={() => onCvssFilter(active ? null : sev.value)}
            className={`px-3 py-1 rounded-full text-xs font-semibold border transition-all ${
              active ? 'border-transparent text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
            }`}
            style={active ? { backgroundColor: sev.color, borderColor: sev.color } : {}}
          >
            {sev.label}
          </button>
        )
      })}
    </div>
  )
}
