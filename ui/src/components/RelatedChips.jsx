import { SOURCE_CONFIG } from '../sourceConfig.js'

export default function RelatedChips({ crossRefs, entryMap, onSelect }) {
  if (!crossRefs?.length) return null

  return (
    <div>
      <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
        Related ({crossRefs.length})
      </div>
      <div className="flex flex-wrap gap-1.5">
        {crossRefs.slice(0, 20).map(id => {
          const related = entryMap[id]
          const cfg = related ? SOURCE_CONFIG[related.source] : null
          return (
            <button
              key={id}
              onClick={() => related && onSelect(related)}
              className="text-xs px-2 py-1 rounded-lg border transition-all hover:scale-105"
              style={
                cfg
                  ? { backgroundColor: cfg.hex + '20', borderColor: cfg.hex + '60', color: cfg.hex }
                  : { backgroundColor: '#374151', borderColor: '#4b5563', color: '#9ca3af' }
              }
              title={related?.name || id}
            >
              {id}
            </button>
          )
        })}
        {crossRefs.length > 20 && (
          <span className="text-xs text-gray-500 self-center">+{crossRefs.length - 20} more</span>
        )}
      </div>
    </div>
  )
}
