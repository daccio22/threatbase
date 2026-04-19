import { SOURCE_CONFIG } from '../sourceConfig.js'

export default function CompareTray({ entries, onRemove, onCompare, onClear }) {
  if (!entries.length) return null

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50 border-t border-gray-700 bg-gray-900/95 backdrop-blur-sm shadow-2xl">
      <div className="max-w-screen-xl mx-auto px-4 py-3 flex items-center gap-4 flex-wrap">
        <span className="text-xs font-semibold text-gray-400 shrink-0">Compare:</span>
        <div className="flex-1 flex items-center gap-3 flex-wrap">
          {entries.map(e => {
            const cfg = SOURCE_CONFIG[e.source]
            return (
              <div
                key={e.id}
                className="flex items-center gap-1.5 px-2 py-1 rounded-lg border text-xs"
                style={{ borderColor: cfg?.hex + '60', backgroundColor: cfg?.hex + '15' }}
              >
                <span style={{ color: cfg?.hex }} className="font-mono">{e.id}</span>
                <span className="text-gray-300 max-w-[150px] truncate">{e.name}</span>
                <button
                  onClick={() => onRemove(e.id)}
                  className="text-gray-500 hover:text-gray-200 ml-0.5 transition-colors"
                  aria-label="Remove"
                >×</button>
              </div>
            )
          })}
          {entries.length < 2 && (
            <span className="text-xs text-gray-600 italic">Add one more entry to compare</span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {entries.length === 2 && (
            <button
              onClick={onCompare}
              className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium rounded-lg transition-colors"
            >
              Compare
            </button>
          )}
          <button
            onClick={onClear}
            className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>
    </div>
  )
}
