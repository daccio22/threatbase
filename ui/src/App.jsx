import { useState, useEffect, useMemo } from 'react'
import { useData } from './hooks/useData.js'
import { useSearch } from './hooks/useSearch.js'
import SearchBar from './components/SearchBar.jsx'
import FilterPills from './components/FilterPills.jsx'
import StatsBar from './components/StatsBar.jsx'
import EntryCard from './components/EntryCard.jsx'
import DetailPanel from './components/DetailPanel.jsx'
import CoverageHeatmap from './components/CoverageHeatmap.jsx'
import CompareTray from './components/CompareTray.jsx'
import CompareView from './components/CompareView.jsx'

const PAGE_SIZE = 60

function SkeletonCard() {
  return (
    <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-4 animate-pulse">
      <div className="flex gap-2 mb-3">
        <div className="h-5 w-16 bg-gray-700 rounded-full" />
      </div>
      <div className="h-3 w-24 bg-gray-700 rounded mb-2" />
      <div className="h-4 w-3/4 bg-gray-700 rounded mb-3" />
      <div className="h-3 bg-gray-700/60 rounded mb-1.5" />
      <div className="h-3 bg-gray-700/60 rounded w-5/6" />
    </div>
  )
}

function useUrlSync(query, setQuery, activeSources, setActiveSources) {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const q = params.get('q') || ''
    const s = params.get('sources') ? params.get('sources').split(',').filter(Boolean) : []
    if (q) setQuery(q)
    if (s.length) setActiveSources(s)
  }, [])

  useEffect(() => {
    const params = new URLSearchParams()
    if (query) params.set('q', query)
    if (activeSources.length) params.set('sources', activeSources.join(','))
    const str = params.toString()
    const newUrl = str ? `${window.location.pathname}?${str}${window.location.hash}` : `${window.location.pathname}${window.location.hash}`
    window.history.replaceState(null, '', newUrl)
  }, [query, activeSources])
}

function useHashRoute() {
  const [hash, setHash] = useState(() => window.location.hash || '#/')
  useEffect(() => {
    function onHashChange() { setHash(window.location.hash || '#/') }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])
  return hash
}

export default function App() {
  const { entries, metadata, loading, error } = useData()
  const [activeSources, setActiveSources] = useState([])
  const [cvssFilter, setCvssFilter] = useState(null)
  const { query, setQuery, results } = useSearch(entries, activeSources, cvssFilter)
  const [selected, setSelected] = useState(null)
  const [page, setPage] = useState(1)
  const [sortMode, setSortMode] = useState('most-connected')
  const [compareEntries, setCompareEntries] = useState([])
  const [showCompare, setShowCompare] = useState(false)
  const [filterIds, setFilterIds] = useState(null)
  const hash = useHashRoute()

  useUrlSync(query, setQuery, activeSources, setActiveSources)

  useEffect(() => { setPage(1) }, [query, activeSources, cvssFilter, sortMode, filterIds])
  useEffect(() => { setFilterIds(null) }, [query, activeSources, cvssFilter])

  const entryMap = useMemo(() => {
    const m = {}
    for (const e of entries) m[e.id] = e
    return m
  }, [entries])

  const sortedResults = useMemo(() => {
    let base = filterIds
      ? entries.filter(e => filterIds.includes(e.id))
      : results
    if (sortMode === 'most-connected') {
      return [...base].sort((a, b) => (b.connection_score ?? 0) - (a.connection_score ?? 0))
    }
    return base
  }, [results, sortMode, filterIds, entries])

  function toggleSource(source) {
    setActiveSources(prev =>
      prev.includes(source) ? prev.filter(s => s !== source) : [...prev, source]
    )
  }

  function toggleCompare(entry) {
    setCompareEntries(prev => {
      if (prev.find(e => e.id === entry.id)) return prev.filter(e => e.id !== entry.id)
      if (prev.length >= 2) return [prev[1], entry]
      return [...prev, entry]
    })
  }

  function handleHeatmapFilter(ids) {
    setFilterIds(ids)
    window.location.hash = '#/'
  }

  const visible = sortedResults.slice(0, page * PAGE_SIZE)
  const hasMore = sortedResults.length > visible.length

  const isDefaultView = !query && activeSources.length === 0 && !cvssFilter

  const isCoverage = hash === '#/coverage'

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur-sm sticky top-0 z-20">
        <div className="max-w-screen-xl mx-auto px-4 py-3 flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-4">
            <a href="#/" className="text-xl font-bold text-white tracking-tight hover:text-gray-200 transition-colors">
              ThreatBase
            </a>
            {metadata && (
              <span className="text-sm text-gray-500 hidden sm:block">
                {metadata.total?.toLocaleString()} entries
              </span>
            )}
          </div>
          <nav className="flex items-center gap-1">
            <a
              href="#/"
              className={`text-sm px-3 py-1.5 rounded-lg transition-colors ${!isCoverage ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'}`}
            >
              Search
            </a>
            <a
              href="#/coverage"
              className={`text-sm px-3 py-1.5 rounded-lg transition-colors ${isCoverage ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'}`}
            >
              Coverage Map
            </a>
          </nav>
          {metadata?.generated_at && (
            <span className="text-xs text-gray-600 hidden md:block">
              Updated {new Date(metadata.generated_at).toLocaleDateString()}
            </span>
          )}
        </div>
      </header>

      <main className="flex-1 max-w-screen-xl mx-auto w-full px-4 py-6 space-y-5">
        {isCoverage ? (
          loading ? (
            <div className="flex items-center justify-center py-20 text-gray-500 text-sm">Loading data…</div>
          ) : (
            <CoverageHeatmap entries={entries} onFilter={handleHeatmapFilter} />
          )
        ) : (
          <>
            <StatsBar metadata={metadata} activeSources={activeSources} onToggleSource={toggleSource} />
            <SearchBar query={query} onChange={setQuery} />
            <FilterPills
              activeSources={activeSources}
              onToggleSource={toggleSource}
              cvssFilter={cvssFilter}
              onCvssFilter={setCvssFilter}
            />

            {/* Status + sort */}
            {!loading && !error && (
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="text-xs text-gray-500">
                  {filterIds
                    ? `${sortedResults.length.toLocaleString()} entries from coverage map`
                    : isDefaultView
                    ? `Top ${Math.min(sortedResults.length, page * PAGE_SIZE).toLocaleString()} most connected entries`
                    : query
                    ? `${sortedResults.length.toLocaleString()} results for "${query}"`
                    : `${sortedResults.length.toLocaleString()} entries`}
                  {!filterIds && (activeSources.length > 0 || cvssFilter) && ' (filtered)'}
                  {filterIds && (
                    <button onClick={() => setFilterIds(null)} className="ml-2 text-indigo-400 hover:text-indigo-300">
                      ✕ clear filter
                    </button>
                  )}
                </div>
                <select
                  value={sortMode}
                  onChange={e => setSortMode(e.target.value)}
                  className="text-xs bg-gray-800 border border-gray-700 text-gray-300 rounded px-2 py-1 cursor-pointer"
                >
                  <option value="most-connected">Sort: Most connected</option>
                  <option value="default">Sort: Default</option>
                </select>
              </div>
            )}

            {error && (
              <div className="bg-red-900/30 border border-red-700 rounded-xl p-4 text-red-300 text-sm">
                Failed to load data: {error}. Make sure the data files have been generated by running the fetch scripts.
              </div>
            )}

            {/* Results grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {loading
                ? Array.from({ length: 12 }).map((_, i) => <SkeletonCard key={i} />)
                : visible.map(entry => (
                    <EntryCard
                      key={entry.id}
                      entry={entry}
                      onClick={setSelected}
                      onCompare={toggleCompare}
                      inCompare={compareEntries.some(e => e.id === entry.id)}
                    />
                  ))
              }
            </div>

            {!loading && !error && sortedResults.length === 0 && query && (
              <div className="text-center py-16">
                <div className="text-4xl mb-3">🔍</div>
                <p className="text-gray-400 mb-1">No results for <strong>"{query}"</strong></p>
                <p className="text-gray-600 text-sm">Try a shorter query, remove filters, or use source:ATT&CK / source:CVE prefixes</p>
              </div>
            )}

            {hasMore && (
              <div className="text-center pt-4">
                <button
                  onClick={() => setPage(p => p + 1)}
                  className="px-6 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-lg text-sm text-gray-300 transition-colors"
                >
                  Load more ({sortedResults.length - visible.length} remaining)
                </button>
              </div>
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-4 px-4 text-center">
        <LastRunStatus />
        <p className="text-xs text-gray-700 mt-1">
          Data: <a href="https://attack.mitre.org" target="_blank" rel="noopener noreferrer" className="hover:text-gray-500">ATT&CK</a>
          {' · '}<a href="https://d3fend.mitre.org" target="_blank" rel="noopener noreferrer" className="hover:text-gray-500">D3FEND</a>
          {' · '}<a href="https://nvd.nist.gov" target="_blank" rel="noopener noreferrer" className="hover:text-gray-500">NVD/CVE</a>
          {' · '}<a href="https://cwe.mitre.org" target="_blank" rel="noopener noreferrer" className="hover:text-gray-500">CWE</a>
          {' · '}<a href="https://github.com/mitre/SPARTA" target="_blank" rel="noopener noreferrer" className="hover:text-gray-500">SPARTA</a>
          {' · '}<a href="https://github.com/esaSPACEops/SHIELD" target="_blank" rel="noopener noreferrer" className="hover:text-gray-500">ESA SHIELD</a>
          {' · MIT License'}
        </p>
      </footer>

      {/* Detail panel */}
      {selected && !showCompare && (
        <DetailPanel
          entry={selected}
          entryMap={entryMap}
          onClose={() => setSelected(null)}
          onSelect={setSelected}
        />
      )}

      {/* Compare tray */}
      {compareEntries.length > 0 && !showCompare && (
        <CompareTray
          entries={compareEntries}
          onRemove={id => setCompareEntries(prev => prev.filter(e => e.id !== id))}
          onCompare={() => setShowCompare(true)}
          onClear={() => setCompareEntries([])}
        />
      )}

      {/* Compare view overlay */}
      {showCompare && compareEntries.length === 2 && (
        <CompareView
          entries={compareEntries}
          entryMap={entryMap}
          onClose={() => setShowCompare(false)}
          onSelect={e => { setShowCompare(false); setSelected(e) }}
        />
      )}
    </div>
  )
}

function LastRunStatus() {
  const [status, setStatus] = useState(null)
  useEffect(() => {
    const base = import.meta.env.BASE_URL || '/'
    fetch(`${base}data/last_run.json`)
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setStatus(d))
      .catch(() => {})
  }, [])

  if (!status) return null

  const errors = Object.entries(status)
    .filter(([k, v]) => k !== '_generated_at' && v?.error)
    .map(([k]) => k)

  if (errors.length === 0) return null

  return (
    <p className="text-xs text-amber-500">
      Last run had errors in: {errors.join(', ')}
    </p>
  )
}
