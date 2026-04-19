import { useState, useEffect, useMemo, useRef } from 'react'
import Fuse from 'fuse.js'

const FUSE_OPTIONS = {
  includeScore: true,
  threshold: 0.35,
  minMatchCharLength: 2,
  keys: [
    { name: 'id', weight: 2.0 },
    { name: 'name', weight: 1.5 },
    { name: 'tags', weight: 1.2 },
    { name: 'cwe_ids', weight: 1.3 },
    { name: 'description', weight: 1.0 },
  ],
}

// Parse advanced query tokens: source:CVE score:>7 tag:rce <rest>
function parseQuery(raw) {
  const filters = { sources: [], minScore: null, tags: [] }
  let rest = raw

  const sourceMatch = [...rest.matchAll(/\bsource:(\S+)/gi)]
  sourceMatch.forEach(m => { filters.sources.push(m[1].toUpperCase()); rest = rest.replace(m[0], '') })

  const scoreMatch = rest.match(/\bscore:([><=])?([\d.]+)/i)
  if (scoreMatch) {
    filters.scoreOp = scoreMatch[1] || '>='
    filters.minScore = parseFloat(scoreMatch[2])
    rest = rest.replace(scoreMatch[0], '')
  }

  const tagMatches = [...rest.matchAll(/\btag:(\S+)/gi)]
  tagMatches.forEach(m => { filters.tags.push(m[1].toLowerCase()); rest = rest.replace(m[0], '') })

  return { filters, text: rest.trim() }
}

function matchesFilters(entry, filters, activeSourceFilters, cvssFilter) {
  // Source filter (from pills)
  if (activeSourceFilters.length > 0 && !activeSourceFilters.includes(entry.source)) return false

  // CVSS severity filter
  if (cvssFilter && entry.source === 'CVE') {
    if (entry.cvss_severity?.toLowerCase() !== cvssFilter.toLowerCase()) return false
  }

  // Advanced query filters
  if (filters.sources.length > 0 && !filters.sources.includes(entry.source?.toUpperCase())) return false

  if (filters.minScore !== null && entry.source === 'CVE') {
    const score = entry.cvss_score || 0
    const op = filters.scoreOp || '>='
    if (op === '>' && !(score > filters.minScore)) return false
    if (op === '>=' && !(score >= filters.minScore)) return false
    if (op === '<' && !(score < filters.minScore)) return false
    if (op === '<=' && !(score <= filters.minScore)) return false
    if (op === '=' && score !== filters.minScore) return false
  }

  if (filters.tags.length > 0) {
    const entryTags = (entry.tags || []).map(t => t.toLowerCase())
    if (!filters.tags.every(t => entryTags.some(et => et.includes(t)))) return false
  }

  return true
}

export function useSearch(entries, activeSourceFilters = [], cvssFilter = null) {
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const timerRef = useRef(null)

  useEffect(() => {
    clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setDebouncedQuery(query), 200)
    return () => clearTimeout(timerRef.current)
  }, [query])

  const fuse = useMemo(() => {
    if (!entries.length) return null
    return new Fuse(entries, FUSE_OPTIONS)
  }, [entries])

  const results = useMemo(() => {
    const { filters, text } = parseQuery(debouncedQuery)

    let pool = entries.filter(e => matchesFilters(e, filters, activeSourceFilters, cvssFilter))

    if (!text) {
      // Empty query: show recently modified
      return pool
        .slice()
        .sort((a, b) => (b.modified || b.last_updated || '').localeCompare(a.modified || a.last_updated || ''))
        .slice(0, 200)
    }

    if (!fuse) return []

    // Run fuse on filtered pool
    const filteredFuse = new Fuse(pool, FUSE_OPTIONS)
    return filteredFuse.search(text).map(r => r.item)
  }, [debouncedQuery, fuse, entries, activeSourceFilters, cvssFilter])

  return { query, setQuery, results }
}
