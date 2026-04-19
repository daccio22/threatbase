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
  if (activeSourceFilters.length > 0 && !activeSourceFilters.includes(entry.source)) return false
  if (cvssFilter && entry.source === 'CVE') {
    if (entry.cvss_severity?.toLowerCase() !== cvssFilter.toLowerCase()) return false
  }
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

    if (!text && activeSourceFilters.length === 0 && !cvssFilter && !filters.sources.length && !filters.tags.length && filters.minScore === null) {
      // No filters at all — just return first 200 entries as-is, no sort
      return entries.slice(0, 200)
    }

    let pool = entries.filter(e => matchesFilters(e, filters, activeSourceFilters, cvssFilter))

    if (!text) {
      // Filters active but no text — return first 200 of filtered pool, no sort
      return pool.slice(0, 200)
    }

    if (!fuse) return []
    const filteredFuse = new Fuse(pool, FUSE_OPTIONS)
    return filteredFuse.search(text).map(r => r.item)
  }, [debouncedQuery, fuse, entries, activeSourceFilters, cvssFilter])

  return { query, setQuery, results }
}
