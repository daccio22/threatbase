import { useState, useEffect } from 'react'

const SESSION_KEY = 'threatbase_unified'
const CVE_SESSION_KEY = 'threatbase_cves'

export function useData() {
  const [entries, setEntries] = useState([])
  const [metadata, setMetadata] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    async function load() {
      try {
        // Try sessionStorage cache first
        const cached = sessionStorage.getItem(SESSION_KEY)
        if (cached) {
          const parsed = JSON.parse(cached)
          setEntries(parsed.entries)
          setMetadata(parsed.metadata)
          setLoading(false)
          return
        }

        const base = import.meta.env.BASE_URL || '/'
        const res = await fetch(`${base}data/unified_index.json`)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()

        let allEntries = data.entries || []
        const meta = data.metadata || {}

        // If split, load CVE index separately
        if (meta.split) {
          try {
            const cveRes = await fetch(`${base}data/cves_index.json`)
            if (cveRes.ok) {
              const cveData = await cveRes.json()
              allEntries = [...allEntries, ...(cveData.entries || [])]
            }
          } catch {
            // CVE index optional
          }
        }

        sessionStorage.setItem(SESSION_KEY, JSON.stringify({ entries: allEntries, metadata: meta }))
        setEntries(allEntries)
        setMetadata(meta)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  return { entries, metadata, loading, error }
}
