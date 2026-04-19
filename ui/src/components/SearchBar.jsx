import { useRef, useEffect } from 'react'

export default function SearchBar({ query, onChange }) {
  const ref = useRef(null)

  useEffect(() => {
    function handler(e) {
      if (e.key === '/' && document.activeElement !== ref.current) {
        e.preventDefault()
        ref.current?.focus()
      }
      if (e.key === 'Escape' && document.activeElement === ref.current) {
        ref.current?.blur()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  return (
    <div className="relative w-full max-w-3xl mx-auto">
      <div className="pointer-events-none absolute inset-y-0 left-4 flex items-center">
        <svg className="w-5 h-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" />
        </svg>
      </div>
      <input
        ref={ref}
        type="text"
        value={query}
        onChange={e => onChange(e.target.value)}
        placeholder='Search techniques, CVEs, weaknesses… (press / to focus)'
        autoFocus
        className="w-full bg-gray-800 border border-gray-700 rounded-xl pl-11 pr-20 py-3.5 text-gray-100 placeholder-gray-500 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none transition text-base"
      />
      {query && (
        <button
          onClick={() => onChange('')}
          className="absolute right-12 inset-y-0 flex items-center px-2 text-gray-400 hover:text-gray-200"
          aria-label="Clear search"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
      <kbd className="absolute right-4 inset-y-0 flex items-center text-xs text-gray-500 font-mono pointer-events-none">
        /
      </kbd>
    </div>
  )
}
