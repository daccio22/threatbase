import { useEffect, useRef } from 'react'
import * as d3 from 'd3'
import { SOURCE_CONFIG } from '../sourceConfig.js'

const MAX_NODES = 30

function relLabel(srcEntry, tgtEntry) {
  const s = srcEntry?.source
  const t = tgtEntry?.source
  if (s === 'CVE' && t === 'CWE') return 'weakness-of'
  if (s === 'CWE' && t === 'CVE') return 'exploited-by'
  if (s === 'D3FEND' && t === 'ATT&CK') return 'mitigates'
  if (s === 'ATT&CK' && t === 'D3FEND') return 'mitigated-by'
  if (s === 'SPARTA' && t === 'ATT&CK') return 'maps-to'
  if (s === 'ATT&CK' && t === 'SPARTA') return 'mapped-by'
  if (s === 'ESA SHIELD' && t === 'SPARTA') return 'implements'
  if (s === 'ESA SHIELD' && t === 'ATT&CK') return 'mitigates'
  if (s === 'ATT&CK' && t === 'ATT&CK') return 'subtechnique-of'
  return 'related'
}

export default function GraphView({ entry, entryMap, onSelect }) {
  const svgRef = useRef(null)

  useEffect(() => {
    if (!entry || !svgRef.current) return

    const el = svgRef.current
    const width = el.clientWidth || 600
    const height = 500

    const nodeSet = new Map()
    const links = []

    function addNode(e, hop) {
      if (!e || nodeSet.has(e.id)) return
      nodeSet.set(e.id, { id: e.id, name: e.name, source: e.source, entry: e, hop })
    }

    addNode(entry, 0)

    const hop1 = (entry.cross_refs || []).map(id => entryMap[id]).filter(Boolean)
    const hop1Capped = hop1.slice(0, MAX_NODES - 1)
    hop1Capped.forEach(e => {
      addNode(e, 1)
      links.push({ source: entry.id, target: e.id, label: relLabel(entry, e) })
    })

    for (const e1 of hop1Capped) {
      if (nodeSet.size >= MAX_NODES) break
      for (const id of (e1.cross_refs || []).slice(0, 5)) {
        if (nodeSet.size >= MAX_NODES) break
        const e2 = entryMap[id]
        if (e2 && id !== entry.id && !nodeSet.has(id)) {
          addNode(e2, 2)
          links.push({ source: e1.id, target: id, label: relLabel(e1, e2) })
        }
      }
    }

    const nodes = [...nodeSet.values()]
    const svg = d3.select(el)
    svg.selectAll('*').remove()
    svg.attr('width', width).attr('height', height)

    const g = svg.append('g')

    svg.call(
      d3.zoom()
        .scaleExtent([0.2, 5])
        .on('zoom', ev => g.attr('transform', ev.transform))
    )

    svg.append('defs').append('marker')
      .attr('id', 'arrow-gc')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 18)
      .attr('markerWidth', 5)
      .attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#4b5563')

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(d => (d.source.hop === 0 || d.target.hop === 0) ? 90 : 70))
      .force('charge', d3.forceManyBody().strength(-250))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(d => d.hop === 0 ? 22 : d.hop === 1 ? 16 : 13))

    const linkG = g.append('g').selectAll('g')
      .data(links)
      .join('g')

    linkG.append('line')
      .attr('stroke', '#374151')
      .attr('stroke-width', 1.5)
      .attr('marker-end', 'url(#arrow-gc)')

    linkG.append('text')
      .attr('font-size', 7)
      .attr('fill', '#6b7280')
      .attr('text-anchor', 'middle')
      .attr('pointer-events', 'none')
      .text(d => d.label)

    const nodeG = g.append('g').selectAll('g')
      .data(nodes)
      .join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y })
        .on('end', (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null })
      )
      .on('click', (ev, d) => {
        ev.stopPropagation()
        if (d.entry && onSelect) onSelect(d.entry)
      })

    nodeG.append('circle')
      .attr('r', d => d.hop === 0 ? 16 : d.hop === 1 ? 10 : 7)
      .attr('fill', d => SOURCE_CONFIG[d.source]?.hex || '#6b7280')
      .attr('fill-opacity', d => d.hop === 0 ? 1 : d.hop === 1 ? 0.85 : 0.65)
      .attr('stroke', d => d.hop === 0 ? '#fff' : 'transparent')
      .attr('stroke-width', 2)

    nodeG.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', d => -(d.hop === 0 ? 21 : d.hop === 1 ? 14 : 11))
      .attr('font-size', d => d.hop === 0 ? 10 : 9)
      .attr('fill', '#d1d5db')
      .attr('pointer-events', 'none')
      .text(d => d.id.length > 14 ? d.id.slice(0, 14) + '…' : d.id)

    sim.on('tick', () => {
      linkG.select('line')
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y)

      linkG.select('text')
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2)

      nodeG.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    return () => sim.stop()
  }, [entry, entryMap, onSelect])

  return (
    <div className="hidden md:block">
      <svg
        ref={svgRef}
        className="w-full bg-gray-950 rounded-lg border border-gray-700"
        style={{ height: '500px' }}
      />
      <p className="text-[10px] text-gray-600 mt-1">Scroll to zoom · drag to pan · click node to navigate</p>
    </div>
  )
}
