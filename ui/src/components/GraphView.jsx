import { useEffect, useRef } from 'react'
import * as d3 from 'd3'
import { SOURCE_CONFIG } from '../sourceConfig.js'

export default function GraphView({ entry, entryMap }) {
  const svgRef = useRef(null)

  useEffect(() => {
    if (!entry || !svgRef.current) return

    const el = svgRef.current
    const width = el.clientWidth || 500
    const height = el.clientHeight || 400

    // Build 2-hop graph
    const nodeSet = new Map()
    const links = []

    function addNode(e) {
      if (!e || nodeSet.has(e.id)) return
      nodeSet.set(e.id, { id: e.id, name: e.name, source: e.source, entry: e })
    }

    addNode(entry)

    // Hop 1
    const hop1 = (entry.cross_refs || []).map(id => entryMap[id]).filter(Boolean)
    hop1.forEach(e => {
      addNode(e)
      links.push({ source: entry.id, target: e.id })
    })

    // Hop 2
    hop1.forEach(e1 => {
      (e1.cross_refs || []).slice(0, 5).forEach(id => {
        const e2 = entryMap[id]
        if (e2 && id !== entry.id) {
          addNode(e2)
          links.push({ source: e1.id, target: id })
        }
      })
    })

    const nodes = [...nodeSet.values()]

    const svg = d3.select(el)
    svg.selectAll('*').remove()

    const defs = svg.append('defs')
    defs.append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 15)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#6b7280')

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(30))

    const link = svg.append('g').selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#374151')
      .attr('stroke-width', 1.5)
      .attr('marker-end', 'url(#arrow)')

    const node = svg.append('g').selectAll('g')
      .data(nodes)
      .join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y })
        .on('end', (ev, d) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null })
      )

    node.append('circle')
      .attr('r', d => d.id === entry.id ? 14 : 9)
      .attr('fill', d => SOURCE_CONFIG[d.source]?.hex || '#6b7280')
      .attr('stroke', d => d.id === entry.id ? '#fff' : 'transparent')
      .attr('stroke-width', 2)

    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.id === entry.id ? -18 : -13)
      .attr('font-size', 10)
      .attr('fill', '#d1d5db')
      .text(d => d.id.length > 12 ? d.id.slice(0, 12) + '…' : d.id)

    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y)
      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    return () => sim.stop()
  }, [entry, entryMap])

  return (
    <svg
      ref={svgRef}
      className="w-full h-64 bg-gray-900 rounded-lg"
    />
  )
}
