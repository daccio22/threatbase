export const SOURCE_CONFIG = {
  'ATT&CK': { hex: '#7c3aed', bg: 'attack', border: 'attack', text: 'attack-text' },
  'D3FEND':  { hex: '#2563eb', bg: 'd3fend', border: 'd3fend', text: 'd3fend-text' },
  'CVE':     { hex: '#dc2626', bg: 'cve',    border: 'cve',    text: 'cve-text' },
  'CWE':     { hex: '#d97706', bg: 'cwe',    border: 'cwe',    text: 'cwe-text' },
  'SPARTA':  { hex: '#db2777', bg: 'sparta', border: 'sparta', text: 'sparta-text' },
  'ESA SHIELD': { hex: '#16a34a', bg: 'shield', border: 'shield', text: 'shield-text' },
}

export const CVSS_SEVERITIES = [
  { value: 'CRITICAL', label: 'Critical', color: '#7f1d1d' },
  { value: 'HIGH',     label: 'High',     color: '#b91c1c' },
  { value: 'MEDIUM',   label: 'Medium',   color: '#d97706' },
  { value: 'LOW',      label: 'Low',      color: '#15803d' },
]

export function cvssColor(score) {
  if (score >= 9.0) return '#7f1d1d'
  if (score >= 7.0) return '#b91c1c'
  if (score >= 4.0) return '#d97706'
  return '#15803d'
}
