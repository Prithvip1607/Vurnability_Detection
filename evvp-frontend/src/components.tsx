import { IntelItem } from './api'

export function severityFromScore(score: number): string {
  if (score >= 20) return 'CRITICAL'
  if (score >= 14) return 'HIGH'
  if (score >= 8)  return 'MEDIUM'
  return 'LOW'
}

export function scoreColor(score: number) {
  if (score >= 20) return '#ef4444'
  if (score >= 14) return '#f97316'
  if (score >= 8)  return '#eab308'
  return '#22c55e'
}

export function cvssColor(score: number) {
  if (score >= 9.0) return '#ef4444'
  if (score >= 7.0) return '#f97316'
  if (score >= 4.0) return '#eab308'
  return '#22c55e'
}

export function timeAgo(ts: string) {
  const diff = Date.now() - new Date(ts).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function formatDate(ts: string) {
  if (!ts) return '—'
  try {
    return new Date(ts).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
  } catch { return ts.slice(0, 10) }
}

export function isNew(ts: string) {
  return Date.now() - new Date(ts).getTime() < 24 * 3600 * 1000
}

export function ScoreBadge({ score }: { score: number }) {
  const c = scoreColor(score)
  return (
    <span className="score-badge" style={{ background: `${c}18`, color: c, border: `1px solid ${c}35` }}>
      {score}
    </span>
  )
}

export function PlatformBadge({ platform }: { platform: string }) {
  return <span className={`badge badge-${platform}`}>{platform}</span>
}

export function SeverityBadge({ severity }: { severity?: string }) {
  if (!severity) return null
  return <span className={`badge badge-${severity.toLowerCase()}`}>{severity}</span>
}

export function Spinner() {
  return <div className="loading"><div className="spinner" /><span>Loading...</span></div>
}

export function Empty({ msg = 'No data found' }: { msg?: string }) {
  return <div className="empty">🔍 {msg}</div>
}

export function Pagination({ page, pages, total, onPage }: {
  page: number; pages: number; total: number; onPage: (p: number) => void
}) {
  if (pages <= 1) return null
  return (
    <div className="pagination">
      <button className="btn" onClick={() => onPage(page - 1)} disabled={page <= 1}>← Prev</button>
      <span className="page-info">Page {page} / {pages} &nbsp;·&nbsp; {total} total</span>
      <button className="btn" onClick={() => onPage(page + 1)} disabled={page >= pages}>Next →</button>
    </div>
  )
}

// The main vulnerability card — full description, date, source link, signals
export function VulnCard({ item }: { item: IntelItem }) {
  const cves = item.cve_ids || []
  const hasCve = cves.length > 0
  const severity = severityFromScore(item.signal_score)
  const nvd = item.nvd_data?.[0]
  const publishedDate = formatDate(item.timestamp || item.collected_at)
  const collectedDate = formatDate(item.collected_at)
  const desc = item.text?.trim()

  // Card left-border class
  let cardClass = 'vuln-card'
  if (hasCve) cardClass += ' has-cve'
  else if (severity === 'CRITICAL') cardClass += ' is-critical'
  else if (severity === 'HIGH') cardClass += ' is-high'

  return (
    <div className={cardClass}>
      {/* Header: score + title */}
      <div className="vuln-header">
        <ScoreBadge score={item.signal_score} />
        <div style={{ flex: 1 }}>
          <div className="vuln-title">
            <a href={item.url} target="_blank" rel="noopener noreferrer">
              {item.title}
            </a>
          </div>
        </div>
        {isNew(item.collected_at) && <span className="badge badge-new">NEW</span>}
      </div>

      {/* Meta row */}
      <div className="vuln-meta">
        <PlatformBadge platform={item.platform} />
        <SeverityBadge severity={severity} />
        {hasCve && <span className="badge badge-info">CVE</span>}
        <span className="vuln-meta-sep">|</span>
        <span>📅 Published: <strong style={{ color: 'var(--text)' }}>{publishedDate}</strong></span>
        <span className="vuln-meta-sep">|</span>
        <span>🕐 Collected: {collectedDate}</span>
        <span className="vuln-meta-sep">|</span>
        <span>📌 {item.source}</span>
        {item.author && <><span className="vuln-meta-sep">|</span><span>👤 {item.author}</span></>}
      </div>

      {/* NVD CVSS if available */}
      {nvd?.cvss_v3 && (
        <div style={{ marginBottom: 10, display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 11, color: 'var(--text3)' }}>CVSS v3</span>
          <span className="cvss-score" style={{ color: cvssColor(nvd.cvss_v3.score) }}>
            {nvd.cvss_v3.score}
          </span>
          <SeverityBadge severity={nvd.cvss_v3.severity} />
          <span style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>
            {nvd.cvss_v3.vector}
          </span>
        </div>
      )}

      {/* Description */}
      {desc && (
        <div className="vuln-desc">
          {nvd?.description || desc}
        </div>
      )}

      {/* CVE tags + signal tags */}
      {(cves.length > 0 || item.matched_signals?.length > 0) && (
        <div className="vuln-tags">
          {cves.map(c => <span key={c} className="cve-tag">{c.toUpperCase()}</span>)}
          {item.matched_signals?.slice(0, 8).map(s => <span key={s} className="signal-tag">{s}</span>)}
        </div>
      )}

      {/* Footer: source link */}
      <div className="vuln-footer">
        <div style={{ fontSize: 12, color: 'var(--text3)' }}>
          Signal score: <span style={{ color: scoreColor(item.signal_score), fontFamily: 'var(--mono)', fontWeight: 700 }}>{item.signal_score}</span>
          &nbsp;·&nbsp; {item.category?.replace(/_/g, ' ')}
        </div>
        <a href={item.url} target="_blank" rel="noopener noreferrer" className="vuln-link">
          View Source ↗
        </a>
      </div>
    </div>
  )
}
