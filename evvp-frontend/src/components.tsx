import { useState } from 'react'
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

// Strip HTML tags and decode entities
export function stripHtml(html: string): string {
  if (!html) return ''
  const tmp = document.createElement('div')
  tmp.innerHTML = html
  return tmp.textContent || tmp.innerText || ''
}

// Format description: strip HTML, truncate, make concise
export function formatDescription(text: string, maxLength = 200): string {
  if (!text) return 'No description available'
  const clean = stripHtml(text).trim()
  if (clean.length <= maxLength) return clean
  return clean.slice(0, maxLength).trim() + '...'
}

// Convert long text to bullet points (split by sentences)
export function toBulletPoints(text: string, maxPoints = 3): string[] {
  if (!text) return []
  const clean = stripHtml(text).trim()
  const sentences = clean.split(/[.!?]+/).filter(s => s.trim().length > 20)
  return sentences.slice(0, maxPoints).map(s => s.trim())
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

// Compact post row — click to open detail drawer
export function VulnCard({ item }: { item: IntelItem }) {
  const [open, setOpen] = useState(false)
  const severity = severityFromScore(item.signal_score)
  const cves = item.cve_ids || []
  const summary = item.summary || formatDescription(item.text, 180)

  let rowClass = 'post-row'
  if (cves.length > 0) rowClass += ' has-cve'
  else if (severity === 'CRITICAL') rowClass += ' is-critical'
  else if (severity === 'HIGH') rowClass += ' is-high'

  return (
    <>
      <div className={rowClass} onClick={() => setOpen(true)}>
        <ScoreBadge score={item.signal_score} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="post-row-title">{item.title}</div>
          {/* AI-generated summary */}
          <div style={{ 
            fontSize: 13, 
            color: 'var(--text3)', 
            marginTop: 4,
            lineHeight: 1.4,
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
            overflow: 'hidden'
          }}>
            {summary}
          </div>
        </div>
        <div className="post-row-meta">
          <PlatformBadge platform={item.platform} />
          <SeverityBadge severity={severity} />
          {cves.length > 0 && <span className="badge badge-info">CVE</span>}
          {isNew(item.collected_at) && <span className="badge badge-new">NEW</span>}
          {item.sources && item.sources.length > 1 && (
            <span className="badge badge-info" style={{ background: 'rgba(6,182,212,0.1)', color: 'var(--cyan)', borderColor: 'rgba(6,182,212,0.25)' }}>
              {item.sources.length} sources
            </span>
          )}
          <span style={{ fontSize: 11, color: 'var(--text3)', marginLeft: 4 }}>{timeAgo(item.collected_at)}</span>
        </div>
      </div>

      {open && <PostDetail item={item} onClose={() => setOpen(false)} />}
    </>
  )
}

// Full detail drawer/modal
function PostDetail({ item, onClose }: { item: IntelItem; onClose: () => void }) {
  const cves = item.cve_ids || []
  const severity = severityFromScore(item.signal_score)
  const nvd = item.nvd_data?.[0]
  const desc = nvd?.description || item.text?.trim()
  const sources = item.sources && item.sources.length > 0 ? item.sources : [{ url: item.url, platform: item.platform }]

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer" onClick={e => e.stopPropagation()}>
        <div className="drawer-header">
          <div style={{ flex: 1 }}>
            <div className="drawer-title">{item.title}</div>
            <div className="vuln-meta" style={{ marginTop: 8, marginBottom: 0 }}>
              <PlatformBadge platform={item.platform} />
              <SeverityBadge severity={severity} />
              {cves.length > 0 && <span className="badge badge-info">CVE</span>}
              <span className="vuln-meta-sep">|</span>
              <span style={{ fontSize: 12, color: 'var(--text3)' }}>📅 {formatDate(item.timestamp || item.collected_at)}</span>
              {item.author && <><span className="vuln-meta-sep">|</span><span style={{ fontSize: 12, color: 'var(--text3)' }}>👤 {item.author}</span></>}
              {sources.length > 0 && (
                <>
                  <span className="vuln-meta-sep">|</span>
                  <a 
                    href={sources[0].url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    style={{ fontSize: 12, color: 'var(--accent)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                    onClick={(e) => e.stopPropagation()}
                  >
                    🔗 Source ↗
                  </a>
                </>
              )}
            </div>
          </div>
          <button className="drawer-close" onClick={onClose}>✕</button>
        </div>

        {/* CVSS */}
        {nvd?.cvss_v3 && (
          <div className="drawer-section" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 11, color: 'var(--text3)' }}>CVSS v3</span>
            <span className="cvss-score" style={{ color: cvssColor(nvd.cvss_v3.score) }}>{nvd.cvss_v3.score}</span>
            <SeverityBadge severity={nvd.cvss_v3.severity} />
            <span style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{nvd.cvss_v3.vector}</span>
          </div>
        )}

        {/* Description */}
        {desc && (
          <div className="drawer-section">
            <div className="drawer-label">Description</div>
            {item.platform === 'blog' ? (
              <div className="drawer-desc" style={{ lineHeight: 1.6 }}>
                {toBulletPoints(desc, 5).map((point, i) => (
                  <div key={i} style={{ marginBottom: 8, paddingLeft: 16, position: 'relative' }}>
                    <span style={{ position: 'absolute', left: 0, color: 'var(--accent)' }}>•</span>
                    {point}
                  </div>
                ))}
              </div>
            ) : (
              <div className="drawer-desc" style={{ lineHeight: 1.6 }}>
                {toBulletPoints(desc, 4).length > 0 ? (
                  toBulletPoints(desc, 4).map((point, i) => (
                    <div key={i} style={{ marginBottom: 8, paddingLeft: 16, position: 'relative' }}>
                      <span style={{ position: 'absolute', left: 0, color: 'var(--accent)' }}>•</span>
                      {point}
                    </div>
                  ))
                ) : (
                  <div>{stripHtml(desc)}</div>
                )}
              </div>
            )}
          </div>
        )}

        {/* CVE tags */}
        {cves.length > 0 && (
          <div className="drawer-section">
            <div className="drawer-label">CVE IDs</div>
            <div className="vuln-tags" style={{ marginTop: 6 }}>
              {cves.map(c => <span key={c} className="cve-tag">{c.toUpperCase()}</span>)}
            </div>
          </div>
        )}

        {/* Matched signals */}
        {item.matched_signals?.length > 0 && (
          <div className="drawer-section">
            <div className="drawer-label">Matched Signals</div>
            <div className="vuln-tags" style={{ marginTop: 6 }}>
              {item.matched_signals.map(s => <span key={s} className="signal-tag">{s}</span>)}
            </div>
          </div>
        )}

        {/* Sources */}
        <div className="drawer-section">
          <div className="drawer-label">Sources ({sources.length})</div>
          <div className="drawer-sources">
            {sources.map((s, i) => (
              <a
                key={i}
                href={s.url}
                target="_blank"
                rel="noopener noreferrer"
                className="drawer-source-item"
              >
                <span className={`badge badge-${s.platform}`} style={{ marginRight: 8 }}>{s.platform}</span>
                <span className="drawer-source-url">{s.url}</span>
                <span style={{ marginLeft: 'auto', color: 'var(--accent)', fontSize: 13 }}>↗</span>
              </a>
            ))}
          </div>
        </div>

        <div className="drawer-footer">
          <span style={{ fontSize: 12, color: 'var(--text3)' }}>
            Signal score: <span style={{ color: scoreColor(item.signal_score), fontFamily: 'var(--mono)', fontWeight: 700 }}>{item.signal_score}</span>
            &nbsp;·&nbsp; {item.category?.replace(/_/g, ' ')}
          </span>
        </div>
      </div>
    </div>
  )
}
