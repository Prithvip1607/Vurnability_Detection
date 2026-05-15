import { useEffect, useState } from 'react'
import { getTrending, TrendingCVE } from '../api'
import { Spinner, Empty } from '../components'

export default function Trending() {
  const [data, setData]     = useState<TrendingCVE[]>([])
  const [loading, setLoading] = useState(true)
  const [hours, setHours]   = useState(24)

  const load = (h: number) => {
    setLoading(true)
    getTrending(h, 50).then(r => { setData(r); setLoading(false) }).catch(() => setLoading(false))
  }

  useEffect(() => { load(hours) }, [hours])
  useEffect(() => { const t = setInterval(() => load(hours), 60000); return () => clearInterval(t) }, [hours])

  const max = data[0]?.mention_count || 1

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">🔥 Trending CVEs</h1>
        <p className="page-sub">CVEs ranked by mention count across all sources. Spike = something is happening.</p>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 20, alignItems: 'center' }}>
        <div className="tabs">
          {[6, 12, 24, 48, 168].map(h => (
            <button key={h} className={`btn ${hours === h ? 'active' : ''}`} onClick={() => setHours(h)}>
              {h < 24 ? `${h}h` : h === 168 ? '7d' : `${h / 24}d`}
            </button>
          ))}
        </div>
        {data.length > 0 && <span style={{ fontSize: 13, color: 'var(--text3)', marginLeft: 'auto' }}>{data.length} CVEs tracked</span>}
      </div>

      {loading ? <Spinner /> : data.length === 0 ? (
        <Empty msg="No trending CVEs yet. Run collectors to populate data." />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {data.map((item, i) => (
            <div key={item.cve_id} className="trending-row">
              <span className="trending-rank">#{i + 1}</span>
              <span className="trending-cve">{item.cve_id}</span>
              <div className="trending-bar-wrap">
                <div className="trending-bar" style={{ width: `${(item.mention_count / max) * 100}%` }} />
              </div>
              <span className="trending-count">{item.mention_count}×</span>
              <div className="trending-sources">
                {item.sources.map(s => <span key={s} className={`badge badge-${s}`}>{s[0].toUpperCase()}</span>)}
              </div>
              {item.latest?.url && (
                <a href={item.latest.url} target="_blank" rel="noopener noreferrer"
                  style={{ fontSize: 12, color: 'var(--accent)', flexShrink: 0 }}>
                  Latest ↗
                </a>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
