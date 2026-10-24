import { useEffect, useState } from 'react'
import { getZerodays, IntelItem, Paginated } from '../api'
import { VulnCard, Spinner, Empty, Pagination } from '../components'

export default function ZeroDays() {
  const [data, setData]         = useState<Paginated<IntelItem> | null>(null)
  const [loading, setLoading]   = useState(true)
  const [page, setPage]         = useState(1)
  const [days, setDays]         = useState(7)
  const [minScore, setMinScore] = useState(8)

  const load = (p: number, d: number, ms: number) => {
    setLoading(true)
    getZerodays(p, d, ms).then(r => { setData(r); setLoading(false) }).catch(() => setLoading(false))
  }

  useEffect(() => { load(page, days, minScore) }, [page, days, minScore])
  useEffect(() => { const t = setInterval(() => load(page, days, minScore), 60000); return () => clearInterval(t) }, [page, days, minScore])

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">🎯 Zero-Day Candidates</h1>
        <p className="page-sub">Evidence-backed candidates with <strong style={{ color: 'var(--red)' }}>NO CVE ID</strong>. Confidence is calculated from exploitation language, PoC evidence, corroboration and source reputation.</p>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <div className="tabs">
          {[3, 7, 14, 30].map(d => (
            <button key={d} className={`btn ${days === d ? 'active' : ''}`} onClick={() => { setDays(d); setPage(1) }}>{d}d</button>
          ))}
        </div>
        <div className="tabs">
          {[8, 12, 16, 20].map(s => (
            <button key={s} className={`btn ${minScore === s ? 'active' : ''}`} onClick={() => { setMinScore(s); setPage(1) }}>≥{s}</button>
          ))}
        </div>
        {data && <span style={{ fontSize: 13, color: 'var(--text3)', marginLeft: 'auto' }}>{data.total} candidates</span>}
      </div>

      {loading ? <Spinner /> : !data || data.items.length === 0 ? (
        <Empty msg="No zero-day candidates. Try lowering min score or expanding time range." />
      ) : (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {data.items.map(item => <VulnCard key={item.id} item={item} />)}
          </div>
          <Pagination page={data.page} pages={data.pages} total={data.total} onPage={p => setPage(p)} />
        </>
      )}
    </div>
  )
}
