import { useEffect, useState } from 'react'
import { getCves, IntelItem, Paginated } from '../api'
import { VulnCard, Spinner, Empty, Pagination } from '../components'

export default function CVEs() {
  const [data, setData]         = useState<Paginated<IntelItem> | null>(null)
  const [loading, setLoading]   = useState(true)
  const [page, setPage]         = useState(1)
  const [days, setDays]         = useState(7)
  const [minScore, setMinScore] = useState(6)

  const load = (p: number, d: number, ms: number) => {
    setLoading(true)
    getCves(p, d, ms).then(r => { setData(r); setLoading(false) }).catch(() => setLoading(false))
  }

  useEffect(() => { load(page, days, minScore) }, [page, days, minScore])
  useEffect(() => { const t = setInterval(() => load(page, days, minScore), 60000); return () => clearInterval(t) }, [page, days, minScore])

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">🛡️ CVE Discussions</h1>
        <p className="page-sub">Items with CVE IDs actively being discussed — disclosed vulnerabilities with PoCs, exploits, or active exploitation chatter.</p>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <div className="tabs">
          {[3, 7, 14, 30].map(d => (
            <button key={d} className={`btn ${days === d ? 'active' : ''}`} onClick={() => { setDays(d); setPage(1) }}>{d}d</button>
          ))}
        </div>
        <div className="tabs">
          {[6, 10, 14].map(s => (
            <button key={s} className={`btn ${minScore === s ? 'active' : ''}`} onClick={() => { setMinScore(s); setPage(1) }}>≥{s}</button>
          ))}
        </div>
        {data && <span style={{ fontSize: 13, color: 'var(--text3)', marginLeft: 'auto' }}>{data.total} CVE discussions</span>}
      </div>

      {loading ? <Spinner /> : !data || data.items.length === 0 ? (
        <Empty msg="No CVE discussions found. Try expanding the time range." />
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
