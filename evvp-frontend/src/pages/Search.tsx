import { useState } from 'react'
import { search, IntelItem, Paginated } from '../api'
import { VulnCard, Spinner, Empty, Pagination } from '../components'

export default function Search() {
  const [q, setQ]           = useState('')
  const [data, setData]     = useState<Paginated<IntelItem> | null>(null)
  const [loading, setLoading] = useState(false)
  const [page, setPage]     = useState(1)
  const [days, setDays]     = useState(30)

  const doSearch = (p: number) => {
    if (q.trim().length < 3) return
    setLoading(true)
    search(q.trim(), p, days).then(r => { setData(r); setLoading(false) }).catch(() => setLoading(false))
  }

  const handleKey = (e: React.KeyboardEvent) => { if (e.key === 'Enter') { setPage(1); doSearch(1) } }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">🔍 Search Intelligence</h1>
        <p className="page-sub">Full-text search across all collected vulnerability intelligence.</p>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          className="search-input"
          type="text"
          placeholder="Search CVE ID, product, exploit type..."
          value={q}
          onChange={e => setQ(e.target.value)}
          onKeyDown={handleKey}
          autoFocus
        />
        <div className="tabs">
          {[7, 14, 30, 90].map(d => (
            <button key={d} className={`btn ${days === d ? 'active' : ''}`} onClick={() => setDays(d)}>{d}d</button>
          ))}
        </div>
        <button className="btn active" onClick={() => { setPage(1); doSearch(1) }}>Search</button>
      </div>

      {data && (
        <div style={{ marginBottom: 14, fontSize: 13, color: 'var(--text3)' }}>
          <strong style={{ color: 'var(--text)', fontFamily: 'var(--mono)' }}>{data.total}</strong> results for "{q}"
        </div>
      )}

      {loading ? <Spinner /> : !data ? (
        <div className="empty">Type a query and press Enter or click Search</div>
      ) : data.items.length === 0 ? (
        <Empty msg={`No results for "${q}". Try a different term or expand the time range.`} />
      ) : (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {data.items.map(item => <VulnCard key={item.id} item={item} />)}
          </div>
          <Pagination page={data.page} pages={data.pages} total={data.total} onPage={p => { setPage(p); doSearch(p) }} />
        </>
      )}
    </div>
  )
}
