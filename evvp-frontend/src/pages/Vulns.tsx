// All Vulnerabilities — the analyst view
// Every fetched item: full description, published date, source link, signals
// Store everything — miss nothing

import { useEffect, useState, useCallback } from 'react'
import { getFeed, IntelItem, Paginated } from '../api'
import { VulnCard, Spinner, Empty, Pagination } from '../components'

const PLATFORMS = ['all', 'reddit', 'github', 'blog', 'nvd']
const DAYS_OPTIONS = [1, 3, 7, 14, 30]
const SORT_OPTIONS = [
  { value: 'score', label: 'Signal Score' },
  { value: 'date',  label: 'Date' },
]

export default function Vulns() {
  const [platform, setPlatform] = useState('all')
  const [days, setDays]         = useState(7)
  const [page, setPage]         = useState(1)
  const [data, setData]         = useState<Paginated<IntelItem> | null>(null)
  const [loading, setLoading]   = useState(true)
  const [sort, setSort]         = useState('score')
  const [filter, setFilter]     = useState('')   // quick title filter

  const load = useCallback((pl: string, p: number, d: number) => {
    setLoading(true)
    getFeed(pl, p, 50, d)
      .then(r => { setData(r); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  useEffect(() => { load(platform, page, days) }, [platform, page, days, load])

  const switchPlatform = (p: string) => { setPlatform(p); setPage(1) }
  const switchDays     = (d: number) => { setDays(d); setPage(1) }

  // Client-side filter + sort on current page
  const displayed = (() => {
    if (!data) return []
    let items = [...data.items]
    if (filter.trim()) {
      const q = filter.toLowerCase()
      items = items.filter(i =>
        i.title?.toLowerCase().includes(q) ||
        i.text?.toLowerCase().includes(q) ||
        i.cve_ids?.some(c => c.toLowerCase().includes(q))
      )
    }
    if (sort === 'date') {
      items.sort((a, b) => new Date(b.collected_at).getTime() - new Date(a.collected_at).getTime())
    }
    return items
  })()

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">🔎 All Vulnerability Findings</h1>
        <p className="page-sub">
          Every item fetched from all sources — full description, published date, source link.
          <strong style={{ color: 'var(--yellow)' }}> We store everything. Miss nothing.</strong>
        </p>
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 16, alignItems: 'center' }}>
        {/* Platform tabs */}
        <div className="tabs">
          {PLATFORMS.map(p => (
            <button key={p} className={`btn ${platform === p ? 'active' : ''}`} onClick={() => switchPlatform(p)}>
              {p === 'all' ? '🌐 All' : p === 'reddit' ? '🟠 Reddit' : p === 'github' ? '⚫ GitHub' : p === 'blog' ? '🔵 Blog' : '🟣 NVD'}
            </button>
          ))}
        </div>

        {/* Days */}
        <div className="tabs">
          {DAYS_OPTIONS.map(d => (
            <button key={d} className={`btn ${days === d ? 'active' : ''}`} onClick={() => switchDays(d)}>
              {d}d
            </button>
          ))}
        </div>

        {/* Sort */}
        <select value={sort} onChange={e => setSort(e.target.value)} style={{ fontSize: 13 }}>
          {SORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>

        {/* Quick filter */}
        <input
          type="text"
          placeholder="Filter by title / CVE..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ fontSize: 13, minWidth: 220 }}
        />
      </div>

      {/* Count */}
      {data && (
        <div style={{ marginBottom: 14, fontSize: 13, color: 'var(--text3)', display: 'flex', gap: 16 }}>
          <span>
            <strong style={{ color: 'var(--text)', fontFamily: 'var(--mono)' }}>{data.total}</strong> total findings
          </span>
          {filter && (
            <span>
              <strong style={{ color: 'var(--accent)', fontFamily: 'var(--mono)' }}>{displayed.length}</strong> matching filter
            </span>
          )}
          <span style={{ marginLeft: 'auto', color: 'var(--text3)' }}>
            Sorted by {sort === 'score' ? 'signal score ↓' : 'date ↓'}
          </span>
        </div>
      )}

      {loading ? <Spinner /> : !data || displayed.length === 0 ? (
        <Empty msg={filter ? `No items matching "${filter}"` : 'No findings in this window. Run collectors first.'} />
      ) : (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {displayed.map(item => <VulnCard key={item.id} item={item} />)}
          </div>
          {!filter && (
            <Pagination page={data.page} pages={data.pages} total={data.total} onPage={p => setPage(p)} />
          )}
        </>
      )}
    </div>
  )
}
