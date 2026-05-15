import { useEffect, useState } from 'react'
import { getFeed, IntelItem, Paginated } from '../api'
import { VulnCard, Spinner, Empty, Pagination } from '../components'
import { useParams } from 'react-router-dom'

export default function Feed() {
  const { platform = 'all' } = useParams<{ platform: string }>()
  const [data, setData]     = useState<Paginated<IntelItem> | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage]     = useState(1)
  const [days, setDays]     = useState(7)

  useEffect(() => {
    setLoading(true)
    setPage(1)
    getFeed(platform, 1, 50, days).then(r => { setData(r); setLoading(false) }).catch(() => setLoading(false))
  }, [platform, days])

  useEffect(() => {
    if (page === 1) return
    setLoading(true)
    getFeed(platform, page, 50, days).then(r => { setData(r); setLoading(false) }).catch(() => setLoading(false))
  }, [page])

  const label: Record<string, string> = {
    reddit: '🟠 Reddit', github: '⚫ GitHub', blog: '🔵 Blogs / RSS', nvd: '🟣 NVD Feed', all: '🌐 All Sources'
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">{label[platform] || platform}</h1>
        <p className="page-sub">All collected intelligence from this source, sorted by signal score.</p>
      </div>

      <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center' }}>
        <div className="tabs">
          {[3, 7, 14, 30].map(d => (
            <button key={d} className={`btn ${days === d ? 'active' : ''}`} onClick={() => setDays(d)}>{d}d</button>
          ))}
        </div>
        {data && <span style={{ fontSize: 13, color: 'var(--text3)', marginLeft: 'auto' }}>{data.total} items</span>}
      </div>

      {loading ? <Spinner /> : !data || data.items.length === 0 ? (
        <Empty msg="No items found. Run the collector for this source." />
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
