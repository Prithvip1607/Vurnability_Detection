import { useEffect, useState } from 'react'
import { getVerified, VerificationResult, Paginated } from '../api'
import { Spinner, Empty, Pagination } from '../components'

const STATUS_CONFIG = {
  confirmed:  { color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.3)',  icon: '✅', label: 'CONFIRMED'  },
  likely:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)', icon: '⚠️', label: 'LIKELY'     },
  unverified: { color: '#eab308', bg: 'rgba(234,179,8,0.12)',  border: 'rgba(234,179,8,0.3)',  icon: '🔍', label: 'UNVERIFIED' },
  noise:      { color: '#64748b', bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.2)',icon: '🔇', label: 'NOISE'      },
}

function CredBar({ score }: { score: number }) {
  const color = score >= 70 ? '#22c55e' : score >= 45 ? '#f97316' : score >= 20 ? '#eab308' : '#64748b'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, background: 'var(--bg4)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${score}%`, background: color, borderRadius: 3, transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 12, fontWeight: 700, color, minWidth: 28 }}>{score}</span>
    </div>
  )
}

function VerifCard({ vr }: { vr: VerificationResult }) {
  const cfg = STATUS_CONFIG[vr.verification_status] || STATUS_CONFIG.unverified
  return (
    <div style={{
      background: 'var(--bg2)', border: `1px solid var(--border)`,
      borderLeft: `3px solid ${cfg.color}`, borderRadius: 10, padding: '16px 20px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <span style={{ fontSize: 16 }}>{cfg.icon}</span>
        <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700, background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}` }}>
          {cfg.label}
        </span>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text3)', marginLeft: 'auto' }}>
          {vr.verified_at?.slice(0, 16).replace('T', ' ')} UTC
        </span>
      </div>

      <div style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 12, color: 'var(--text3)', marginBottom: 4 }}>Credibility Score</div>
        <CredBar score={vr.credibility_score} />
      </div>

      <div className="grid-3" style={{ gap: 10, marginBottom: 12 }}>
        <div style={{ background: 'var(--bg3)', borderRadius: 6, padding: '8px 12px' }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 3 }}>PoC Found</div>
          <div style={{ fontWeight: 700, color: vr.poc_found ? '#22c55e' : 'var(--text3)', fontSize: 13 }}>
            {vr.poc_found ? '✅ Yes' : '❌ No'}
          </div>
        </div>
        <div style={{ background: 'var(--bg3)', borderRadius: 6, padding: '8px 12px' }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 3 }}>In NVD</div>
          <div style={{ fontWeight: 700, color: vr.in_nvd ? '#22c55e' : 'var(--text3)', fontSize: 13 }}>
            {vr.in_nvd ? `✅ ${vr.in_nvd_at?.slice(0, 10) || 'Yes'}` : '❌ Not yet'}
          </div>
        </div>
        <div style={{ background: 'var(--bg3)', borderRadius: 6, padding: '8px 12px' }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 3 }}>Cross-Source</div>
          <div style={{ fontWeight: 700, color: vr.cross_source_count >= 3 ? '#22c55e' : 'var(--text2)', fontSize: 13 }}>
            {vr.cross_source_count} source{vr.cross_source_count !== 1 ? 's' : ''}
          </div>
        </div>
      </div>

      {vr.affected_products?.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 5 }}>Affected Products</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {vr.affected_products.map(p => (
              <span key={p} style={{ padding: '2px 7px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 4, fontSize: 11, color: '#fca5a5', fontFamily: 'var(--mono)' }}>{p}</span>
            ))}
          </div>
        </div>
      )}

      {vr.poc_signals?.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 5 }}>PoC Signals</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {vr.poc_signals.slice(0, 8).map(s => (
              <span key={s} className="signal-tag">{s}</span>
            ))}
          </div>
        </div>
      )}

      {vr.credibility_notes?.length > 0 && (
        <div style={{ background: 'var(--bg3)', borderRadius: 6, padding: '8px 12px' }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 5 }}>Credibility Reasoning</div>
          {vr.credibility_notes.map((n, i) => (
            <div key={i} style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>· {n}</div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function Verified() {
  const [data, setData]     = useState<Paginated<VerificationResult> | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage]     = useState(1)
  const [days, setDays]     = useState(7)
  const [status, setStatus] = useState('')

  const load = (p: number, d: number, s: string) => {
    setLoading(true)
    getVerified(p, d, s).then(r => { setData(r); setLoading(false) }).catch(() => setLoading(false))
  }

  useEffect(() => { load(page, days, status) }, [page, days, status])
  useEffect(() => { const t = setInterval(() => load(page, days, status), 60000); return () => clearInterval(t) }, [page, days, status])

  const counts = data?.items.reduce((acc, r) => {
    acc[r.verification_status] = (acc[r.verification_status] || 0) + 1
    return acc
  }, {} as Record<string, number>) || {}

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">🔬 Verification Results</h1>
        <p className="page-sub">Phase 3 — PoC detection, affected product extraction, credibility scoring. Every novel item is automatically verified.</p>
      </div>

      {data && (
        <div className="grid-4" style={{ marginBottom: 20 }}>
          {Object.entries(STATUS_CONFIG).map(([s, cfg]) => (
            <div key={s} className="stat-card" style={{ borderTopColor: cfg.color, cursor: 'pointer' }}
              onClick={() => { setStatus(status === s ? '' : s); setPage(1) }}>
              <div style={{ fontSize: 22, marginBottom: 4 }}>{cfg.icon}</div>
              <div className="stat-value" style={{ color: cfg.color, fontSize: 24 }}>{counts[s] || 0}</div>
              <div className="stat-label">{cfg.label}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <div className="tabs">
          {[3, 7, 14, 30].map(d => (
            <button key={d} className={`btn ${days === d ? 'active' : ''}`} onClick={() => { setDays(d); setPage(1) }}>{d}d</button>
          ))}
        </div>
        <div className="tabs">
          {['', 'confirmed', 'likely', 'unverified'].map(s => (
            <button key={s} className={`btn ${status === s ? 'active' : ''}`} onClick={() => { setStatus(s); setPage(1) }}>
              {s === '' ? 'All' : STATUS_CONFIG[s as keyof typeof STATUS_CONFIG]?.label || s}
            </button>
          ))}
        </div>
        {data && <span style={{ fontSize: 13, color: 'var(--text3)', marginLeft: 'auto' }}>{data.total} results</span>}
      </div>

      {loading ? <Spinner /> : !data || data.items.length === 0 ? (
        <Empty msg="No verification results yet. Run collectors — novel items are auto-verified." />
      ) : (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {data.items.map(vr => <VerifCard key={vr.id} vr={vr} />)}
          </div>
          <Pagination page={data.page} pages={data.pages} total={data.total} onPage={p => setPage(p)} />
        </>
      )}
    </div>
  )
}
