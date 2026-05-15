import { useEffect, useState } from 'react'
import { getAuditStats, AuditStats } from '../api'
import { Spinner } from '../components'

const EVENT_COLORS: Record<string, string> = {
  item_passed:        'var(--green)',
  item_novel:         'var(--cyan)',
  trending_detected:  'var(--orange)',
  notification_sent:  'var(--yellow)',
  item_dropped:       'var(--text3)',
  item_duplicate:     'var(--text3)',
  item_collected:     'var(--text2)',
  storage_saved:      'var(--accent)',
  worker_start:       'var(--green)',
  system_start:       'var(--green)',
  error:              'var(--red)',
  worker_error:       'var(--red)',
}

export default function AuditLog() {
  const [stats, setStats] = useState<AuditStats | null>(null)
  const [loading, setLoading] = useState(true)

  const load = () => {
    getAuditStats().then(s => { setStats(s); setLoading(false) }).catch(() => setLoading(false))
  }

  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t) }, [])

  if (loading) return <Spinner />

  const passRate = stats && stats.items_collected > 0
    ? ((stats.items_passed / stats.items_collected) * 100).toFixed(1)
    : '0'

  const dropRate = stats && stats.items_collected > 0
    ? ((stats.items_dropped / stats.items_collected) * 100).toFixed(1)
    : '0'

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">📋 System Audit</h1>
        <p className="page-sub">Live pipeline counters — auto-refreshes every 10s. Full audit trail in <code style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>logs/audit.jsonl</code></p>
      </div>

      {stats && (
        <>
          {/* Counter grid */}
          <div className="grid-3" style={{ marginBottom: 20 }}>
            {[
              { label: 'Items Collected',   value: stats.items_collected,   color: 'var(--text)',   icon: '📡' },
              { label: 'Passed Filter',     value: stats.items_passed,      color: 'var(--green)',  icon: '✅' },
              { label: 'Dropped (noise)',   value: stats.items_dropped,     color: 'var(--text3)',  icon: '🗑️' },
              { label: 'Notifications Sent',value: stats.notifications,     color: 'var(--yellow)', icon: '🔔' },
              { label: 'Trending Alerts',   value: stats.trending_alerts,   color: 'var(--orange)', icon: '🔥' },
              { label: 'Errors',            value: stats.errors,            color: 'var(--red)',    icon: '⚠️' },
            ].map(s => (
              <div key={s.label} className="stat-card" style={{ borderTopColor: s.color }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 18 }}>{s.icon}</span>
                  <span className="stat-value" style={{ color: s.color, fontSize: 26 }}>{s.value.toLocaleString()}</span>
                </div>
                <div className="stat-label">{s.label}</div>
              </div>
            ))}
          </div>

          {/* Pass/drop rates */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="section-title" style={{ marginBottom: 14 }}>Pipeline Efficiency</div>
            <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap' }}>
              <div>
                <div style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--green)' }}>{passRate}%</div>
                <div style={{ fontSize: 12, color: 'var(--text3)' }}>Signal pass rate</div>
              </div>
              <div>
                <div style={{ fontSize: 28, fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text3)' }}>{dropRate}%</div>
                <div style={{ fontSize: 12, color: 'var(--text3)' }}>Noise drop rate</div>
              </div>
              <div style={{ flex: 1, display: 'flex', alignItems: 'center' }}>
                <div style={{ width: '100%', height: 10, background: 'var(--bg4)', borderRadius: 5, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${passRate}%`, background: 'linear-gradient(90deg, var(--green), var(--accent))', borderRadius: 5 }} />
                </div>
              </div>
            </div>
          </div>

          {/* How to view full log */}
          <div className="card">
            <div className="section-title" style={{ marginBottom: 12 }}>📁 Full Audit Trail</div>
            <p style={{ fontSize: 13, color: 'var(--text2)', marginBottom: 12 }}>
              Every system action is written to <code style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>evvp-backend/logs/audit.jsonl</code> (machine-readable) and <code style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>logs/audit.log</code> (human-readable).
            </p>
            <div style={{ background: 'var(--bg3)', borderRadius: 8, padding: '14px 16px', fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text2)', lineHeight: 1.8 }}>
              <div style={{ color: 'var(--text3)', marginBottom: 6 }}># Watch live in terminal:</div>
              <div style={{ color: 'var(--green)' }}>tail -f evvp-backend/logs/audit.log</div>
              <div style={{ color: 'var(--text3)', marginTop: 10, marginBottom: 6 }}># Query machine-readable log:</div>
              <div style={{ color: 'var(--green)' }}>cat evvp-backend/logs/audit.jsonl | python3 -m json.tool | grep "item_novel"</div>
              <div style={{ color: 'var(--text3)', marginTop: 10, marginBottom: 6 }}># API endpoint:</div>
              <div style={{ color: 'var(--cyan)' }}>GET http://localhost:8000/api/audit?n=100</div>
              <div style={{ color: 'var(--cyan)' }}>GET http://localhost:8000/api/audit/stats</div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
