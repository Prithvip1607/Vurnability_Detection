import { useEffect, useState } from 'react'
import { getStats, getAuditStats, getTrending, Stats, AuditStats, TrendingCVE } from '../api'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { Spinner, scoreColor } from '../components'
import { Link } from 'react-router-dom'

const P_COLORS: Record<string, string> = {
  reddit: '#ff6314', github: '#8b949e', blog: '#06b6d4', nvd: '#a855f7'
}

function StatCard({ label, value, sub, color, to }: {
  label: string; value: number | string; sub?: string; color?: string; to?: string
}) {
  const inner = (
    <div className="stat-card" style={{ borderTopColor: color || 'var(--accent)', cursor: to ? 'pointer' : 'default' }}>
      <div className="stat-value" style={{ color: color || 'var(--text)' }}>{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
  return to ? <Link to={to} style={{ textDecoration: 'none' }}>{inner}</Link> : inner
}

function PipelineStep({ icon, label, value, color }: { icon: string; label: string; value: number; color: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <div style={{ fontSize: 22 }}>{icon}</div>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 18, fontWeight: 700, color }}>{value.toLocaleString()}</div>
      <div style={{ fontSize: 11, color: 'var(--text3)', textAlign: 'center' }}>{label}</div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [audit, setAudit] = useState<AuditStats | null>(null)
  const [trending, setTrending] = useState<TrendingCVE[]>([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    Promise.all([getStats(), getAuditStats(), getTrending(24, 10)])
      .then(([s, a, t]) => { setStats(s); setAudit(a); setTrending(t); setLoading(false) })
      .catch(() => setLoading(false))
  }

  useEffect(() => { load(); const t = setInterval(load, 60000); return () => clearInterval(t) }, [])

  if (loading) return <Spinner />

  const timelineData = stats ? Object.entries(stats.timeline).slice(-7).map(([date, counts]) => ({
    date: date.slice(5), ...counts
  })) : []

  const passRate = audit && audit.items_collected > 0
    ? Math.round((audit.items_passed / audit.items_collected) * 100)
    : 0

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">⚡ Intelligence Dashboard</h1>
        <p className="page-sub">Real-time vulnerability intelligence — auto-refreshes every 60s</p>
      </div>

      {/* Top stats */}
      <div className="grid-6" style={{ marginBottom: 20 }}>
        <StatCard label="Total Stored" value={stats?.total || 0} sub="All platforms" color="var(--accent)" to="/vulns" />
        <StatCard label="Last 24h" value={stats?.recent_24h || 0} sub="New findings" color="var(--green)" to="/vulns" />
        <StatCard label="Reddit" value={stats?.by_platform.reddit || 0} color="#ff6314" to="/feed/reddit" />
        <StatCard label="GitHub" value={stats?.by_platform.github || 0} color="#8b949e" to="/feed/github" />
        <StatCard label="Blogs" value={stats?.by_platform.blog || 0} color="var(--cyan)" to="/feed/blog" />
        <StatCard label="NVD" value={stats?.by_platform.nvd || 0} color="var(--purple)" to="/feed/nvd" />
      </div>

      {/* Pipeline flow */}
      {audit && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="section-header">
            <span className="section-title">🔄 Ingestion Pipeline — Live Counters</span>
            <Link to="/audit" style={{ fontSize: 12, color: 'var(--accent)' }}>View full audit →</Link>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 0, overflowX: 'auto', paddingBottom: 4 }}>
            <PipelineStep icon="📡" label="Collected" value={audit.items_collected} color="var(--text)" />
            <div style={{ flex: 1, height: 2, background: 'var(--border)', minWidth: 20 }} />
            <PipelineStep icon="✅" label="Passed Filter" value={audit.items_passed} color="var(--green)" />
            <div style={{ flex: 1, height: 2, background: 'var(--border)', minWidth: 20 }} />
            <PipelineStep icon="🗑️" label="Dropped (noise)" value={audit.items_dropped} color="var(--text3)" />
            <div style={{ flex: 1, height: 2, background: 'var(--border)', minWidth: 20 }} />
            <PipelineStep icon="🔔" label="Notifications" value={audit.notifications} color="var(--yellow)" />
            <div style={{ flex: 1, height: 2, background: 'var(--border)', minWidth: 20 }} />
            <PipelineStep icon="🔥" label="Trending Alerts" value={audit.trending_alerts} color="var(--orange)" />
            <div style={{ flex: 1, height: 2, background: 'var(--border)', minWidth: 20 }} />
            <PipelineStep icon="⚠️" label="Errors" value={audit.errors} color="var(--red)" />
          </div>
          <div style={{ marginTop: 14, fontSize: 12, color: 'var(--text3)', textAlign: 'center' }}>
            Signal pass rate: <span style={{ color: passRate > 5 ? 'var(--green)' : 'var(--yellow)', fontFamily: 'var(--mono)', fontWeight: 700 }}>{passRate}%</span>
            &nbsp;·&nbsp; {audit.items_passed} high-signal items stored out of {audit.items_collected} collected
          </div>
        </div>
      )}

      <div className="grid-2" style={{ marginBottom: 20 }}>
        {/* Timeline chart */}
        <div className="card">
          <div className="section-header">
            <span className="section-title">📈 Collection Timeline (7 days)</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={timelineData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <XAxis dataKey="date" tick={{ fill: '#4a5a72', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#4a5a72', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: 'var(--bg3)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }} labelStyle={{ color: 'var(--text)' }} />
              {['reddit', 'github', 'blog', 'nvd'].map(p => (
                <Bar key={p} dataKey={p} stackId="a" fill={P_COLORS[p]} radius={p === 'nvd' ? [3, 3, 0, 0] : [0, 0, 0, 0]} />
              ))}
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', gap: 16, marginTop: 10, flexWrap: 'wrap' }}>
            {Object.entries(P_COLORS).map(([p, c]) => (
              <div key={p} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: c, display: 'inline-block' }} />
                <span style={{ color: 'var(--text2)' }}>{p}</span>
                <span style={{ color: 'var(--text)', fontFamily: 'var(--mono)', fontWeight: 600 }}>
                  {stats?.by_platform[p] || 0}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Trending CVEs */}
        <div className="card">
          <div className="section-header">
            <span className="section-title">🔥 Trending CVEs (24h)</span>
            <Link to="/trending" style={{ fontSize: 12, color: 'var(--accent)' }}>See all →</Link>
          </div>
          {trending.length === 0 ? (
            <div style={{ color: 'var(--text3)', fontSize: 13, padding: '20px 0', textAlign: 'center' }}>
              No trending CVEs yet — run collectors to populate
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {trending.slice(0, 6).map((t, i) => (
                <div key={t.cve_id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: 12, width: 18 }}>{i + 1}</span>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 13, fontWeight: 700, color: '#c084fc', minWidth: 140 }}>{t.cve_id}</span>
                  <div style={{ flex: 1, height: 5, background: 'var(--bg4)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${Math.min((t.mention_count / (trending[0]?.mention_count || 1)) * 100, 100)}%`, background: 'linear-gradient(90deg, var(--purple), var(--accent))', borderRadius: 3 }} />
                  </div>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 12, fontWeight: 700, color: 'var(--text)', minWidth: 28, textAlign: 'right' }}>{t.mention_count}</span>
                  <div style={{ display: 'flex', gap: 3 }}>
                    {t.sources.map(s => <span key={s} className={`badge badge-${s}`}>{s[0].toUpperCase()}</span>)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Sources status */}
      <div className="card">
        <div className="section-title" style={{ marginBottom: 14 }}>📡 Active Sources</div>
        <div className="grid-4">
          {[
            { name: 'Reddit', icon: '🟠', color: '#ff6314', desc: '12 subreddits · JSON + RSS', interval: 'Every 5 min' },
            { name: 'GitHub', icon: '⚫', color: '#8b949e', desc: '25 exploit keywords · repos, issues, commits', interval: 'Every 10 min' },
            { name: 'Blogs / RSS', icon: '🔵', color: '#06b6d4', desc: '18 security feeds', interval: 'Every 15 min' },
            { name: 'NVD', icon: '🟣', color: '#a855f7', desc: 'NIST CVE database · CVSS enrichment', interval: 'Every 1 hour' },
          ].map(s => (
            <div key={s.name} className="card-sm" style={{ borderLeft: `3px solid ${s.color}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 16 }}>{s.icon}</span>
                <span style={{ fontWeight: 600, fontSize: 14 }}>{s.name}</span>
                <span style={{ marginLeft: 'auto', width: 7, height: 7, borderRadius: '50%', background: 'var(--green)', display: 'inline-block' }} />
              </div>
              <div style={{ fontSize: 12, color: 'var(--text3)', marginBottom: 4 }}>{s.desc}</div>
              <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>⏱ {s.interval}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
