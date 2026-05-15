import { NavLink, Outlet } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { getHealth } from './api'

const NAV = [
  { section: 'OVERVIEW' },
  { to: '/',            icon: '⚡', label: 'Dashboard'      },
  { to: '/audit',       icon: '📋', label: 'System Audit'   },
  { section: 'INTELLIGENCE' },
  { to: '/vulns',       icon: '🔎', label: 'All Findings'   },
  { to: '/zerodays',    icon: '🎯', label: 'Zero-Days'      },
  { to: '/cves',        icon: '🛡️', label: 'CVEs'           },
  { to: '/trending',    icon: '🔥', label: 'Trending'       },
  { to: '/verified',    icon: '🔬', label: 'Verified'       },
  { section: 'SOURCES' },
  { to: '/feed/reddit', icon: '🟠', label: 'Reddit'         },
  { to: '/feed/github', icon: '⚫', label: 'GitHub'         },
  { to: '/feed/blog',   icon: '🔵', label: 'Blogs / RSS'    },
  { to: '/feed/nvd',    icon: '🟣', label: 'NVD Feed'       },
  { section: 'TOOLS' },
  { to: '/search',      icon: '🔍', label: 'Search'         },
]

export default function Layout() {
  const [online, setOnline] = useState<boolean | null>(null)

  useEffect(() => {
    const check = () => getHealth().then(() => setOnline(true)).catch(() => setOnline(false))
    check()
    const t = setInterval(check, 30000)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-title">
            <span style={{ color: 'var(--accent)' }}>EVVP</span> Intel
          </div>
          <div className="sidebar-logo-sub">Early Vuln Verification</div>
        </div>

        <nav className="sidebar-nav">
          {NAV.map((item, i) => {
            if ('section' in item) {
              return <div key={i} className="nav-section">{item.section}</div>
            }
            return (
              <NavLink
                key={item.to}
                to={item.to!}
                end={item.to === '/'}
                className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
              >
                <span className="icon">{item.icon}</span>
                <span>{item.label}</span>
              </NavLink>
            )
          })}
        </nav>

        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', color: 'var(--text3)' }}>
            <span className="status-dot" style={{
              background: online === null ? 'var(--text3)' : online ? 'var(--green)' : 'var(--red)'
            }} />
            {online === null ? 'Connecting...' : online ? 'Backend Online' : 'Backend Offline'}
          </div>
          <div style={{ color: 'var(--text3)', marginTop: 4, fontFamily: 'var(--mono)', fontSize: 11 }}>
            localhost:8000
          </div>
        </div>
      </aside>

      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
