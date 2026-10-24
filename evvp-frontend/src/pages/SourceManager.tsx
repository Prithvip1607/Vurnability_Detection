import { useEffect, useState } from 'react'

type Source = {
  id: string
  name: string
  url: string
  type: string
  enabled: boolean
  status: string
  last_fetched?: string | null
  last_success?: string | null
  last_error?: string | null
}

export default function SourceManager() {
  const [sources, setSources] = useState<Source[]>([])
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  const load = async () => {
    const r = await fetch('/api/sources')
    const data = await r.json()
    setSources(data.sources || [])
  }

  useEffect(() => { load().catch(e => setMessage(String(e))) }, [])

  const test = async () => {
    setBusy(true); setMessage('')
    try {
      const r = await fetch('/api/sources/test', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ url })
      })
      const data = await r.json()
      setMessage(data.valid
        ? `✓ Valid ${data.feed_title || 'RSS/Atom'} feed — ${data.entry_count} entries found`
        : `✗ ${data.error || 'Invalid feed'}`)
    } finally { setBusy(false) }
  }

  const add = async () => {
    setBusy(true); setMessage('')
    try {
      const r = await fetch('/api/sources', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name, url, type: 'rss'})
      })
      const data = await r.json()
      if (!r.ok) { setMessage(`✗ ${data.error || 'Unable to add source'}`); return }
      setName(''); setUrl('')
      setMessage('✓ Source added successfully.')
      await load()
    } finally { setBusy(false) }
  }

  const toggle = async (s: Source) => {
    await fetch(`/api/sources/${s.id}`, {
      method: 'PATCH',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enabled: !s.enabled})
    })
    await load()
  }

  const remove = async (s: Source) => {
    if (!window.confirm(`Delete ${s.name}?`)) return
    await fetch(`/api/sources/${s.id}`, {method: 'DELETE'})
    await load()
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1>Source Intelligence Manager</h1>
          <p className="muted">Add and control RSS/Atom security intelligence sources without editing backend code.</p>
        </div>
      </div>

      <div className="card" style={{maxWidth: 850, marginBottom: 20}}>
        <h2 style={{marginTop: 0}}>Add New Source</h2>
        <div style={{display:'grid', gap:12}}>
          <label>
            <div className="muted" style={{marginBottom:5}}>Site Name</div>
            <input value={name} onChange={e=>setName(e.target.value)} placeholder="e.g. Krebs Security" />
          </label>
          <label>
            <div className="muted" style={{marginBottom:5}}>RSS / Atom Feed URL</div>
            <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://example.com/feed.xml" />
          </label>
          <div style={{display:'flex', gap:8}}>
            <button onClick={test} disabled={!url || busy}>Test Feed</button>
            <button onClick={add} disabled={!name || !url || busy}>Add Source</button>
          </div>
          {message && <div style={{marginTop:4}}>{message}</div>}
        </div>
      </div>

      <div className="card">
        <h2 style={{marginTop:0}}>Configured Sources</h2>
        {sources.length === 0 && <p className="muted">No sources configured.</p>}
        <div style={{display:'grid', gap:10}}>
          {sources.map(s => (
            <div key={s.id} style={{border:'1px solid var(--border)', padding:14, borderRadius:8}}>
              <div style={{display:'flex', justifyContent:'space-between', gap:12, alignItems:'flex-start'}}>
                <div>
                  <div style={{fontWeight:700}}>{s.enabled ? '🟢' : '⚪'} {s.name}</div>
                  <div className="muted" style={{fontSize:12, wordBreak:'break-all', marginTop:4}}>{s.url}</div>
                  <div className="muted" style={{fontSize:11, marginTop:5}}>
                    {s.type.toUpperCase()} · Status: {s.status || 'unknown'}
                    {s.last_success ? ` · Last success: ${new Date(s.last_success).toLocaleString()}` : ''}
                  </div>
                  {s.last_error && <div style={{fontSize:12, marginTop:5}}>Error: {s.last_error}</div>}
                </div>
                <div style={{display:'flex', gap:6, flexShrink:0}}>
                  <button onClick={()=>toggle(s)}>{s.enabled ? 'Disable' : 'Enable'}</button>
                  <button onClick={()=>remove(s)}>Delete</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
