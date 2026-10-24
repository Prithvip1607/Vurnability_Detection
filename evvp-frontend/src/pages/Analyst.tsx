import { useState } from 'react'
import { analystSearch, IntelItem } from '../api'
import { VulnCard, Empty } from '../components'

export default function Analyst() {
  const [q,setQ]=useState(''); const [items,setItems]=useState<IntelItem[]>([]); const [count,setCount]=useState(0); const [loading,setLoading]=useState(false)
  const run=async()=>{ if(q.trim().length<3)return; setLoading(true); try{const r=await analystSearch(q);setItems(r.matches);setCount(r.count)}finally{setLoading(false)} }
  return <div className="page"><div className="page-header"><h1 className="page-title">🤖 Security Analyst Search</h1><p className="page-sub">Evidence-backed retrieval from EVVP's collected intelligence. This is retrieval, not an autonomous security decision.</p></div><div style={{display:'flex',gap:8,marginBottom:18}}><input value={q} onChange={e=>setQ(e.target.value)} onKeyDown={e=>e.key==='Enter'&&run()} placeholder="Try: apache rce, kubernetes, authentication bypass" style={{flex:1}}/><button className="btn active" onClick={run}>Investigate</button></div>{loading?<div className="loading">Searching…</div>:items.length===0?<Empty msg={q?'No matching intelligence found.':'Ask about a product, CVE, technique or vulnerability type.'}/>:<><div style={{fontSize:12,color:'var(--text3)',marginBottom:10}}>{count} matching observations</div><div style={{display:'flex',flexDirection:'column',gap:10}}>{items.map(i=><VulnCard key={i.id} item={i}/>)}</div></>}</div>
}
