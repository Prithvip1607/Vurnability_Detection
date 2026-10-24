import { useEffect, useState } from 'react'
import { getThreatLandscape, ThreatLandscape } from '../api'
import { Spinner, Empty, SeverityBadge } from '../components'
import { Link } from 'react-router-dom'

export default function ThreatLandscapePage() {
  const [data, setData] = useState<ThreatLandscape | null>(null)
  const [days, setDays] = useState(30)
  useEffect(() => { getThreatLandscape(days).then(setData).catch(() => setData(null)) }, [days])
  if (!data) return <Spinner />
  const cards = [
    ['Findings', data.total, 'var(--accent)'], ['Critical', data.critical, 'var(--red)'],
    ['High', data.high, 'var(--orange)'], ['Zero-Day Candidates', data.zero_day_candidates, 'var(--red)'],
    ['Active Exploitation', data.active_exploitation, 'var(--yellow)'], ['Average Risk', data.average_risk, 'var(--cyan)'],
  ]
  return <div className="page">
    <div className="page-header"><h1 className="page-title">🌐 Threat Landscape</h1><p className="page-sub">Risk-aware overview of collected vulnerability intelligence.</p></div>
    <div className="tabs" style={{marginBottom:20}}>{[7,30,90].map(d => <button className={`btn ${days===d?'active':''}`} onClick={()=>setDays(d)} key={d}>{d}d</button>)}</div>
    <div className="grid-6" style={{marginBottom:20}}>{cards.map(([label,value,color])=><div className="stat-card" key={String(label)} style={{borderTopColor:String(color)}}><div className="stat-value" style={{color:String(color)}}>{String(value)}</div><div className="stat-label">{String(label)}</div></div>)}</div>
    <div className="grid-2">
      <div className="card"><div className="section-title" style={{marginBottom:14}}>Severity Distribution</div>{[['CRITICAL',data.critical],['HIGH',data.high],['MEDIUM',data.medium],['LOW',data.low]].map(([s,n])=><div key={String(s)} style={{display:'flex',gap:10,alignItems:'center',margin:'10px 0'}}><SeverityBadge severity={String(s)}/><div style={{flex:1,height:8,background:'var(--bg4)',borderRadius:4}}><div style={{height:'100%',width:`${data.total?Number(n)/data.total*100:0}%`,background:'var(--accent)',borderRadius:4}}/></div><span style={{fontFamily:'var(--mono)'}}>{String(n)}</span></div>)}</div>
      <div className="card"><div className="section-title" style={{marginBottom:14}}>Top Risk Findings</div>{data.top_risk_items.length===0?<Empty/>:data.top_risk_items.slice(0,8).map(i=><Link key={i.id} to={`/item/${i.id}`} style={{display:'flex',justifyContent:'space-between',gap:12,padding:'9px 0',borderBottom:'1px solid var(--border)',textDecoration:'none',color:'var(--text)'}}><span style={{fontSize:13,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{i.title}</span><strong style={{fontFamily:'var(--mono)',color:'var(--red)'}}>{i.intelligence?.risk_score ?? i.risk_score ?? 0}</strong></Link>)}</div>
    </div>
  </div>
}
