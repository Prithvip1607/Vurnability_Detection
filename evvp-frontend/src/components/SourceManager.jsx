
import { useEffect, useState } from "react";

export default function SourceManager() {
  const [sources, setSources] = useState([]);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");

  const load = async () => {
    const r = await fetch("/api/sources");
    const data = await r.json();
    setSources(data.sources || []);
  };

  useEffect(() => { load(); }, []);

  const add = async () => {
    setMessage("");
    const r = await fetch("/api/sources", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({name, url, type: "rss"})
    });
    const data = await r.json();
    if (!r.ok) return setMessage(data.error || "Unable to add source");
    setName(""); setUrl("");
    setMessage("Source added successfully.");
    load();
  };

  const test = async () => {
    setMessage("");
    const r = await fetch("/api/sources/test", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url})
    });
    const data = await r.json();
    setMessage(data.valid
      ? `✓ Valid feed: ${data.feed_title || "Untitled"} (${data.entry_count} entries)`
      : `✗ ${data.error || "Invalid feed"}`);
  };

  const toggle = async (s) => {
    await fetch(`/api/sources/${s.id}`, {
      method: "PATCH",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({enabled: !s.enabled})
    });
    load();
  };

  const remove = async (s) => {
    if (!window.confirm(`Delete ${s.name}?`)) return;
    await fetch(`/api/sources/${s.id}`, {method: "DELETE"});
    load();
  };

  return (
    <section style={{padding: 24}}>
      <h2>Source Intelligence Manager</h2>
      <p>Add RSS/Atom security sources without changing backend code.</p>

      <div style={{display:"grid", gap:8, maxWidth:700}}>
        <input placeholder="Site name" value={name} onChange={e=>setName(e.target.value)} />
        <input placeholder="RSS / Atom feed URL" value={url} onChange={e=>setUrl(e.target.value)} />
        <div style={{display:"flex", gap:8}}>
          <button onClick={test}>Test Feed</button>
          <button onClick={add}>Add Source</button>
        </div>
        {message && <div>{message}</div>}
      </div>

      <h3 style={{marginTop:24}}>Configured Sources</h3>
      <div style={{display:"grid", gap:10}}>
        {sources.map(s => (
          <div key={s.id} style={{border:"1px solid #ddd", padding:12, borderRadius:8}}>
            <strong>{s.enabled ? "🟢" : "⚪"} {s.name}</strong>
            <div style={{fontSize:13, wordBreak:"break-all"}}>{s.url}</div>
            <div style={{marginTop:8}}>
              <button onClick={()=>toggle(s)}>{s.enabled ? "Disable" : "Enable"}</button>{" "}
              <button onClick={()=>remove(s)}>Delete</button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
