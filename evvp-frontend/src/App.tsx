import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './Layout'
import Dashboard  from './pages/Dashboard'
import Vulns      from './pages/Vulns'
import ZeroDays   from './pages/ZeroDays'
import CVEs       from './pages/CVEs'
import Trending   from './pages/Trending'
import Verified   from './pages/Verified'
import Feed       from './pages/Feed'
import Search     from './pages/Search'
import AuditLog   from './pages/AuditLog'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index                  element={<Dashboard />} />
          <Route path="vulns"           element={<Vulns />} />
          <Route path="zerodays"        element={<ZeroDays />} />
          <Route path="cves"            element={<CVEs />} />
          <Route path="trending"        element={<Trending />} />
          <Route path="verified"        element={<Verified />} />
          <Route path="feed/:platform"  element={<Feed />} />
          <Route path="search"          element={<Search />} />
          <Route path="audit"           element={<AuditLog />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
