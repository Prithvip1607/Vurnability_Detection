import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

export interface IntelItem {
  id: string
  platform: string
  source: string
  title: string
  text: string
  author: string
  timestamp: string
  url: string
  signal_score: number
  category: string
  matched_signals: string[]
  negative_signals: string[]
  collected_at: string
  cve_ids?: string[]
  nvd_data?: NVDRecord[]
  metadata?: Record<string, unknown>
  sources?: { url: string; platform: string }[]
  summary?: string
  epss?: number
  epss_percentile?: number
  epss_data?: { cve_id: string; epss: number; percentile: number }[]
  intelligence?: Intelligence
  risk_score?: number
  zero_day_score?: number
  zero_day_candidate?: boolean
  zero_day_evidence?: string[]
  attack_techniques?: { id: string; name: string; matched: string }[]
  cross_source_count?: number
}

export interface NVDRecord {
  cve_id: string
  description: string
  cvss_v3?: { score: number; severity: string; vector: string }
  cvss_v2?: { score: number; severity: string }
  published: string
  references: string[]
}

export interface Paginated<T> {
  items: T[]
  total: number
  page: number
  per_page: number
  pages: number
}

export interface Stats {
  total: number
  recent_24h: number
  by_platform: Record<string, number>
  by_category: Record<string, number>
  timeline: Record<string, Record<string, number>>
}

export interface TrendingCVE {
  cve_id: string
  mention_count: number
  sources: string[]
  latest: { ts: string; platform: string; url: string; title: string }
}

export interface Intelligence {
  risk_score: number
  risk_reasons: string[]
  zero_day_score: number
  zero_day_evidence: string[]
  zero_day_candidate: boolean
  attack_techniques: { id: string; name: string; matched: string }[]
  cross_source_count: number
}

export interface ThreatLandscape {
  days: number; total: number; critical: number; high: number; medium: number; low: number
  zero_day_candidates: number; active_exploitation: number; average_risk: number
  by_platform: Record<string, number>; by_category: Record<string, number>
  attack_techniques: Record<string, number>; top_risk_items: IntelItem[]
}

export interface Evidence {
  item_id: string; title: string; cve_ids: string[]; risk_score: number; risk_reasons: string[]
  zero_day_score: number; zero_day_evidence: string[]; cross_source_count: number
  sources: { url: string; platform: string }[]; attack_techniques: { id: string; name: string; matched: string }[]
  nvd_data: NVDRecord[]; epss_data?: { cve_id: string; epss: number; percentile: number }[]
}

export interface AuditStats {
  items_collected: number
  items_passed: number
  items_dropped: number
  notifications: number
  trending_alerts: number
  errors: number
}

export interface VerificationResult {
  id: string
  raw_id: string
  poc_found: boolean
  poc_signals: string[]
  affected_products: string[]
  credibility_score: number
  credibility_notes: string[]
  in_nvd: boolean
  in_nvd_at: string
  cross_source_count: number
  verification_status: 'confirmed' | 'likely' | 'unverified' | 'noise'
  verified_at: string
}

export const getStats       = () => api.get<Stats>('/stats').then(r => r.data)
export const getTrending    = (hours = 24, top = 20) => api.get<TrendingCVE[]>('/trending', { params: { hours, top } }).then(r => r.data)
export const getFeed        = (platform: string, page = 1, perPage = 50, days = 7) => api.get<Paginated<IntelItem>>(`/feed/${platform}`, { params: { page, per_page: perPage, days } }).then(r => r.data)
export const getZerodays    = (page = 1, days = 7, minScore = 8) => api.get<Paginated<IntelItem>>('/zerodays', { params: { page, days, min_score: minScore } }).then(r => r.data)
export const getCves        = (page = 1, days = 7, minScore = 6) => api.get<Paginated<IntelItem>>('/cves', { params: { page, days, min_score: minScore } }).then(r => r.data)
export const search         = (q: string, page = 1, days = 30) => api.get<Paginated<IntelItem>>('/search', { params: { q, page, days } }).then(r => r.data)
export const getAuditStats  = () => api.get<AuditStats>('/audit/stats').then(r => r.data)
export const getHealth      = () => api.get<{ status: string; ts: string }>('/health').then(r => r.data)
export const getVerified    = (page = 1, days = 7, status = '') => api.get<Paginated<VerificationResult>>('/verified', { params: { page, days, status } }).then(r => r.data)
export const getVerifiedDetail = (rawId: string) => api.get<VerificationResult>(`/verified/${rawId}`).then(r => r.data)

// The API returns attack_techniques as a ranked [{name,count}] list; this page works with a name→count map.
export const getThreatLandscape = (days = 30) =>
  api.get<ThreatLandscape>('/threat-landscape', { params: { days } }).then(r => {
    const t = r.data as unknown as Record<string, unknown>
    const at = t.attack_techniques
    if (Array.isArray(at)) t.attack_techniques = Object.fromEntries(at.map((x: { name: string; count: number }) => [x.name, x.count]))
    return r.data
  })
export const getEvidence = (id: string) => api.get<Evidence>(`/evidence/${id}`).then(r => r.data)
export const analystSearch = (q: string, days = 30) => api.get<{query: string; count: number; matches: IntelItem[]}>('/analyst', { params: { q, days } }).then(r => r.data)
