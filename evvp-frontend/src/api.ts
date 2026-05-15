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
