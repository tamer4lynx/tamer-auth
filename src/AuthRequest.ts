'background only'

import { createURL } from 'tamer-linking'
import { openAuthSessionAsync } from 'tamer-display-browser'
import { buildCodeAsync, generateRandomState } from './PKCE.js'
import type { AuthDiscoveryDocument, AuthRequestConfig, AuthSessionResult, TokenResponseConfig } from './AuthRequest.types.js'
import { TokenResponse } from './TokenResponse.js'

function getQueryParams(url: string): Record<string, string> {
  const idx = url.indexOf('?')
  if (idx < 0) return {}
  const params: Record<string, string> = {}
  const search = url.slice(idx + 1)
  const hashIdx = search.indexOf('#')
  const qs = hashIdx >= 0 ? search.slice(0, hashIdx) + search.slice(hashIdx).replace('#', '&') : search
  qs.split('&').forEach((p) => {
    const eq = p.indexOf('=')
    if (eq >= 0) params[decodeURIComponent(p.slice(0, eq))] = decodeURIComponent(p.slice(eq + 1).replace(/\+/g, ' '))
  })
  return params
}

export function makeRedirectUri(options: { scheme?: string; path?: string } = {}): string {
  return createURL(options.path ?? 'auth/callback', { scheme: options.scheme ?? 'tamerdevapp' })
}

export class AuthRequest {
  state: string
  codeVerifier?: string
  codeChallenge?: string
  url: string | null = null
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes?: string[]
  readonly responseType: string
  readonly usePKCE: boolean
  readonly extraParams: Record<string, string>

  constructor(config: AuthRequestConfig) {
    this.clientId = config.clientId
    this.redirectUri = config.redirectUri
    this.scopes = config.scopes
    this.responseType = config.responseType ?? 'code'
    this.usePKCE = config.usePKCE ?? true
    this.state = config.state ?? generateRandomState(10)
    this.extraParams = config.extraParams ?? {}
  }

  async makeAuthUrlAsync(discovery: AuthDiscoveryDocument): Promise<string> {
    if (this.usePKCE) {
      const { codeVerifier, codeChallenge } = await buildCodeAsync(128)
      this.codeVerifier = codeVerifier
      this.codeChallenge = codeChallenge
    }
    const pairs: [string, string][] = [
      ['response_type', this.responseType],
      ['client_id', this.clientId],
      ['redirect_uri', this.redirectUri],
      ['state', this.state],
    ]
    const extra = this.extraParams
    const extraKeys = Object.keys(extra)
    for (let i = 0; i < extraKeys.length; i++) pairs.push([extraKeys[i], extra[extraKeys[i]]])
    if (this.scopes?.length) pairs.push(['scope', this.scopes.join(' ')])
    if (this.codeChallenge) {
      pairs.push(['code_challenge', this.codeChallenge])
      pairs.push(['code_challenge_method', 'S256'])
    }
    const qs = pairs.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&')
    this.url = `${discovery.authorizationEndpoint}${discovery.authorizationEndpoint.includes('?') ? '&' : '?'}${qs}`
    return this.url
  }

  async promptAsync(discovery: AuthDiscoveryDocument): Promise<AuthSessionResult> {
    const authUrl = this.url ?? (await this.makeAuthUrlAsync(discovery))
    const result = await openAuthSessionAsync(authUrl, this.redirectUri)
    if (result.type === 'success') return this.parseReturnUrl(result.url)
    if (result.type === 'cancel') return { type: 'cancel' }
    return { type: 'cancel' }
  }

  parseReturnUrl(url: string): AuthSessionResult {
    const params = getQueryParams(url)
    const { state, error } = params
    if (state !== this.state) {
      return { type: 'error', error: new Error('state_mismatch') }
    }
    if (error) {
      return { type: 'error', error: new Error(error) }
    }
    if (params.access_token) {
      const auth = TokenResponse.fromQueryParams(params)
      return { type: 'success', url, params, authentication: auth }
    }
    return { type: 'success', url, params }
  }
}

export async function exchangeCodeAsync(
  config: { clientId: string; redirectUri: string; code: string; codeVerifier: string; clientSecret?: string },
  discovery: AuthDiscoveryDocument
): Promise<TokenResponse> {
  const fetchFn = typeof globalThis !== 'undefined' && (globalThis as any).fetch
  if (!fetchFn) throw new Error('fetch not available')
  const bodyPairs: [string, string][] = [
    ['grant_type', 'authorization_code'],
    ['code', config.code],
    ['redirect_uri', config.redirectUri],
  ]
  if (config.codeVerifier) bodyPairs.push(['code_verifier', config.codeVerifier])
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' }
  if (config.clientSecret) {
    const str = `${config.clientId}:${config.clientSecret}`
    const bytes = new Uint8Array(str.length)
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i)
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    let b64 = ''
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2]
      b64 += B64[a >> 2] + B64[((a & 3) << 4) | (b >> 4)] + (b !== undefined ? B64[((b & 15) << 2) | (c >> 6)] : '=') + (c !== undefined ? B64[c & 63] : '=')
    }
    headers['Authorization'] = `Basic ${b64}`
  } else {
    bodyPairs.push(['client_id', config.clientId])
  }
  const bodyStr = bodyPairs.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&')
  const res = await fetchFn(discovery.tokenEndpoint, {
    method: 'POST',
    headers,
    body: bodyStr,
  })
  const data = await res.json()
  if (!res.ok) throw new Error((data as { error_description?: string }).error_description ?? (data as { error?: string }).error ?? 'Token exchange failed')
  return new TokenResponse(data as TokenResponseConfig)
}
