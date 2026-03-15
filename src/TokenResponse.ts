import type { TokenResponseConfig } from './AuthRequest.types.js'

export class TokenResponse implements TokenResponseConfig {
  accessToken: string
  tokenType: string
  expiresIn?: number
  refreshToken?: string
  scope?: string
  state?: string
  idToken?: string
  issuedAt: number

  constructor(config: TokenResponseConfig) {
    this.accessToken = config.accessToken
    this.tokenType = config.tokenType ?? 'bearer'
    this.expiresIn = config.expiresIn
    this.refreshToken = config.refreshToken
    this.scope = config.scope
    this.state = config.state
    this.idToken = config.idToken
    this.issuedAt = config.issuedAt ?? Math.floor(Date.now() / 1000)
  }

  static fromQueryParams(params: Record<string, string>): TokenResponse {
    return new TokenResponse({
      accessToken: params.access_token ?? '',
      tokenType: params.token_type ?? 'bearer',
      expiresIn: params.expires_in ? parseInt(params.expires_in, 10) : undefined,
      refreshToken: params.refresh_token,
      scope: params.scope,
      state: params.state,
      idToken: params.id_token,
      issuedAt: params.issued_at ? parseInt(params.issued_at, 10) : Math.floor(Date.now() / 1000),
    })
  }
}
