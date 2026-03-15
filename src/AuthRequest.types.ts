export interface AuthDiscoveryDocument {
  authorizationEndpoint: string
  tokenEndpoint: string
  revocationEndpoint?: string
}

export interface AuthRequestConfig {
  clientId: string
  redirectUri: string
  scopes?: string[]
  responseType?: 'code' | 'token' | 'id_token'
  state?: string
  usePKCE?: boolean
  extraParams?: Record<string, string>
}

export type AuthSessionResult =
  | { type: 'success'; url: string; params: Record<string, string>; authentication?: TokenResponseConfig }
  | { type: 'cancel' }
  | { type: 'error'; error: Error }
  | { type: 'locked' }

export interface TokenResponseConfig {
  accessToken: string
  tokenType?: string
  expiresIn?: number
  refreshToken?: string
  scope?: string
  state?: string
  idToken?: string
  issuedAt?: number
}
