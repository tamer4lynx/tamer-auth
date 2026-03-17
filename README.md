# tamer-auth

OAuth 2.0 / OpenID Connect for Lynx.

## Installation

```bash
npm install @tamer4lynx/tamer-auth
```

Add to your app's dependencies and run `t4l link`. Depends on **tamer-linking** and **tamer-display-browser**.

## Usage

```ts
import {
  AuthRequest,
  makeRedirectUri,
  exchangeCodeAsync,
  type AuthRequestConfig,
  type AuthDiscoveryDocument,
  type AuthSessionResult,
} from '@tamer4lynx/tamer-auth'
import { openAuthSessionAsync } from '@tamer4lynx/tamer-display-browser'

const redirectUri = makeRedirectUri({ scheme: 'myapp' })

const authRequest = new AuthRequest({
  clientId: 'your-client-id',
  redirectUri,
  scopes: ['openid', 'profile'],
  usePKCE: true,
})

const discovery: AuthDiscoveryDocument = {
  authorization_endpoint: 'https://auth.example.com/authorize',
  token_endpoint: 'https://auth.example.com/token',
}

const authUrl = await authRequest.makeAuthUrlAsync(discovery)
const result = await openAuthSessionAsync(authUrl, redirectUri)

if (result.type === 'success' && result.url) {
  const tokenResponse = await exchangeCodeAsync(authRequest, discovery, result.url)
}
```

## API

| Export | Description |
|--------|-------------|
| `AuthRequest` | OAuth request builder with PKCE support |
| `makeRedirectUri(options?)` | Build redirect URI; options: `scheme`, `path` |
| `exchangeCodeAsync(authRequest, discovery, redirectUrl)` | Exchange authorization code for tokens |
| `TokenResponse` | Token response type |
| `AuthRequestConfig` | Config for AuthRequest: `clientId`, `redirectUri`, `scopes`, `responseType`, `usePKCE`, `state`, `extraParams` |
| `AuthDiscoveryDocument` | OIDC discovery: `authorization_endpoint`, `token_endpoint` |
| `AuthSessionResult` | `{ type: 'success', url }` or `{ type: 'cancel' }` or `{ type: 'dismiss' }` |

## Platform

Uses **lynx.ext.json**. Run `t4l link` after adding to your app.
