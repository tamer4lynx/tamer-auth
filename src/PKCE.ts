const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

function generateRandom(size: number): string {
  const arr = new Uint8Array(size)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(arr)
  } else {
    for (let i = 0; i < size; i++) arr[i] = Math.floor(Math.random() * 256)
  }
  let s = ''
  for (let i = 0; i < size; i++) s += CHARSET[arr[i] % CHARSET.length]
  return s
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let s = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2]
    s += B64[a >> 2] + B64[((a & 3) << 4) | (b >> 4)] + (b !== undefined ? B64[((b & 15) << 2) | (c >> 6)] : '=') + (c !== undefined ? B64[c & 63] : '=')
  }
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function stringToUtf8Bytes(str: string): Uint8Array {
  const bytes: number[] = []
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i)
    if (c < 0x80) bytes.push(c)
    else if (c < 0x800) { bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)) }
    else if (c >= 0xd800 && c <= 0xdbff) {
      const hi = c
      const lo = str.charCodeAt(++i)
      c = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
      bytes.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
    } else {
      bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
    }
  }
  return new Uint8Array(bytes)
}

async function sha256(message: string): Promise<ArrayBuffer> {
  const data = stringToUtf8Bytes(message)
  if (typeof crypto !== 'undefined' && crypto.subtle?.digest) {
    return crypto.subtle.digest('SHA-256', data)
  }
  return digestSHA256Fallback(data)
}

function digestSHA256Fallback(data: Uint8Array): ArrayBuffer {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  ]
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19
  const msg = new Uint8Array(((data.length + 72) >> 6) << 6)
  msg.set(data)
  msg[data.length] = 0x80
  const view = new DataView(msg.buffer)
  view.setUint32(msg.length - 4, data.length * 8, false)
  for (let i = 0; i < msg.length; i += 64) {
    const w = new Uint32Array(64)
    for (let j = 0; j < 16; j++) w[j] = view.getUint32(i + j * 4, false)
    for (let j = 16; j < 64; j++) {
      const s0 = (w[j - 15] >>> 7) ^ (w[j - 15] >>> 18) ^ (w[j - 15] >>> 3)
      const s1 = (w[j - 2] >>> 17) ^ (w[j - 2] >>> 19) ^ (w[j - 2] >>> 10)
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0
    }
    let [a, b, c, d, e, f, g, h] = [h0, h1, h2, h3, h4, h5, h6, h7]
    for (let j = 0; j < 64; j++) {
      const S1 = (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
      const ch = (e & f) ^ (~e & g)
      const temp1 = (h + S1 + ch + K[j] + w[j]) >>> 0
      const S0 = (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const temp2 = (S0 + maj) >>> 0
      h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0
  }
  const out = new ArrayBuffer(32)
  const outView = new DataView(out)
  ;[h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => outView.setUint32(i * 4, v, false))
  return out
}

export async function buildCodeAsync(size = 128): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const codeVerifier = generateRandom(size)
  const hash = await sha256(codeVerifier)
  const codeChallenge = base64UrlEncode(hash)
  return { codeVerifier, codeChallenge }
}

export function generateRandomState(size = 10): string {
  return generateRandom(size)
}
