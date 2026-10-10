/// WebAuthn / Passkey 前端辅助函数
/// 使用浏览器原生 Web Authentication API

// Base64URL 编解码
function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const padLen = (4 - (base64.length % 4)) % 4
  const padded = base64 + '='.repeat(padLen)
  const binary = atob(padded)
  const buffer = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i)
  }
  return buffer.buffer
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/// 注册 Passkey
export async function registerPasskey(options: {
  challenge: string
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  excludeCredentials?: string[]
}): Promise<any> {
  const challengeBuffer = base64urlToBuffer(options.challenge)
  const userIdBuffer = new TextEncoder().encode(options.user.id)

  const credentialCreationOptions: CredentialCreationOptions = {
    publicKey: {
      rp: {
        id: options.rp.id,
        name: options.rp.name,
      },
      user: {
        id: userIdBuffer,
        name: options.user.name,
        displayName: options.user.displayName,
      },
      challenge: challengeBuffer,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256 (P-256)
        { type: 'public-key', alg: -257 }, // RS256
      ],
      timeout: 60000,
      attestation: 'none',
      excludeCredentials: (options.excludeCredentials || []).map(id => ({
        id: base64urlToBuffer(id),
        type: 'public-key' as PublicKeyCredentialType,
      })),
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
      },
    },
  }

  const credential = await navigator.credentials.create(credentialCreationOptions)
  if (!credential) {
    throw new Error('用户取消了 Passkey 注册')
  }

  const cred = credential as PublicKeyCredential
  const response = cred.response as AuthenticatorAttestationResponse

  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  }
}

/// Passkey 登录
export async function authenticateWithPasskey(options: {
  challenge: string
  rpId: string
  allowCredentials?: string[]
}): Promise<any> {
  const challengeBuffer = base64urlToBuffer(options.challenge)

  const credentialRequestOptions: CredentialRequestOptions = {
    publicKey: {
      rpId: options.rpId,
      challenge: challengeBuffer,
      timeout: 60000,
      userVerification: 'preferred',
      allowCredentials: (options.allowCredentials || []).map(id => ({
        id: base64urlToBuffer(id),
        type: 'public-key' as PublicKeyCredentialType,
      })),
    },
  }

  const credential = await navigator.credentials.get(credentialRequestOptions)
  if (!credential) {
    throw new Error('用户取消了 Passkey 认证')
  }

  const cred = credential as PublicKeyCredential
  const response = cred.response as AuthenticatorAssertionResponse

  return {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
    },
  }
}

/// 检查浏览器是否支持 WebAuthn
export function isWebAuthnSupported(): boolean {
  return !!(window.PublicKeyCredential && navigator.credentials)
}

/// 检查是否支持平台认证器（指纹/面容）
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  } catch {
    return false
  }
}
