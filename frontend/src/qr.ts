import QRCode from 'qrcode'

/**
 * 生成 TOTP 二维码的 data URL（纯本地，不发送密钥到第三方）
 */
export async function generateQrDataUrl(text: string): Promise<string> {
  return QRCode.toDataURL(text, {
    width: 200,
    margin: 2,
    color: { dark: '#000000', light: '#ffffff' },
  })
}
