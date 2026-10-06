# MIDAS — alertas de riesgo de liquidación con prueba firmada

Vivo desde el 2026-09-27 (primer recibo real: `fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee`, posición Aave V3 en Ethereum con HF 1.0009, observada por el nodo a las 01:52:34 UTC y firmada 6 s después).

## Qué es (y qué no)

Cada alerta es una **declaración firmada con ML-DSA-65 (FIPS 204)** de lo que el escáner MIDAS observó y cuándo: dirección, cadena, health factor, umbral, colateral, deuda, tier de riesgo, `observed_at` (reloj del nodo), fuente, hash del snapshot crudo y `emitted_at`. Un tercero la verifica sin confiar en FractalAI. Nadie más en el mercado firma alertas (Otomato, HAL, DeFi Monitor no lo hacen).

**No es**: protección automática, garantía de liquidación evitada, lectura de oráculo verificada por consenso, ni confirmación de que el destinatario la leyó. `@noble/post-quantum` implementa el algoritmo FIPS 204; no es un módulo validado CMVP.

## API

Acceso = los mismos raíles que `/api/midas/intelligence`: cabecera `x-midas-key` (suscripción USDC de `/midas/pricing`) o wallet probada (`wallet`+`ts`+`sig`). Free → 402.

```
POST /api/midas/alerts
{ "address": "0x…", "chain_id": 1 | 8453 | … | 0 (cualquiera), "threshold": 1.3,
  "channel": "webhook" | "email" | "telegram", "channel_ref": "https://… | correo | chat_id",
  "cooldown_secs": 3600 }
→ 201 { watch: {...}, confirmation? }      (email: doble opt-in por enlace)
GET    /api/midas/alerts            → tus vigilancias + tus alertas recientes
DELETE /api/midas/alerts { "id" }   → desactiva
GET    /api/midas/alerts/recent     → track record público (direcciones enmascaradas)
GET    /api/midas/alerts/receipt/<receipt_id>  → recibo público completo
```

Tope de vigilancias = `address_limit` del tier (Scout 25 · Sentinel 100 · Institutional sin tope práctico). Evaluación cada ~10 min (workflow `midas-alerts.yml`, runner del droplet); el nodo reescanea Ethereum/Base cada 20 s. Regla de disparo: `health_factor < threshold` en un cruce de umbral, y después como máximo una vez por `cooldown_secs` mientras siga por debajo. Si un canal falla, el recibo se guarda igual y la entrega se reintenta en la siguiente pasada (no se marca entregado lo que no se entregó).

Webhook: `POST` JSON a tu URL HTTPS pública (nunca loopback/privadas) con cabecera `X-FractalAI-Alert-Receipt: <receipt_id>`; cuerpo = `{ receipt_id, verify_url, facts, canonical, served_message, signature, public_key, algorithm, key_directory, scope }`.

## Sin suscripción: atestado por llamada vía x402 ($0.01)

`POST https://fractalai.net.co/api/x402/midas-attest { "address": "0x…", "chain_id"? }` — primera llamada 402 con `accepts[]` (EIP-3009 vía facilitador o txHash); reintento con `X-PAYMENT`. Devuelve `attestation` (`receipt_id`, `facts`, `canonical`, `signed_message`, `signature` ML-DSA-65, `public_key`, `verify_url`) + `position` cruda de las 6 cadenas + `payment` con evidencia on-chain. Es el **mismo recibo** que emiten las alertas (`threshold: 0`), así que se verifica igual en `/api/midas/alerts/receipt/<id>` y `/midas/proof`. Sin deuda → `health_factor` centinela `1000000`. Catalogado como 9.º recurso en `/.well-known/x402.json` (Bazaar de CDP / x402scan). Primer atestado pagado real: `90f69630…` (2026-09-27 04:24 UTC).

## Créditos Sentinel (FRC-55R) vía x402 — $0,50/crédito

`POST /api/x402/sentinel-credit { "to": "fractal1_pq_…", "credits"?: 1..20 }` → 402 a `credits × $0,50` → reintento con `X-PAYMENT`. Devuelve `order` (`request_id`, `evidence_hash` = sha256(JCS(`payment`)) — el `payment` incluye `product`, `credits` y `to`, así el hash ata quién recibe), `status` (`minted` con `mint_tx_hash`/`asset_id`, o `pending` con `status_url` — el mint se reintenta cada ~10 min hasta que el activo esté activo en consenso: `ASSET_TX_ACTIVATION_HEIGHT`), `served_signature` (ML-DSA-65 de la clave de recibos sobre el digest del pedido) y `payment`. Estado público: `GET /api/x402/sentinel-credit?order=<request_id>`. Acuñación: la clave de recibos atesta los `signing_bytes` exactos que devuelve el nodo (`prometheus_midas_sentinelMintPreview`) y el nodo firma el sobre con su clave creadora (`prometheus_midas_sentinelMint`). Política de mint inmutable: clave activa + 3 reservas (época 3 del directorio, `status: reserved`), variable pública `MIDAS_SENTINEL_MINT_ATTESTERS`. Canje: `ServiceRedeem` + `prometheus_midas_sentinelActivate` (ver `blockchain/docs/SENTINEL.md`).

## Verificar un recibo (sin confiar en nosotros)

```js
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
const r = await (await fetch(`https://fractalai.net.co/api/midas/alerts/receipt/${id}`)).json();
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
sha(r.canonical) === r.receipt_id;                                        // 1. el id ES el hash de los hechos
r.served_message === `FRACTALAI-x402-served-v1\nmidas-alert\n${r.receipt_id}`; // 2. dominio + ruta propia
ml_dsa65.verify(Buffer.from(r.signature, 'base64'), new TextEncoder().encode(r.served_message), Buffer.from(r.public_key, 'base64')); // 3. firma
// 4. r.public_key debe estar en https://fractalai.net.co/.well-known/x402-receipt-keys
//    (directorio firmado y encadenado por épocas; clave 'active' o 'retiring' con emitted_at <= not_after)
```

`canonical` es el texto exacto firmado (12 líneas, `FRACTALAI-midas-alert-v1` + `clave=valor`); `snapshot` es la fila cruda del nodo cuyo hash JCS va dentro.

## Piezas

`frontend/lib/midas-alert-proof.ts` (canon + regla de disparo), `midas-alert-store.ts` (Postgres `midas_alert_subscriptions` / `midas_alerts_sent`, fallback en memoria), `midas-alert-delivery.ts` (webhook/email/telegram, SSRF), `app/api/midas/alerts/*`, `app/api/rpa/midas-alerts` (bucle, único sitio que usa `PROMETHEUS_ADMIN_TOKEN`), `.github/workflows/midas-alerts.yml` (cada 10 min) y `midas-alerts-smoke.yml` (prueba de punta a punta con vigilancia de operador).
