# PQC-signed x402 receipts anchored on Arbitrum

Estado: construido y probado el 2026-10-03 (Arbitrum Open House Singapore — Online Buildathon). Contrato
`PQCReceiptAnchor.sol`, hook opcional en el notario `/api/x402/witness`, verificador offline en
`@fractalai/x402-pqc-witness/verify-anchor`. **Despliegue: ver §4 — la tabla dice la verdad en cada momento.**

## 1. Qué es (y qué no)

Un recibo x402 de FractalAI es un objeto firmado con **ML-DSA-65 (FIPS 204)** que ata un pago x402 a lo que
se compró (`/api/x402/witness` lo firma tras re-derivar el pago desde Base RPC; `lib/x402-receipt.ts` lo hace
para cada recurso pagado). La firma prueba *integridad + autoría* (contra el directorio de claves público
`/.well-known/x402-receipt-keys`). Lo que la firma **no** prueba por sí sola es *cuándo* existió el recibo:
quien tiene la clave podría firmar hoy un recibo fechado ayer.

`PQCReceiptAnchor` cierra ese hueco con 96 bytes por recibo en una cadena Arbitrum:

| Campo on-chain | Derivación | Por qué |
|---|---|---|
| `receiptId` (bytes32) | `sha256(bytes de la firma ML-DSA-65)` | único por recibo emitido (la firma es aleatorizada), write-once |
| `payloadHash` (bytes32) | `sha256(bytes exactos que cubre la firma)` = `sha256(utf8("<domain>\n<content_id>"))` | cualquiera lo recomputa desde el recibo |
| `kid` (bytes32) | `sha256(public_key_b64)[:16]` (8 bytes) alineado a la izquierda | el `kid` del directorio de claves por épocas |
| `observedAt` (uint64) | unix s en que firmamos | reclamación del emisor; el contrato la rechaza si va > 15 min al futuro |

El evento `ReceiptAnchored(receiptId, payloadHash, kid, observedAt, msg.sender, block.timestamp)` queda
indexado por `receiptId`, `payloadHash` y `kid`. El contrato **no tiene owner, ni fondos, ni upgrade, ni
allow-list**: cualquiera puede anclar cualquier recibo, exactamente una vez por `receiptId`.

**Lo que prueba un anclaje:** que un recibo con esa firma y esos bytes existía *no más tarde* del bloque
que lo ancló, y bajo qué `kid` dice haberse firmado.
**Lo que NO prueba:** que la firma sea válida (eso se verifica *offline* con `@noble/post-quantum`, no en
la EVM), que el pago fuera correcto, ni quién es `msg.sender` (es informativo; se puede pinear).

## 2. Cómo verificar SIN confiar en FractalAI

Necesitas: (a) el recibo (la respuesta JSON de `/api/x402/witness`, que ahora trae `seal.anchor`), (b) el
directorio público de claves o una clave pineada, (c) **cualquier** RPC de Arbitrum (el tuyo, Alchemy,
Infura, el público). Nada de esto llama a FractalAI salvo (b), y (b) puedes pinearlo una vez y olvidarlo.

```bash
npm i @fractalai/x402-pqc-witness        # ≥ 0.1.4 (exporta ./verify-anchor); o clona el repo público
# 1) verifica firma ML-DSA-65 + content_id + kid pineado + evento on-chain, con el RPC público de Arbitrum Sepolia
npx x402-verify-anchor receipt.json --rpc https://sepolia-rollup.arbitrum.io/rpc
# 2) con tu propio RPC y pineando el anclador (opcional)
npx x402-verify-anchor receipt.json --rpc https://arb-sepolia.g.alchemy.com/v2/$KEY --anchored-by 0x…
# 3) sin tocar fractalai.net.co (clave ya pineada en tu código): --no-key-pin + trustedPublicKeysB64 vía API
```

Programáticamente:

```js
import { verifyAnchoredSeal, fetchTrustedKeys } from '@fractalai/x402-pqc-witness/verify-anchor';
const keys = await fetchTrustedKeys();            // o tu lista pineada
const r = await verifyAnchoredSeal(response.seal, { trustedPublicKeysB64: keys, rpcUrl: 'https://sepolia-rollup.arbitrum.io/rpc' });
// r = { valid, signature_valid, key_trusted, anchor_valid, block_number, anchored_at, anchored_by, tx_hash, reason }
```

A mano, con `curl` y `sha256sum` (lo que hace el verificador por dentro):

```bash
# receiptId y payloadHash desde el recibo
jq -r .seal.signature receipt.json | base64 -d | sha256sum          # → receiptId
printf '%s\n%s' "$(jq -r .seal.domain receipt.json)" "$(jq -r .seal.content_id receipt.json)" | sha256sum   # → payloadHash
printf '%s' "$(jq -r .seal.public_key receipt.json)" | sha256sum | cut -c1-16                            # → kid (8 bytes)
# evento on-chain: topic0 = keccak256("ReceiptAnchored(bytes32,bytes32,bytes32,uint64,address,uint256)")
curl -s -X POST https://sepolia-rollup.arbitrum.io/rpc -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,
 "method":"eth_getLogs","params":[{"address":"<CONTRATO>","fromBlock":"0x0","toBlock":"latest",
 "topics":["0x86069938b925599e2755e87e9b3242e8f6cbd24f2bc3d1ab52bc585d82646184","0x<receiptId>"]}]}'
# topics[2] debe ser 0x<payloadHash>, topics[3] debe empezar por 0x<kid>; data = observedAt | anchoredBy | anchoredAt
```

La firma ML-DSA-65 en sí se verifica con `verifySeal` de `@fractalai/x402-pqc-witness/verify` (ya publicado):
`ml_dsa65.verify(sig, utf8(domain + "\n" + content_id), pk)`.

## 3. Cómo se produce (lado servidor)

`frontend/lib/x402-receipt-anchor.ts` → `anchorReceiptOnArbitrum(seal)`:

- Se activa **solo** con `X402_ANCHOR_RPC_URL`, `X402_ANCHOR_CONTRACT` y `X402_ANCHOR_PRIVATE_KEY`
  (opcionales `X402_ANCHOR_CHAIN_ID` = 421614 por defecto, `X402_ANCHOR_TIMEOUT_MS` = 25000). Sin ellas:
  no-op, el recibo lleva `anchor: null`. Nunca lanza; un fallo de RPC/gas devuelve `null` y la llamada pagada
  sigue siendo correcta.
- En `/api/x402/witness` se llama **después** de firmar y de que el cliente pagó (no gastamos gas en
  llamadas no pagadas). El `anchor` va como hermano de `body` dentro de `seal`, **fuera** de los bytes
  firmados: la firma se verifica exactamente igual que antes; el anclaje es evidencia encima.
- Si la tx se emite pero no se incluye dentro del presupuesto, el recibo lleva `status: "pending"` con el
  `tx_hash` y `log_index: null` — el verificador lo resuelve después por `eth_getTransactionReceipt` o por
  `eth_getLogs(receiptId)`.
- `ethers.NonceManager` serializa nonces entre peticiones concurrentes del mismo proceso.

Forma de `seal.anchor`:

```json
{ "scheme": "fractalai.pqc-receipt-anchor/1", "chain_id": 421614, "contract": "0x…", "tx_hash": "0x…",
  "log_index": 3, "block_number": 123456, "status": "confirmed", "receipt_id": "0x…", "payload_hash": "0x…",
  "kid": "0x86c139c960bb274c000…", "observed_at": 1759500000, "anchored_by": "0x…" }
```

## 4. Despliegues

| Cadena | chainId | Contrato | Tx de despliegue | Estado |
|---|---|---|---|---|
| Arbitrum Sepolia | 421614 | **PENDIENTE DE FONDOS** — ver `smart-contracts/deployments/PQCReceiptAnchor-421614.json` cuando exista | — | wallet de despliegue `0x39db643192c0e81f2BC13883ad8c1a0e4060Bf63` (testnet, nueva, saldo 0 al 2026-10-03 05:47 UTC). Gas estimado del despliegue en vivo: 375.566 gas × ~0,045 gwei ≈ **0,00002 ETH**. Faucets sin cuenta probados y agotados (ver nota) |

**Nota de fondeo (2026-10-03, verificado por el enjambre, ~40 min de intentos):** ningún faucet acepta hoy una
dirección nueva sin humano: Alchemy, QuickNode, GetBlock y Tatum exigen ≥0,001 ETH o actividad en Ethereum
mainnet de la MISMA dirección; Chainlink exige ≥1 LINK en mainnet; Google Cloud exige login de Google;
pk910 (PoW) está tras Cloudflare Turnstile que rechaza navegadores automatizados (`[INVALID_CAPTCHA]`
server-side); Triangle/LearnWeb3/Bware caídos (503/530); l2faucet en mantenimiento. **Vías humanas de 2
minutos:** (a) desde el navegador del fundador, `https://www.alchemy.com/faucets/arbitrum-sepolia` o
`https://faucet.quicknode.com/arbitrum/sepolia` pegando la dirección — pero califican por la wallet que FIRMA
el captcha/login, así que lo más simple es pedir el drip a una wallet propia con historial (p. ej. la
tesorería `0xC137…ef4f`, que ya opera en Arbitrum One) y reenviar 0,001 ETH a `0x39db…Bf63`; (b)
`https://cloud.google.com/application/web3/faucet/ethereum/sepolia` con la cuenta Google (0,05 ETH en
Sepolia L1) y luego `node /Users/johneomo/.claude/jobs/40dd5ee6/tmp/bridge-sepolia-to-arb.mjs 0.01`
(Inbox `0xaAe29B…ae21`, verificado contra `bridge()`; crédito en L2 en 3–15 min); (c) cualquier wallet de
testnet existente del equipo que envíe 0,001 ETH en Arbitrum Sepolia.
| Arbitrum One | 42161 | no desplegado | — | ~0,00002 ETH de gas; decisión del fundador |
| Robinhood Chain (testnet) | — | no desplegado | — | siguiente paso (premio reservado en el buildathon) |

Comandos (la clave vive fuera del repo; `PRIVATE_KEY` solo en el entorno del proceso):

```bash
cd smart-contracts
PRIVATE_KEY=$(cat /ruta/fuera/del/repo/deployer.key) npx hardhat run scripts/deploy-pqc-receipt-anchor.js --network arbitrumSepolia
PRIVATE_KEY=… npx hardhat run scripts/deploy-pqc-receipt-anchor.js --network arbitrumOne
npx hardhat verify --network arbitrumSepolia <address>     # Sourcify habilitado; Arbiscan con ARBISCAN_KEY
```

Tras desplegar, activar en el frontend (drop-in de systemd, nunca en el repo): `X402_ANCHOR_RPC_URL`,
`X402_ANCHOR_CONTRACT`, `X402_ANCHOR_PRIVATE_KEY` (una EOA con unos céntimos de ETH en esa cadena; no tiene
ningún otro poder).

## 5. Pruebas (números reales, 2026-10-03)

- `smart-contracts/test/PQCReceiptAnchor.test.js`: **20/20** (write-once, evento, batch atómico, sin owner/ETH,
  skew, `eth_getLogs` por `receiptId`, gas < 150k — real: ~95k).
- `frontend/__tests__/x402-receipt-anchor.test.ts` (ethers mockeado): **12/12**; `tsc --noEmit` limpio.
- `integrations/x402-pqc-witness/test/verify-anchor.test.mjs` (firmas ML-DSA-65 reales + RPC mockeado con la
  codificación exacta del evento): **15/15**; suite completa del paquete sin fallos.

## 6. Limitaciones honestas

- **Opcional y best-effort.** Un recibo sin `anchor` sigue siendo un recibo válido; el anclaje añade
  "existía antes de T", no cambia la firma.
- **Testnet.** Arbitrum Sepolia no tiene valor económico ni garantías de permanencia. Arbitrum One es un
  despliegue de ~$0,05 y una variable de entorno; no se ha hecho aún.
- **Un solo anclador.** Hoy ancla FractalAI con una EOA; el contrato acepta a cualquiera, pero nadie más lo
  usa todavía. `anchored_by` es informativo salvo que el verificador lo pinee.
- **La verificación ML-DSA-65 es off-chain.** La EVM no verifica FIPS 204; anclamos hashes. No afirmar
  "firma post-cuántica verificada on-chain". `@noble/post-quantum` implementa FIPS 204 pero no es un módulo
  validado CMVP.
- **Sin auditoría externa** del contrato (es deliberadamente mínimo: 1 mapping, 1 evento, sin ETH, sin
  owner; 20 tests). Sin auditoría tampoco del hook ni del verificador.
- **Finalidad L2 ≠ L1.** `minConfirmations` cuenta bloques de Arbitrum; la finalidad en Ethereum llega
  después (~1 semana de ventana de disputa en One). Para "no más tarde de T" basta el bloque L2; para
  disputas legales, esperar la finalidad L1.
- **`observedAt` es una reclamación del emisor.** El contrato solo impide que vaya al futuro; `anchoredAt`
  (block.timestamp) es el dato que vale.
- `receiptId = sha256(firma)` asume firma aleatorizada (ML-DSA hedged por defecto en `@noble`); con firma
  determinista dos recibos idénticos colisionarían y el segundo revertiría (`AlreadyAnchored`) — comportamiento
  correcto, pero conviene saberlo.

## 7. Siguiente paso

1. Fondear la EOA de anclaje y desplegar en **Arbitrum One** (mismo script, `--network arbitrumOne`); activar
   las 3 variables en prod → cada sello del notario queda anclado en mainnet.
2. **Robinhood Chain** (testnet hoy): añadir red en `hardhat.config.js` cuando se publique RPC/chainId, mismo
   contrato sin cambios. También Arc (Circle) para los microgrants.
3. `anchorBatch` desde un cron cada N minutos para los recibos de `lib/x402-receipt.ts` (hoy solo se ancla
   en vivo el notario), amortizando gas.
4. Publicar `@fractalai/x402-pqc-witness` 0.1.4 con `./verify-anchor` (requiere OTP del fundador en npm).
5. Puerto a **Stylus (Rust)**: trivial para este contrato; valor real sería verificar ML-DSA-65 on-chain con
   el precompilado/wasm — no lo hemos hecho ni medido el gas; no prometerlo.


## Deployed — Arbitrum One mainnet (2026-10-03, verified on-chain)

| Item | Value |
|---|---|
| Contract `PQCReceiptAnchor` | `0x3A23c614033cb22139DC13932524767c5fE841d8` — https://arbiscan.io/address/0x3A23c614033cb22139DC13932524767c5fE841d8 |
| Deploy tx | `0xb42b8df36438a195fc629e15926142dea386aa9fc6ca597c982c9fc0fb0aff44` (block 511335138, deployer `0xC13789e82661635d9Cea38a53A0390CF9939ef4f`, ≈0.0000146 ETH max cost) |
| First anchored receipt | MIDAS alert receipt `fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee` → `receiptId 0xb9b47ba81d30d95a087ac40b4d7c1c07816148251c147121e7c4aac477cd94eb`, `payloadHash 0xef737f1ca8d99fabf58a81373188cc349183bfc8976c1ae3d3861238b498e065`, `kid 0x86c139c960bb274c…` (= active key in the directory), `observedAt 1790473960` |
| Anchor tx | `0x37f0254389deed3953aa44333e32eaeb466f28ff41ac9299eb5285599a7a1174` (block 511335916, logIndex 5, 138,288 gas ≈ 0.0000028 ETH) — https://arbiscan.io/tx/0x37f0254389deed3953aa44333e32eaeb466f28ff41ac9299eb5285599a7a1174 |
| Source verification | pending (no `ARBISCAN_KEY` in this environment): `cd smart-contracts && ARBISCAN_KEY=… npx hardhat verify --network arbitrumOne 0x3A23c614033cb22139DC13932524767c5fE841d8` |

Re-check from any machine: `getAnchor(0xb9b47ba8…94eb)` on the contract returns the payloadHash/kid/observedAt above; the receipt itself is public at https://fractalai.net.co/api/midas/alerts/receipt/fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee and verifies in the browser at https://fractalai.net.co/midas/proof. Arbitrum Sepolia was not used (no faucet accepted a fresh wallet); mainnet gas was cheaper than the time.

## Trust Kernel v2 (2026-10-07)

La verificación de este documento la decide ahora `kernel/` (especificación normativa: `spec/TRUST-KERNEL.md`,
corpus adversarial: `corpus/`). Cambios relevantes: el contrato de anclaje se fija por `chainId → (dirección, code
hash)` en `kernel/trust-roots.json` (una dirección traída por el sello se rechaza); la hora sale de la cabecera del
bloque y `observedAt` debe ser igual a la hora FIRMADA; Solana exige génesis del cluster, `finalized` + `blockTime`,
firmante anunciado y un único Memo v2 idéntico byte a byte; las redes de prueba quedan marcadas `test` y no cuentan
como prueba de tiempo salvo `allowTestnetAnchors`; el ciclo de vida de la clave se evalúa en la hora firmada y una
clave revocada solo vale con un anclaje anterior a `revoked_at`. Protocolo anti-squatting "anclar antes de publicar":
spec §10. Límites (RPC/consenso, raíces fijadas por TOFU, sin auditoría externa, librería no CMVP): spec §11.
