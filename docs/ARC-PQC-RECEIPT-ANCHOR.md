# PQC-signed receipts anchored on Arc mainnet (Circle's L1)

Estado: **desplegado y verificado en vivo el 2026-10-03** en Arc mainnet (chainId 5042, gas en USDC).
Mismo contrato `PQCReceiptAnchor.sol` y mismo verificador que en [ARBITRUM-PQC-RECEIPT-ANCHOR.md](./ARBITRUM-PQC-RECEIPT-ANCHOR.md);
aquí solo cambia la cadena y el hecho de que **ya está en mainnet con un recibo real anclado**.

## 1. Qué es

Un recibo de FractalAI (sello del notario x402 o alerta MIDAS de riesgo de liquidación) está firmado con
**ML-DSA-65 (FIPS 204)**. La firma prueba integridad y autoría contra el directorio público de claves
`https://fractalai.net.co/.well-known/x402-receipt-keys` (época 3, raíz encadenada). Lo que la firma no
prueba sola es *cuándo* existió el recibo. `PQCReceiptAnchor` registra, write-once y sin owner, 96 bytes:

| Campo | Derivación | Valor del recibo público `fe62b072…` |
|---|---|---|
| `receiptId` | `sha256(bytes de la firma ML-DSA-65)` | `0xb9b47ba81d30d95a087ac40b4d7c1c07816148251c147121e7c4aac477cd94eb` |
| `payloadHash` | `sha256(utf8("<domain>\n<content_id>"))` = bytes exactos firmados | `0xef737f1ca8d99fabf58a81373188cc349183bfc8976c1ae3d3861238b498e065` |
| `kid` | `sha256(public_key_b64)[:16]` alineado a la izquierda | `0x86c139c960bb274c00…` (kid `86c139c960bb274c`, `active`) |
| `observedAt` | unix s en que FractalAI firmó (`emitted_at`) | `1790473960` (2026-09-27 01:52:40 UTC) |

Para una alerta MIDAS, `domain = served_domain` (`FRACTALAI-x402-served-v1\nmidas-alert`) y
`content_id = receipt_id = sha256(canonical)`, de modo que `"<domain>\n<content_id>"` es exactamente el
`served_message` que cubre la firma. La derivación es la de `frontend/lib/x402-receipt-anchor.ts#deriveAnchorIds`.

**Lo que prueba:** que ese recibo (esa firma, esos bytes, ese `kid`) existía no más tarde del bloque
24072596 de Arc (`anchoredAt` 1791042087 = 2026-10-03 15:41:27 UTC). **Lo que no prueba:** que la
firma sea válida (se verifica off-chain), que la posición Aave descrita fuera correcta, ni quién es
`anchoredBy` (informativo; se puede pinear).

## 2. Direcciones y transacciones (Arc mainnet, chainId 5042)

| Qué | Valor |
|---|---|
| Red | Arc mainnet · chainId **5042** (`0x13b2`) · RPC `https://rpc.mainnet.arc.io` · explorer `https://explorer.arc.io` · gas en USDC (nativo, 18 decimales; vista ERC-20 en `0x3600…0000`, 6 decimales) |
| Contrato `PQCReceiptAnchor` | **`0x1f0d2774943250A7EB179e960203ea86319a8181`** — https://explorer.arc.io/address/0x1f0d2774943250A7EB179e960203ea86319a8181 |
| Tx de despliegue | `0xa5b2b9acc0379aab20882de7a90e416dd81106efb26b8e81ef90ba4560d18f47` · bloque 24072431 · 357.471 gas × 24 gwei = **0,008579 USDC** |
| Deployer / anclador | `0xC13789e82661635d9Cea38a53A0390CF9939ef4f` (tesorería FractalAI; sin poder alguno sobre el contrato) |
| Tx de anclaje (recibo `fe62b072…`) | `0x31979b7fa0a6605ea4ac9380051c92ad6b6e222fc39ada10ea46e655eab86b64` · bloque 24072596 · logIndex 5 · 136.658 gas × 20 gwei = **0,002733 USDC** — https://explorer.arc.io/tx/0x31979b7fa0a6605ea4ac9380051c92ad6b6e222fc39ada10ea46e655eab86b64 |
| Compilador | solc 0.8.24, optimizer 200 runs, viaIR, evmVersion cancun (Arc es Osaka-baseline, compatible) |
| Registro | `smart-contracts/deployments/PQCReceiptAnchor-5042.json` (ABI + anclajes) y `deployments/anchors/PQCReceiptAnchor-5042-fe62b072.json` (fixture del verificador: sello + `anchor`) |

Fondeo (CCTP v2 + Forwarding Service, 2026-10-03 15:20 UTC, 16 s de extremo a extremo):

| Paso | Tx | Coste |
|---|---|---|
| `approve` 10 USDC → TokenMessengerV2 (Base) | `0xa2ef8f7fcf28bf44c8d5f2dfce89adee329e664adabd77a5704c99bf0504cdaa` | 55.437 gas (≈0,0000003 ETH) |
| `depositForBurnWithHook` 10 USDC, dominio 6→26, hook `cctp-forward`, fast (1000), maxFee 0,04 (Base) | `0x1edb29bf5dc084b4e11bd1350c6ad7d047784c2d342fa6f7fb61021d0d0b12bc` · bloque 52125749 | 110.364 gas = 0,00000066 ETH |
| Attestation Iris (`/v2/messages/6?transactionHash=…`) | nonce `0x8bb586dc…`, `status: complete` en 10 s | — |
| `receiveMessage` en Arc, enviado por el Forwarding Service de Circle (`0xd0cC64D2…`) | `0x3fa82901a6ea07e88844db5835efc92dac7d95563831da41427af950a17ce41f` · bloque 24070154 | **feeExecuted = 0,04 USDC** (Circle cobró el `maxFee` íntegro, no los ~0,0167 cotizados) |

Saldo resultante en Arc: 9,96 → tras despliegue y anclaje **9,948687 USDC**. Coste total de la jugada:
**0,051313 USDC + 0,000001 ETH** (Base: 0,000746553 → 0,000745556 ETH; USDC 99,012553 → 89,032553).

## 3. Cómo verificar sin confiar en FractalAI

Necesitas (a) el recibo público, (b) el directorio de claves (o una clave pineada) y (c) **cualquier** RPC
de Arc. Verificador: `integrations/x402-pqc-witness/src/verify-anchor.mjs` (paquete
`@fractalai/x402-pqc-witness`, export `./verify-anchor`; la versión con soporte Arc/MIDAS aún no está
publicada en npm — usa el repo).

```bash
cd integrations/x402-pqc-witness && npm i
# fixture del repo (sello + referencia de anclaje), RPC público de Arc, anclador pineado
node src/verify-anchor.mjs ../../smart-contracts/deployments/anchors/PQCReceiptAnchor-5042-fe62b072.json \
  --rpc https://rpc.mainnet.arc.io --anchored-by 0xC13789e82661635d9Cea38a53A0390CF9939ef4f
# → { "valid": true, "signature_valid": true, "key_trusted": true, "anchor_valid": true, "mode": "canonical",
#     "chain_id": 5042, "block_number": 24072596, "anchored_at": 1791042087, "tx_hash": "0x31979b7f…", "reason": "ok" }
```

El verificador: 1) verifica la firma ML-DSA-65 con `@noble/post-quantum` sobre `"<domain>\n<content_id>"`
y que `content_id == sha256(canonical)`; 2) comprueba que la clave está `active`/`retiring` en el
directorio; 3) recomputa `receiptId/payloadHash/kid`; 4) exige `eth_chainId == 5042`; 5) lee el evento
`ReceiptAnchored` de la tx (o por `eth_getLogs` filtrando `topic1 = receiptId` en el bloque indicado) y
exige que `payloadHash` y `kid` on-chain coincidan byte a byte. Cualquier fallo → `valid:false` con `reason`.

A mano, sin nuestro código:

```bash
R=https://fractalai.net.co/api/midas/alerts/receipt/fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee
curl -s $R > r.json
jq -r .signature r.json | base64 -d | sha256sum                        # → b9b47ba8… (receiptId)
printf '%s' "$(jq -r .served_message r.json)" | sha256sum              # → ef737f1c… (payloadHash; $(…) quita solo el \n final)
curl -s -X POST https://rpc.mainnet.arc.io -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,
 "method":"eth_getLogs","params":[{"address":"0x1f0d2774943250A7EB179e960203ea86319a8181","fromBlock":"0x16f5194","toBlock":"0x16f5194",
 "topics":["0x86069938b925599e2755e87e9b3242e8f6cbd24f2bc3d1ab52bc585d82646184","0xb9b47ba81d30d95a087ac40b4d7c1c07816148251c147121e7c4aac477cd94eb"]}]}'
# topics[2] == 0xef737f1c…, topics[3] empieza por 0x86c139c960bb274c; data = observedAt (0x6ab876e8) | anchoredBy (0xc137…) | anchoredAt (0x6ac12227)
```

(Los tres comandos se ejecutaron el 2026-10-03 y devolvieron exactamente esos valores; bloque 24072596 = `0x16f5194`.)

## 4. Cómo se produce y se reproduce

```bash
cd smart-contracts
# 1) USDC a Arc (10 USDC, Forwarding Service; la clave vive fuera del repo)
TK=$(cat /fuera/del/repo/treasury.key) node scripts/cctp-bridge-base-to-arc.mjs
# 2) desplegar (aborta si el coste estimado > ARC_MAX_DEPLOY_USDC, por defecto 2 USDC; DRY_RUN=1 para solo estimar)
PRIVATE_KEY=$(cat /fuera/del/repo/treasury.key) npx hardhat run scripts/deploy-pqc-receipt-anchor.js --network arc
# 3) anclar un recibo público (re-verifica la firma ML-DSA-65 ANTES de gastar gas; write-once)
PRIVATE_KEY=… RECEIPT_ID=<hex> npx hardhat run scripts/anchor-public-receipt.js --network arc
```

Red `arc` en `hardhat.config.js` (chainId 5042, `https://rpc.mainnet.arc.io`, sin gasPrice fijo: Arc exige
`maxFeePerGas ≥ 20 gwei` y hardhat lo lee en vivo). Para que el notario `/api/x402/witness` ancle cada sello
en Arc en vez de Arbitrum: `X402_ANCHOR_RPC_URL=https://rpc.mainnet.arc.io`,
`X402_ANCHOR_CONTRACT=0x1f0d2774943250A7EB179e960203ea86319a8181`, `X402_ANCHOR_CHAIN_ID=5042` y una EOA
con unos céntimos de USDC en Arc (drop-in de systemd; **no activado aún en prod**).

## 5. Limitaciones honestas

- **Un recibo anclado, por ahora.** `totalAnchored() == 1`. El hook del notario no está apuntando a Arc en
  producción; anclar cada recibo es una variable de entorno y ~0,003 USDC por recibo.
- **La verificación ML-DSA-65 es off-chain.** La EVM de Arc no verifica FIPS 204; anclamos hashes. No
  afirmar "firma post-cuántica verificada on-chain". `@noble/post-quantum` no es un módulo validado CMVP.
- **`observedAt` es una reclamación del emisor** (aquí 6 días antes del anclaje: el recibo se firmó el
  27-sep y se ancló el 3-oct). El dato con fuerza probatoria es `anchoredAt` (block.timestamp de Arc).
- **Sin auditoría externa** del contrato (1 mapping, 1 evento, sin owner/ETH/upgrade; 20 tests) ni del
  verificador. Sin verificación de código fuente en explorer.arc.io todavía (Sourcify/Blockscout pendiente).
- **Arc es una cadena de semanas de edad** (mainnet desde el 16-sep-2026). Finalidad < 1 s según Circle;
  no hemos evaluado sus supuestos de confianza (conjunto de validadores, gobernanza de Circle).
- **El RPC público limita `eth_getLogs` a 10.000 bloques**: el verificador acota al bloque del anclaje;
  sin `block_number` ni `tx_hash` hay que paginar o usar un RPC propio.
- **Coste del puente:** Circle ejecutó el `maxFee` completo (0,04 USDC) aunque la cotización era ~0,0167.
  Poner `maxFee` ajustado a la cotización `high` + margen pequeño la próxima vez.
- **Un solo anclador.** Cualquiera puede anclar; hoy solo lo hace la tesorería de FractalAI.
- El contrato es el mismo que en Arbitrum (sin cambios de código); ningún componente usa funcionalidad
  específica de Arc más allá de pagar gas en USDC.

## 6. Fuentes (consultadas 2026-10-03)

- Arc: https://docs.arc.io/arc/references/connect-to-arc · https://docs.arc.io/arc/references/contract-addresses ·
  https://docs.arc.io/arc/references/evm-differences · https://docs.arc.io/arc/references/gas-and-fees ·
  https://docs.arc.io/integrate/exchanges/cctp-bridging (docs.arc.network redirige a docs.arc.io)
- CCTP v2: https://developers.circle.com/cctp/evm-smart-contracts · https://developers.circle.com/cctp/cctp-supported-blockchains
  (Arc = dominio 26, Base = 6) · https://developers.circle.com/cctp/concepts/forwarding-service ·
  https://developers.circle.com/cctp/howtos/transfer-usdc-with-forwarding-service ·
  https://developers.circle.com/cctp/quickstarts/transfer-usdc-ethereum-to-arc · API `https://iris-api.circle.com/v2/burn/USDC/fees/6/26?forward=true`
  y `https://iris-api.circle.com/v2/messages/6?transactionHash=<burn>`
- USDC: https://developers.circle.com/stablecoins/usdc-contract-addresses (Arc `0x3600…0000`, Base `0x8335…2913`)

## Trust Kernel v2 (2026-10-07)

La verificación de este documento la decide ahora `kernel/` (especificación normativa: `spec/TRUST-KERNEL.md`,
corpus adversarial: `corpus/`). Cambios relevantes: el contrato de anclaje se fija por `chainId → (dirección, code
hash)` en `kernel/trust-roots.json` (una dirección traída por el sello se rechaza); la hora sale de la cabecera del
bloque y `observedAt` debe ser igual a la hora FIRMADA; Solana exige génesis del cluster, `finalized` + `blockTime`,
firmante anunciado y un único Memo v2 idéntico byte a byte; las redes de prueba quedan marcadas `test` y no cuentan
como prueba de tiempo salvo `allowTestnetAnchors`; el ciclo de vida de la clave se evalúa en la hora firmada y una
clave revocada solo vale con un anclaje anterior a `revoked_at`. Protocolo anti-squatting "anclar antes de publicar":
spec §10. Límites (RPC/consenso, raíces fijadas por TOFU, sin auditoría externa, librería no CMVP): spec §11.
