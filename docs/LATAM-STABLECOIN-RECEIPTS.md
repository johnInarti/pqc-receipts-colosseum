# LatAm Stablecoin Receipts — recibos post-cuánticos de pagos en stablecoins latinoamericanas

| | |
|---|---|
| Estado | **Construido y probado; NO desplegado.** Kernel 2.1 (JS + Python), emisor de referencia (`issuer/`), 44 vectores nuevos en el corpus (8 positivos con transferencias reales). En producción no existe todavía ninguna clave con `use = stablecoin-receipt` en el directorio publicado (época 3). |
| Especificación normativa | [`spec/TRUST-KERNEL.md` §12](../spec/TRUST-KERNEL.md) |
| Tipo (`kind`) | `latam-stablecoin-receipt` · dominio `FRACTALAI-stablecoin-receipt-v1` · uso de clave `stablecoin-receipt` |
| Firma | ML-DSA-65 (FIPS 204, nivel 3 de NIST). Módulo `@noble/post-quantum`, **no validado CMVP / FIPS 140-3**. |
| Fecha | 2026-10-08 |

## 1. Qué es, en una frase

Dado un pago en una stablecoin latinoamericana **que ya ocurrió on-chain**, FractalAI emite un recibo firmado con
ML-DSA-65 que dice exactamente **qué token, cuánto, de qué dirección, a qué dirección, en qué transacción, en qué log,
en qué bloque (número, hash y hora) y con cuántas confirmaciones / qué finalidad**, y que **cualquiera puede verificar
sin confiar en FractalAI**: la firma se comprueba offline y cada hecho se recalcula desde la cadena con RPC públicos.

El recibo **no mueve fondos, no es una orden de pago y no identifica personas**. Certifica un hecho on-chain pasado.

## 2. Tokens soportados (registro fijado `fractalai.latam-stablecoins/1`)

Cada dirección se verificó el 2026-10-08 con `eth_chainId` + `symbol()` + `name()` + `decimals()` en **dos RPC públicos
independientes por cadena**, con respuestas idénticas.

| Token | Moneda | Cadena | Contrato | Decimales | Fuente de la dirección |
|---|---|---|---|---|---|
| COPM ("COP Minteo") | COP | Polygon (137) | `0x12050c705152931cfee3dd56c52fb09dea816c23` | 18 | emisor (directorio de contratos Minteo) |
| BRLA | BRL | Polygon (137) | `0xe6a537a407488807f0bbeb0038b79004f19dddfb` | 18 | explorador / CoinGecko |
| BRLA | BRL | Base (8453) | `0xfcb34c47f850f452c15ea1b84d51231c38a61783` | 18 | explorador |
| MXNB | MXN | Arbitrum One (42161) | `0xf197ffc28c23e0309b5559e7a166f2c6164c80aa` | 6 | emisor (docs de Bitso/Juno) |
| MXNB | MXN | Base (8453) | `0xf197ffc28c23e0309b5559e7a166f2c6164c80aa` | 6 | CoinGecko |
| wARS ("Peso Argentino") | ARS | Base (8453) | `0x0dc4f92879b7670e5f4e4e6e3c801d229129d90d` | 18 | emisor (whitepaper wFIAT de Ripio) |
| wBRL ("Real Brasileño") | BRL | Base (8453) | `0xd76f5faf6888e24d9f04bf92a0c8b921fe4390e0` | 18 | emisor (whitepaper wFIAT de Ripio) |

Ninguna dirección del censo prioritario quedó excluida: las siete respondieron el símbolo y los decimales esperados.
Estar en la lista **no** es un aval del emisor, de sus reservas ni de su situación regulatoria. COPM en Celo, BRLA en
Celo/Gnosis, BRZ, BRL1, COPW, wCOP, etc. no están fijados todavía (no se verificaron para esta versión); añadirlos es
una versión nueva del registro.

## 3. Para qué le sirve a una fintech colombiana o latinoamericana

### 3.1 Conciliación

- Un recibo por cada pago recibido, con los hechos **leídos de la cadena** (no del cliente ni del front-end):
  monto en unidades mínimas **y** en decimal (`amount_decimal`, sin errores de coma flotante), remitente, destinatario,
  `tx_hash` + `log_index` (identifica la transferencia exacta aunque la transacción tenga varias, p. ej. un swap).
- El campo `reference` (p. ej. `factura:FE-2026-000123`) asocia el pago con la factura o el pedido. Queda **firmado
  como asociación declarada por quien lo pidió**; FractalAI no verifica que esa factura exista.
- Formato canónico de líneas `clave=valor`, en orden fijo: se procesa igual en cualquier lenguaje (hay verificador
  en JavaScript y en Python) y se puede archivar como texto.

### 3.2 Auditoría

- Un auditor interno o externo verifica cada recibo **sin acceso a sistemas de la fintech ni de FractalAI**:
  `fractalai-verify recibo.json --kind latam-stablecoin-receipt --onchain`. Si la firma, la clave o cualquier hecho
  on-chain no cuadra, el veredicto dice **qué nivel falló y por qué** (código de razón).
- La firma es post-cuántica (ML-DSA-65). Para archivos que deben conservarse muchos años (los libros y soportes
  contables suelen tener plazos largos de conservación; confírmelo con su asesor), esto evita depender de firmas
  ECDSA/RSA cuya seguridad a largo plazo frente a computación cuántica es el riesgo conocido de "cosechar ahora,
  falsificar después".
- El recibo es **anclable** en `PQCReceiptAnchor` (Arbitrum One / Arc, §7 y §10 de la spec) para probar que existía en
  una fecha determinada por el consenso, no por el reloj del emisor.

### 3.3 Disputas

- "Yo pagué" / "no me llegó": el recibo fija la transferencia exacta (tx, log, bloque, hash del bloque, hora del
  bloque). Si hubo reorganización de la cadena, si la transacción revirtió o si el log es de otro contrato, el
  verificador lo detecta y lo dice con un código (`PAYMENT_REORGED`, `PAYMENT_TX_REVERTED`,
  `PAYMENT_LOG_WRONG_CONTRACT`).
- Si alguien edita la copia legible del recibo (por ejemplo, el monto que muestra un panel), el verificador la rechaza
  (`UNSIGNED_FIELD_MISMATCH`); si edita lo firmado, la firma no verifica (`SIGNATURE_INVALID`).
- Si **el propio emisor** firmara algo que la cadena contradice (clave comprometida o error), el nivel `onchain` lo
  delata aunque la firma y la clave sean válidas (`trusted = true`, `onchain = false`).

### 3.4 Evidencia ante la SFC, la UIAF u otras autoridades — sin afirmar cumplimiento normativo

- El recibo puede servir como **soporte técnico documental** de que un movimiento on-chain concreto ocurrió (qué,
  cuánto, entre qué direcciones, cuándo según el consenso), verificable por un tercero con herramientas abiertas.
- **No es** un reporte regulatorio (no es un ROS a la UIAF ni un reporte a la SFC), **no** sustituye el SARLAFT ni
  ningún sistema de gestión de riesgo, **no** identifica a las personas detrás de las direcciones, **no** incluye
  verificación de listas restrictivas ni datos de la regla de viaje, y **no** es una firma digital certificada en el
  sentido de la Ley 527 de 1999 (no la emite una entidad de certificación acreditada).
- FractalAI **no afirma** que usar estos recibos cumpla ninguna norma de la SFC, la UIAF, el Banco de la República,
  la CNBV, el BCB ni ningún otro regulador. Su valor probatorio en un proceso concreto lo decide la autoridad o el
  juez, con la asesoría jurídica de la fintech.

## 4. Qué prueba y qué no prueba un recibo válido

| Prueba (si el veredicto es válido en los niveles indicados) | No prueba |
|---|---|
| La clave de FractalAI autorizada para `stablecoin-receipt` firmó exactamente estos 18 campos (`authentic` + `trusted`). | Quién es la persona o empresa dueña de `from` o `to`. |
| La transacción existe, no revirtió y su log en `log_index` es un `Transfer` del contrato fijado, con ese `from`, `to` y monto (`onchain`). | El origen lícito de los fondos, ni el propósito económico del pago. |
| El bloque firmado sigue siendo el canónico, con esa hora de cabecera y al menos esas confirmaciones; finalizado si así lo dice (`onchain`). | Que la stablecoin esté respaldada 1:1, ni la solvencia de su emisor. |
| El token es el contrato fijado en esa cadena, con el símbolo y los decimales fijados, y hoy sigue respondiendo lo mismo (`integrity` + `onchain`). | Que `reference` corresponda a una factura real. |
| El recibo existía antes de cierto bloque, si está anclado (`time_anchored`). | Cumplimiento de ninguna norma. |

## 5. Ejemplo real (corpus `P30`)

Transferencia **real** de 667.703 COPM en Polygon, leída por `eth_getLogs` el 2026-10-08 y re-verificada contra dos RPC
públicos independientes (firmada aquí con una **clave de prueba** determinista del corpus, no con la de producción):

```
FRACTALAI-stablecoin-transfer-v1
registry=fractalai.latam-stablecoins/1
chain_id=137
token=0x12050c705152931cfee3dd56c52fb09dea816c23
token_symbol=COPM
token_decimals=18
from=0xbb6cb4e3fc7ab30ac0f2bb2aeb10b35b180eb0a6
to=0x8ca3c426764058249d7cf65b9364773c02fd514f
amount=667703000000000000000000
amount_decimal=667703
tx_hash=0x5cd84fa7d8e6a4fafc9783f7f0ced013225307a904d7bceb6923e7ac1777420b
log_index=2229
block_number=95201999
block_hash=0x93d48221b0869f9de89eb42d16cc83c53d1863b44e035ac66d9f8c892268978a
block_timestamp=1791508208
confirmations=8190
finality=finalized
issued_at=1791520495
reference=factura:FE-2026-000123
```

Mensaje firmado: `FRACTALAI-stablecoin-receipt-v1\n` + sha256 de ese texto
(`57e787af07ef27b67ceb83570043054a0145122f13def299fdfb79a56098a549`).

Otros positivos reales del corpus: BRLA en Polygon (8,4 BRLA, `P31`), BRLA en Base (48,52 BRLA, `P32`), MXNB en
Arbitrum One (135 MXNB, `P33`), la pata MXNB (log 22) de un swap multi-token en Base (`P34`).

## 6. Cómo verificar

```bash
# JavaScript (Node 20+)
cd kernel && npm install
node bin/fractalai-verify.mjs recibo.json --kind latam-stablecoin-receipt --onchain \
  --rpc eip155:137=https://polygon-bor-rpc.publicnode.com --rpc eip155:137=https://polygon.drpc.org --quorum 2 \
  --require integrity,authentic,trusted,onchain
# Código de salida: 0 válido · 10 integridad · 11 firma · 12 confianza en la clave · 15 hechos on-chain
```

```python
from fractalai_pqc_verify.kernel import verify
v = verify(open("recibo.json").read(), kind="latam-stablecoin-receipt", directory=directorio_json, check_onchain=True,
           rpc={"eip155:137": ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org"]},
           policy={"require": ["integrity", "authentic", "trusted", "onchain"], "rpc_quorum": 2})
v["valid"], v["levels"], v["onchain"], v["reasons"]
```

Sin red (`verifySync` o sin `--onchain`) se comprueban integridad, firma y clave; el nivel `onchain` queda sin evaluar.

## 7. Ataques cubiertos (vectores del corpus, JS y Python al 100 %)

| Ataque | Dónde se detiene | Vector |
|---|---|---|
| Monto alterado en la copia legible | integridad | `N-SC-amount-altered-unsigned-copy`, `N-SC-amount-as-json-number` |
| Monto alterado en lo firmado | firma | `N-SC-amount-altered-canonical` |
| Clave válida firma un monto ×10 | on-chain | `N-SC-compromised-signer-inflates-amount` |
| Token falso con el mismo símbolo (COPM, 18 dec.) | integridad (registro) | `N-SC-fake-token-same-symbol` |
| Dirección real con símbolo cambiado | integridad | `N-SC-pinned-token-wrong-symbol` |
| Log de otro contrato (USDC real dentro de un swap real) | on-chain | `N-SC-log-of-another-contract` |
| Evento que no es Transfer (Approval real) | on-chain | `N-SC-approval-is-not-a-transfer` |
| Transacción revertida / inexistente | on-chain | `N-SC-tx-reverted`, `N-SC-tx-not-found` |
| Cadena equivocada (en el recibo / en el RPC) | integridad / on-chain | `N-SC-wrong-chain-in-receipt`, `N-SC-wrong-chain-rpc` |
| Reorg simulado (cabecera distinta, re-inclusión, bloque+1, log `removed`) | on-chain | `N-SC-reorg-*`, `N-SC-log-removed` |
| RPC mentiroso / quórum insuficiente | on-chain | `N-SC-cross-rpc-disagreement`, `N-SC-quorum-not-met` |
| Finalidad sobre-declarada (respuesta real de un RPC rezagado) | on-chain | `N-SC-claimed-finality-not-reported` |
| Confirmaciones infladas, hora alterada, partes intercambiadas | on-chain | `N-SC-confirmations-overclaimed`, `N-SC-compromised-signer-*` |
| Clave de otro producto (x402) firmando pagos / clave reservada | confianza | `N-SC-x402-key-cannot-sign-payments`, `N-SC-reserved-key` |
| Mint o burn presentado como pago | integridad | `N-SC-mint-is-not-a-payment` (+ burn real en `issuer/test`) |

El emisor, además, se niega a firmar todos esos casos (`issuer/test/issuer.test.mjs`, con transacciones reales: el
USDC del swap, el Approval y el burn de MXNB).

## 8. Límites honestos

- **Confianza en RPC**: sin cliente ligero, el verificador cree a los RPC configurados; con varios, exige que coincidan.
  Los RPC públicos limitan tráfico: el 2026-10-08 vimos HTTP 403 de `1rpc.io`, `base-rpc.publicnode.com` y
  `arbitrum-one-rpc.publicnode.com`, y `mainnet.base.org` limitó `eth_getLogs`. El verificador falla cerrado
  (`RPC_ERROR`); producción necesita RPC dedicados.
- **Finalidad**: es lo que reporta la etiqueta `finalized` de cada RPC; dos RPC de Arbitrum dieron respuestas distintas
  para el mismo bloque (registrado en el corpus).
- **Metadatos del token**: `symbol()`/`decimals()` se leen en `latest`; la mayoría de estos tokens son proxies
  actualizables. Si un emisor cambia el símbolo, los recibos viejos fallan `onchain` a propósito hasta revisar el
  registro.
- **Identidad**: direcciones, no personas. Sin KYC, sin listas restrictivas, sin regla de viaje.
- **Criptografía**: implementaciones abiertas (`@noble/post-quantum`, `dilithium-py`), sin validación CMVP / FIPS 140-3
  y sin auditoría externa de este código.
- **Producción**: hoy no hay clave de producción para este tipo ni endpoint desplegado; ningún cliente lo usa.

## 9. API propuesta del endpoint x402 de pago por recibo (para que Codex la despliegue)

> Propuesta. No toca el facilitador x402 (`frontend/lib/x402-facilitator.ts`) ni la rama `feat/x402-copm-polygon`;
> reutiliza el flujo x402 existente del catálogo (402 → `X-PAYMENT` → settle). El cobro en COPM llega cuando esa rama
> se integre: el precio solo cambia de activo.

### 9.1 `POST /api/x402/stablecoin-receipt`

Petición (JSON, ≤ 2 KiB):

```json
{ "chain_id": 137, "tx_hash": "0x5cd8…420b", "log_index": 2229, "reference": "factura:FE-2026-000123" }
```

- `log_index` opcional: si se omite y la transacción tiene **exactamente un** `Transfer` de un token fijado, se usa ese;
  si hay varios → `422 {"code":"INPUT_SHAPE"}` pidiendo `log_index`.
- **No** se aceptan `amount`, `from`, `to` ni `token`: el servidor los lee de la cadena.

Flujo (orden obligatorio, "verificar antes de cobrar"):

1. Sin `X-PAYMENT` → `402` con `accepts` (precio sugerido: **0,01 USDC en Base**, `resource` =
   `/api/x402/stablecoin-receipt`, `description` = "Post-quantum ML-DSA-65 receipt for an on-chain LatAm stablecoin
   transfer", `outputSchema` = el documento de la §12.2).
2. Con `X-PAYMENT`: ejecutar `issueStablecoinReceipt` **con `selfVerify: true` y SIN liquidar todavía**. Si el emisor
   se niega → `422 {"code": "<CÓDIGO>", "detail": "…"}` y **no se liquida el pago** (el cliente no paga por un recibo
   que no se emitió). Códigos: `TOKEN_NOT_PINNED`, `PAYMENT_TX_REVERTED`, `PAYMENT_TX_NOT_FOUND`,
   `PAYMENT_LOG_NOT_FOUND`, `PAYMENT_LOG_NOT_TRANSFER`, `PAYMENT_NOT_A_TRANSFER`, `TOKEN_METADATA_MISMATCH`,
   `PAYMENT_REORGED`, `PAYMENT_CONFIRMATIONS`, `PAYMENT_NOT_FINALIZED` (con `Retry-After`), `RPC_DISAGREEMENT`,
   `RPC_ERROR` (→ `503`).
3. Liquidar el pago x402 (facilitador existente). Si falla → `402` y el recibo se descarta.
4. (Recomendado, spec §10) anclar el recibo en `PQCReceiptAnchor` antes de servirlo públicamente, o encolarlo.
5. `200`:

```json
{
  "receipt": { "profile": "latam-stablecoin-receipt", "algorithm": "ml-dsa-65", "domain": "FRACTALAI-stablecoin-receipt-v1",
               "transfer_id": "…", "transfer_canonical": "…", "signed_message": "…", "transfer": { "…": "…" },
               "issued_at": 1791520495, "public_key": "…", "signature": "…" },
  "verify": { "kind": "latam-stablecoin-receipt", "key_directory": "https://fractalai.net.co/.well-known/x402-receipt-keys",
              "registry": "https://fractalai.net.co/.well-known/stablecoin-registry.json",
              "cli": "fractalai-verify receipt.json --kind latam-stablecoin-receipt --onchain" },
  "x402": { "request_id": "…", "settle_tx": "0x…", "settle_block_number": 0, "settle_log_index": 0 }
}
```

con la cabecera `X-PAYMENT-RESPONSE` habitual.

### 9.2 Rutas gratuitas de apoyo

- `GET /api/stablecoin-receipts/{transfer_id}` → el recibo ya emitido (para que el auditor lo descargue por id;
  `expectedId` = `transfer_id` en el verificador).
- `GET /.well-known/stablecoin-registry.json` → copia byte a byte de `kernel/latam-stablecoins.json`.
- Entrada nueva en `/.well-known/x402.json` (catálogo / Bazaar) para la ruta de pago.

### 9.3 Configuración del servidor

- Clave de firma ML-DSA-65 **nueva y exclusiva** (`use = stablecoin-receipt`), en la misma custodia que las claves de
  recibos actuales; nunca reutilizar la clave `x402-receipt` (el kernel lo rechaza: `KEY_USE_MISMATCH`).
- Por cadena (137, 8453, 42161): **al menos dos RPC de proveedores distintos**; el emisor exige que coincidan.
- Política por defecto: `requireFinalized: true`, `minConfirmations: 1`; para pagos sin finalizar, responder `422
  PAYMENT_NOT_FINALIZED` con `Retry-After` (Polygon ≈ segundos, Base/Arbitrum ≈ 15–30 min según el RPC).
- Idempotencia: cachear por `(chain_id, tx_hash, log_index, reference)` y servir el mismo recibo; re-emitir produce
  otro `issued_at`/`confirmations` (otro `transfer_id`).
- Límite de tasa por IP / pagador y tamaño de petición acotado; registrar `transfer_id`, `request_id` y código de
  rechazo (sin secretos).

## 10. Qué falta para producción

1. **Clave de producción**: generar la clave ML-DSA-65 `stablecoin-receipt` en el servidor y publicarla en la época 4
   del directorio, firmada por la clave de gobernanza (acción del fundador; el kernel solo la aceptará vía la cadena
   de épocas desde el checkpoint fijado, §6.2).
2. **Endpoint** de la §9 desplegado por Codex (con el facilitador existente; el cobro en COPM cuando se integre la rama
   `feat/x402-copm-polygon`).
3. **RPC dedicados** (≥ 2 proveedores por cadena) en lugar de los públicos.
4. **Anclaje** de cada recibo emitido en `PQCReceiptAnchor` antes de servirlo (§10 de la spec).
5. **Publicar** el kernel 2.1 (npm `@fractalai/pqc-trust-kernel`) y el paquete Python con este tipo.
6. **Revisión externa** del formato y del verificador (hoy solo hay revisión interna adversarial).
7. **Asesoría jurídica** antes de ofrecerlo como "evidencia" a clientes regulados en Colombia u otros países.
8. Ampliar el registro (COPM/BRLA en Celo, BRZ, BRL1, wCOP…) solo tras verificarlos igual que la versión 1.
