# Paga en tu moneda: COP, MXN, BRL, ARS · Pay in your currency

[Español](#español) · [English](#english)

`pay.mjs` es un cliente x402 mínimo (Node 20+, una sola dependencia: `ethers`) que paga los endpoints x402 de
FractalAI en una stablecoin latinoamericana. Lee el `402` real, elige la oferta de tu token, firma exactamente lo que
el servidor espera y te devuelve el resultado y el recibo de entrega verificable.

| Token | Moneda | Red | Método x402 `exact` | ¿Gas del pagador? |
|---|---|---|---|---|
| MXNB | MXN | Base, Arbitrum One | EIP-3009 `transferWithAuthorization` | No (sin gas) |
| USDC | USD | Base | EIP-3009 | No |
| COPM, COPW | COP | Polygon | Permit2 `permitWitnessTransferFrom` vía `x402ExactPermit2Proxy` | Una vez: `approve(Permit2)` en POL |
| BRLA | BRL | Polygon | Permit2 | Una vez, en POL |
| wCOP, wARS, wBRL, wMXN | COP, ARS, BRL, MXN | Base, World Chain | Permit2 | Una vez, en ETH |

---

## Español

### Los 3 pasos

```bash
cd examples/pay-latam && npm install

# 1) Mira el precio de hoy en tu moneda (no firma nada, no necesita clave)
node pay.mjs --list --route witness
node pay.mjs --token COPM --route witness

# 2) Pon la clave del pagador SOLO en la variable de entorno (nunca en un archivo ni en la línea de comandos)
read -s PAYER_PRIVATE_KEY && export PAYER_PRIVATE_KEY

# 3) Paga. Si el token usa Permit2 y falta la aprobación, el cliente envía approve(Permit2) una sola vez
node pay.mjs --token COPM --route witness --body mi-seal.json --yes
node pay.mjs --token MXNB --network base --route witness --yes        # MXNB existe en Base y Arbitrum
node pay.mjs --token wARS --network worldchain --route witness --yes
```

Salida (resumida):

```
Price      15.98 COPM on Polygon (eip155:137), method permit2, payTo 0xC137…ef4f
Rate       1 USD = 3194.44 COP — TRM (Superintendencia Financiera de Colombia) via datos.gov.co …
Signed     1 permit2 authorization, nonce …
PAID       15.98 COPM on Polygon
tx         0x…
receiptId  77795afa…
verify     node ../../verifier/verify-delivery-receipt-openssl.mjs <receiptId> --pin-ed25519 … --pin-ml-dsa-65 …
```

Con `--json` imprime una sola línea JSON al final (para agentes). `--max 20` rechaza pagar más de 20 unidades del
token. `--url` apunta a cualquier otro vendedor x402 con la misma forma de `402`.

### Precios en moneda local, leídos del 402

El cliente no tiene precios fijos: los lee de `accepts[]` y de `pricing_latam` / `pricing_copm` del `402`. El
servidor calcula cada monto como **precio en USD × tasa oficial de referencia** del día:

| Moneda | Fuente que publica el 402 |
|---|---|
| COP | TRM, Superintendencia Financiera de Colombia (datos.gov.co, dataset 32sa-8pi3) |
| MXN | FIX del Banco de México |
| BRL | PTAX del Banco Central do Brasil (cierre, venta) |
| ARS | Banco Central de la República Argentina (API Estadísticas Cambiarias) |

Ejemplo leído el 2026-10-11 para `witness` (USD 0.005): 15.98 COPM / COPW / wCOP · 0.0921 MXNB / wMXN · 0.0250
BRLA / wBRL · 7.59 wARS · 0.005 USDC. Estas cifras cambian a diario: córrelo con `--list` para ver las de hoy.

### Qué firma y por qué no cobra dos veces

- **EIP-3009** (MXNB, USDC): `TransferWithAuthorization` sobre el dominio EIP-712 del token (`extra.name`,
  `extra.version`, chainId, contrato del token), `to = payTo`, `value = amount`, nonce aleatorio de 32 bytes.
- **Permit2** (resto): `PermitWitnessTransferFrom` sobre el dominio `Permit2`, `spender = 0x402085c2…0001`
  (`x402ExactPermit2Proxy`), `witness.to = payTo`, `permitted.amount = amount`. El proxy solo puede enviar al
  `payTo` firmado: el servidor no puede desviar los fondos.
- El encabezado (`PAYMENT-SIGNATURE` y `X-PAYMENT`) lleva `{x402Version: 2, scheme, network, resource, accepted, payload}`.
- **Una firma por ejecución.** Ante timeout, error de red o 429/502/503/504 se reenvía **el mismo pago firmado**.
  Antes de cada reenvío el cliente mira en la cadena si ese nonce ya se consumió; si sí, se detiene y avisa
  "pagado, respuesta perdida" en vez de pagar otra vez. Un `409` significa que ese pago ya se está canjeando: el
  cliente espera a verlo en la cadena y lo informa.
- La clave privada solo se lee de `PAYER_PRIVATE_KEY`; no se escribe en disco ni aparece en la salida (las pruebas
  lo comprueban). El cliente rechaza `--key`.

### Verificar el recibo

Si la ruta devuelve la extensión `delivery-receipt`, el cliente imprime `receiptId` y la orden para verificarlo
**solo con OpenSSL** (Node 24+): firmas Ed25519 + ML-DSA-65, directorio de claves con raíz fijada, y la
transferencia de liquidación leída de un RPC público:

```bash
node verifier/verify-delivery-receipt-openssl.mjs <receiptId> \
  --pin-ed25519 3e7f09b0566701962c0994dba8da89b930a091506b4fbb6472a742bcd2372877 \
  --pin-ml-dsa-65 bec0e906bf74e6f20003f073b4a0d61a99309810909b549cf4db27af159b94c1
```

### Pruebas (forks locales, sin dinero real)

```bash
npm test        # necesita anvil (Foundry); ANVIL=/ruta/a/anvil si no está en el PATH
```

Levanta forks de Base y Polygon mainnet con anvil, un vendedor x402 mínimo de prueba (`test/server.mjs`, mismo
`402` que producción, verifica y liquida en el fork) y cuentas efímeras generadas en memoria. Cubre USDC, MXNB y
wCOP en Base, COPM y BRLA en Polygon; aprobación Permit2 única; reintento con el mismo pago tras un 503; respuesta
perdida tras liquidar (no paga dos veces); `--max`; y rechazo de un pagador con código EIP-7702. Nunca paga a
producción.

### Honestidad

- **Pre-piloto.** Los pagos en monedas LatAm están en producción (COPM desde 2026-10-09), pero los pagos de
  aceptación fueron nuestros (wallet propia): todavía no hay clientes que paguen así.
- **La tasa es la referencia fiat oficial**, no el precio de mercado del token. Si un token cotiza por debajo de su
  paridad, pagas más en valor real; si cotiza por encima, menos. El servidor acepta entre 1× y 2× la cotización
  para tolerar el cambio diario de tasa; este cliente firma exactamente el monto cotizado.
- **Aceptar un token no es avalar a su emisor.** COPM, BRLA, MXNB, COPW y los w-tokens tienen emisores distintos,
  algunos pueden pausar o congelar cuentas, y su respaldo es responsabilidad de cada emisor. Revisa a cada uno.
- Solo wallets EOA (firmas ECDSA). Las cuentas con código (smart accounts, delegaciones EIP-7702) se rechazan antes
  de firmar, porque el token o Permit2 verificarían la firma por ERC-1271.
- Permit2 requiere una aprobación ilimitada a Permit2 (el patrón estándar de Uniswap Permit2) y gas nativo una vez.
- Si se pierde la respuesta después de liquidar, el recibo de entrega no se puede recuperar por nonce desde este
  cliente; el pago queda demostrable por la transferencia en la cadena.

---

## English

`pay.mjs` is a minimal x402 client (Node 20+, one dependency: `ethers`) that pays FractalAI's x402 endpoints in a
Latin-American stablecoin. It reads the real `402`, picks your token's offer, signs exactly what the server expects
and returns the result plus a verifiable delivery receipt.

### The 3 steps

```bash
cd examples/pay-latam && npm install
node pay.mjs --list --route witness                       # 1) today's prices in local currency (signs nothing)
read -s PAYER_PRIVATE_KEY && export PAYER_PRIVATE_KEY     # 2) the payer key lives ONLY in the environment
node pay.mjs --token BRLA --route witness --yes           # 3) pay (one-time approve(Permit2) if needed)
```

`--network` picks the chain when a token is offered on several (MXNB: base / arbitrumone; w-tokens: base /
worldchain). `--json` prints one JSON line for agents, `--max <units>` caps the price, `--url` targets any x402
seller with the same `402` shape.

### Local prices, read from the 402

Nothing is hard-coded: amounts come from `accepts[]` and `pricing_latam` / `pricing_copm`. The server prices each
token as **USD price × the day's official reference rate**: COP from the TRM (Superintendencia Financiera), MXN from
Banco de México FIX, BRL from Banco Central do Brasil PTAX, ARS from Banco Central de la República Argentina.
Snapshot of 2026-10-11 for `witness` (USD 0.005): 15.98 COPM / COPW / wCOP, 0.0921 MXNB / wMXN, 0.0250 BRLA / wBRL,
7.59 wARS. Run `--list` for today's.

### What it signs, and why it never pays twice

- **EIP-3009** (MXNB, USDC): `TransferWithAuthorization` over the token's own EIP-712 domain (`extra.name`,
  `extra.version`, chainId, token address), `to = payTo`, `value = amount`, random 32-byte nonce. Gasless.
- **Permit2** (all others): `PermitWitnessTransferFrom` over the `Permit2` domain, `spender = x402ExactPermit2Proxy`
  (`0x402085c2…0001`), `witness.to = payTo`. The proxy can only pay the signed `payTo`.
- **One signature per run.** On a timeout, network error or 429/502/503/504 it re-sends the **same signed payment**,
  and before each re-send it checks on-chain whether that nonce was already consumed; if so it stops with
  "paid, response lost" instead of paying again. A `409` means the payment is already being redeemed: it waits to
  see it on-chain and reports it.
- The private key is read only from `PAYER_PRIVATE_KEY`, never written to disk, never printed (the tests assert it).

### Verify the receipt

When the route returns the `delivery-receipt` extension, the client prints the `receiptId` and the OpenSSL-only
verification command (`verifier/verify-delivery-receipt-openssl.mjs`, Node 24+, pins as above).

### Tests (local forks, no real money)

`npm test` starts anvil forks of Base and Polygon mainnet, a minimal x402 test seller (`test/server.mjs`, same `402`
shape as production, verifies and settles on the fork) and ephemeral in-memory accounts. It pays USDC, MXNB and wCOP
on Base and COPM and BRLA on Polygon, and checks the one-time Permit2 approval, the same-payment retry after a 503,
the lost-response-after-settlement case (charged once), `--max`, and the refusal of an EIP-7702-delegated payer. It
never pays production. The test seller's delivery receipt is an unsigned placeholder.

### Honesty

- **Pre-pilot.** LatAm payments are live in production (COPM since 2026-10-09), but acceptance payments came from
  our own wallet: no customer pays this way yet.
- **The rate is the official fiat reference**, not the token's market price. The server accepts 1×–2× the quote to
  absorb the daily rate change; this client signs exactly the quote.
- **Accepting a token is not endorsing its issuer.** Each issuer is responsible for its reserves; several can pause
  or freeze accounts.
- EOA wallets only (ECDSA). Addresses with code (smart accounts, EIP-7702 delegations) are refused before signing.
- Permit2 needs one unlimited approval to Permit2 (the standard pattern) and native gas once per token and chain.
- If the response is lost after settlement, the delivery receipt cannot be fetched by nonce from this client; the
  payment remains provable by its on-chain transfer.

License: Apache-2.0.
