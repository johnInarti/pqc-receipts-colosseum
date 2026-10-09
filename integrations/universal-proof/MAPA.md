# MAPA — FractalAI como capa de prueba universal para pagos de agentes y fintech

**Fecha de verificación:** 2026-10-09
**Método:** lectura directa de repositorios y especificaciones oficiales (clonados o leídos con `gh api` / WebFetch), una llamada `eth_getCode` propia para ERC-8004 y documentos oficiales de los bancos centrales (BanRep vía su CDN oficial, BCB, Banxico).
**Límite declarado:** el cupo de búsqueda web de la sesión se agotó. La adopción que solo aparece en prensa (comercios de ChatGPT, transacciones de Mastercard Agent Pay, socios de AP2 en producción) **no está verificada** y se marca con ⚠.
**Alcance:** x402 y Coinbase AgentKit los cubre otro agente; aquí solo aparecen cuando otro protocolo los transporta (por ejemplo `x402/payment-response` dentro de MCP).

---

## 0. La tesis en una línea, y su límite

Todos los protocolos revisados autorizan pagos, transportan credenciales o firman *peticiones*. **Casi ninguno firma una prueba verificable que ligue el pago con el contenido que se entregó**, y **ninguno usa criptografía post-cuántica**. Todos usan ES256, Ed25519, PS256/RS256, secp256k1/EIP-712 o HMAC.

El encaje honesto de FractalAI es una **contrafirma ML-DSA-65 (FIPS 204) adicional**, y nunca reemplaza el recibo del protocolo:

```
FRACTALAI-agent-commerce-receipt-v1\n sha256( JCS({ protocolo, perfil, issued_at,
        payment:{ identificadores del pago },
        bindings:{ hashes de los artefactos del protocolo (mandatos, recibos, requestHash…) },
        delivery:{ sha256 del contenido entregado } }) )
```

El verificador es el Trust Kernel v2 público (https://github.com/johnInarti/pqc-receipts-colosseum), ampliado aquí con el `kind` `agent-commerce-receipt` (§13 de la spec, ver `kernel-patch/`).

**Qué NO dice el recibo:**
- que el pago se liquidó, salvo que el perfil lo recompruebe contra el artefacto del protocolo;
- que el contenido sea correcto o de calidad;
- quiénes son las partes (no hay KYC).

**"Pago cuántico-seguro" es falso:** los pagos y los comprobantes oficiales siguen siendo clásicos. Lo que es post-cuántico es la integridad del recibo de ligadura a largo plazo.

---

## 1. Protocolos de pago de agentes

### 1.1 Google AP2 — Agent Payments Protocol

| | |
|---|---|
| Repositorio | https://github.com/google-agentic-commerce/AP2 — clonado en el commit `e1ea56db` del 2026-04-29; unas 3,2 mil estrellas |
| Versión | **v0.2.0 (2026-04-28)**, "Release of V2" en el CHANGELOG. La v0.1.0 es del 2025-09-16 |
| Gobernanza | La especificación central se **donó a FIDO Alliance** (https://blog.google/products-and-platforms/platforms/google-pay/agent-payments-protocol-fido-alliance/). Según CONTRIBUTING, el repositorio solo acepta cambios en *samples* y *sdk*. ⚠ No se identificó el grupo de trabajo concreto de FIDO |
| Adopción real | ⚠ No hay despliegues en producción verificables en fuentes oficiales. El repositorio contiene muestras en Python, Go y Android, y una de ellas implementa `FLOW=x402` |

**Qué cambió en v0.2.** `IntentMandate`/`CartMandate` desaparecieron. Ahora hay **Checkout Mandate** y **Payment Mandate** en SD-JWT (con cadenas abiertas y cerradas, KB-SD-JWT y `sd_hash`) y, sobre todo, **Checkout Receipt y Payment Receipt firmados como JWT ES256**:
- Esquema `code/sdk/schemas/ap2/payment_receipt.json`: `{status, iss, iat, reference, payment_id, psp_confirmation_id, network_confirmation_id}`.
- Esquema `checkout_receipt.json`: `{status, iss, iat, reference, order_id}`.
- `reference` es "the hash of the closed Mandate". Se calcula como `sd_hash` (base64url(sha256(ascii del SD-JWT compacto))).

**Mecanismo de extensión.** La sección "Extension Points" de `docs/ap2/specification.md` permite:
- Mandate Constraints con un `type` nuevo;
- Checkout Object;
- Payment Instrument con un `type` nuevo;
- otros formatos VDC.

AP2 viaja sobre A2A con la URI de extensión `https://github.com/google-agentic-commerce/ap2/v1`.

**Punto exacto de inserción.** El recibo de FractalAI es una **contrafirma separada** que liga:
- `sha256(PaymentReceipt JWT)` y `sha256(CheckoutReceipt JWT)`;
- sus `reference` (los hashes de los mandatos cerrados);
- `payment_id`, `psp_confirmation_id`, `network_confirmation_id` y `order_id`;
- `sha256(contenido entregado)`.

Viaja en `Artifact.metadata` de A2A, bajo la URI de extensión de FractalAI. La especificación de "Dispute Evidence" (§"Dispute") ya junta mandato y recibo como evidencia. Nuestra contrafirma añade la pieza que AP2 declara fuera de alcance: **qué se entregó**.

**Valor honesto.** AP2 **ya tiene recibo**, así que nunca debe decirse "AP2 no tiene recibo". Lo que se añade:
1. La ligadura con el contenido entregado; `reference` liga el recibo al mandato, no a lo entregado.
2. Una firma post-cuántica a largo plazo.
3. Un testigo independiente del emisor; el recibo AP2 lo firma la misma parte que cobra.

### 1.2 A2A — Agent2Agent (Linux Foundation)

| | |
|---|---|
| Repositorio | https://github.com/a2aproject/A2A — unas 26 mil estrellas; v1.0.0 (2026-03-12) y v1.0.1 (2026-05-28). La fuente normativa es `specification/a2a.proto` |
| Adopción | `docs/partners.md` lista unas 178 organizaciones. ⚠ Es una lista de anuncios, no de producción. Hay SDKs oficiales, entre ellos uno en .NET mantenido por Microsoft |

**Extensión.**
- Se declara en `AgentCard.capabilities.extensions[]` como `AgentExtension{uri, description, required, params}`.
- Se activa con la cabecera **`A2A-Extensions`**. En v1 ya no lleva el prefijo `X-`.
- `Message.extensions` y `Artifact.extensions` son listas de URIs.
- En v1, `Part` unifica los tipos `text`, `raw`, `url` y `data`, y lleva `metadata` y `media_type`.
- La guía oficial dice: "Extensions should place custom attributes in the `metadata` map".

**Punto exacto.** `Artifact.metadata["<uri-extensión>"]` = el recibo, junto con `Artifact.extensions = [uri]`. El artefacto es justamente lo entregado.

**Recibo propio.** A2A no tiene. Solo existe `AgentCard.signatures[]`, que firma la tarjeta y no la entrega.

**Quién acepta.** Nadie para una URI propia, que funciona sin permiso. Para que sea "oficial" (bajo `https://a2a-protocol.org/extensions/`) hace falta un issue, un mantenedor patrocinador y una votación del TSC.

### 1.3 ACP — Agentic Commerce Protocol (OpenAI + Stripe, ahora con Meta)

| | |
|---|---|
| Repositorio | https://github.com/agentic-commerce-protocol/agentic-commerce-protocol — unas 1,6 mil estrellas; especificaciones fechadas de 2025-09-29 a 2026-04-17. El README dice "beta"; los mantenedores son OpenAI, Stripe y Meta |
| Adopción | El README afirma "first implemented by both OpenAI and Stripe, production-ready". ⚠ La lista de comercios no está verificada |

**Extensión.** `rfcs/rfc.extensions.md`: `capabilities.extensions[]{name, extends[] (JSONPath), schema, spec}`, con nombres en DNS inverso.

**Recibo propio.** No hay recibo criptográfico:
- `OrderConfirmation.receipt_url` es una URL;
- `Order` tiene `additionalProperties:false`;
- las peticiones llevan la cabecera `Signature` y los webhooks un HMAC.

**Punto exacto.** Una extensión `co.net.fractalai.pqc-receipt` con `extends: ["$.Order.pqc_receipt"]`, que llegue en la respuesta de *complete* y en el webhook de la orden.

**Quién acepta.** El proceso SEP de ese repositorio, con CLA.

### 1.4 Visa Intelligent Commerce y Trusted Agent Protocol (TAP)

**VIC:** https://developer.visa.com/capabilities/visa-intelligent-commerce. El estado oficial es "in the process of development and deployment" y hay sandbox. Tiene APIs de tokenización, Payment Instructions, Signals y un servidor MCP.

**TAP:**
- Repositorio https://github.com/visa/trusted-agent-protocol, **sin commits desde el 2025-10-28**.
- Usa RFC 9421 con `tag` igual a `agent-browser-auth` o `agent-payer-auth`.
- Algoritmos Ed25519, PS256 y RS256; claves en `https://mcp.visa.com/.well-known/jwks`.
- Firma la **petición** del agente, no la entrega.

**Punto de inserción.** No hay ninguno público para un tercero. La única vía técnica es una firma RFC 9421 en la **respuesta** del comercio, que queda fuera de TAP. `ml-dsa-65` no está registrado en IANA para HTTP Signatures. **No se construye.**

### 1.5 Mastercard Agent Pay

⚠ Las páginas oficiales devolvieron 403 o llegaron vacías. Lo que sí está confirmado:
- El blog de Cloudflare (https://blog.cloudflare.com/secure-agentic-commerce/) confirma que se basa en Web Bot Auth / RFC 9421 con Ed25519.
- La parte pública verificable es **Verifiable Intent** (https://github.com/agent-intent/verifiable-intent): "Draft v0.1, maintained by Mastercard", una cadena SD-JWT L1–L3 con mapeos a AP2, ACP y UCP. No tiene recibo, y la resolución de disputas queda fuera de su alcance.

**Punto de inserción.** No hay uno oficial. Como mucho, una propuesta de "recibo de cumplimiento" como capa L4 en Verifiable Intent. **No se construye.**

### 1.6 MCP — Model Context Protocol

| | |
|---|---|
| Repositorio | https://github.com/modelcontextprotocol/modelcontextprotocol — **versión vigente `2026-07-28`** (`LATEST_PROTOCOL_VERSION`) |
| Adopción | **La más alta de la lista**: es el estándar de facto de herramientas para LLM |

**Extensión.**
- `_meta` con claves `prefijo-dns-inverso/nombre`, por ejemplo `co.net.fractalai/receipt`. Están reservados los prefijos cuya segunda etiqueta es `modelcontextprotocol` o `mcp`.
- La negociación va en `ClientCapabilities.extensions` y `ServerCapabilities.extensions`.

**Pagos.** No hay ninguno en la especificación:
- SEP-2007 se cerró como "dormant" el 2026-06-24.
- El issue #3393 de x402 se cerró el 2026-09-28.
- La propuesta #3354 de "verifiable tool results" está cerrada. En ese hilo se señaló que **`structuredContent` no está atestiguado** y que el pago de MCP+x402 queda "unattested and malleable".
- De facto, x402 usa `_meta["x402/payment"]` y `_meta["x402/payment-response"]` (`coinbase/x402 specs/transports-v2/mcp.md`).

**Punto exacto.** `CallToolResult._meta["co.net.fractalai/receipt"]`: un recibo que liga `sha256(JCS(structuredContent))` (o el array `content`), el nombre de la herramienta, `sha256(JCS(arguments))` y, si existe, `sha256(JCS(_meta["x402/payment-response"]))`. Responde exactamente al hueco señalado en #3354.

**Quién acepta.** El proceso SEP, que requiere un patrocinador en un Working o Interest Group. No hace falta permiso para usar una clave `_meta` propia.

### 1.7 L402 (Lightning Labs)

- La especificación es bLIP-0026, **PR #26 en https://github.com/lightning/blips, abierto desde junio de 2023 y sin fusionar**.
- Implementación de referencia: https://github.com/lightninglabs/aperture (activa).
- El *preimage* ya es una **prueba de pago criptográfica**. No hay ligadura con la entrega.

**Punto de inserción.** Solo fuera de la especificación: una cabecera o el cuerpo de la respuesta 200. Los *caveats* del macaroon no sirven, porque los pone el emisor o atenuador. **Valor:** medio.

### 1.8 ERC-8004 — Trustless Agents

| | |
|---|---|
| Estado | **Draft** (`ethereum/ERCs`, `ERCS/erc-8004.md`, creado el 2025-08-13). Autores de MetaMask, EF, Google y Coinbase |
| Contratos | https://github.com/erc-8004/erc-8004-contracts — clonado en el commit `b9e466c2` (2026-08-15) |
| Despliegue | IdentityRegistry `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` y ReputationRegistry `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` en unas 25 mainnets. Testnets: `0x8004A818…BD9e` y `0x8004B663…8713`. Se verificó con `eth_getCode` que el Identity de mainnet y el de Base tienen código |
| **Validation Registry** | **Existe como código (`ValidationRegistryUpgradeable.sol`) pero no tiene dirección desplegada en el README oficial.** Su sección dice "still under active update and discussion with the TEE community" |

**Firmas verificadas en el código clonado.**
- `validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)`: solo puede llamarla el dueño u operador del agente.
- `validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)`: solo el validador nombrado; `response` va de 0 a 100 y se puede repetir.
- `getValidationStatus(requestHash) → (validator, agentId, response, responseHash, tag, lastUpdate)`.

**Punto exacto.**
- Hoy (sin Validation Registry desplegado): el JSON de `feedbackURI` de la ReputationRegistry, que ya trae `proofOfPayment{fromAddress, toAddress, chainId, txHash}`, más `feedbackHash`.
- Cuando se despliegue: `validationResponse(requestHash, 100, responseURI → recibo, responseHash = keccak256(bytes del recibo), tag = "fractalai-pqc-receipt/1")`.

**Valor honesto.** El registro solo guarda keccak y ECDSA. El recibo aporta una evidencia post-cuántica, verificable fuera de la cadena, que liga el `requestHash` con el pago y el contenido. `response = 100` significa **"la ligadura se verificó y se firmó"**, no "el trabajo es bueno".

### 1.9 EAS — Ethereum Attestation Service

- Repositorio https://github.com/ethereum-attestation-service/eas-contracts. Está desplegado en unas 15 mainnets.
- En base.easscan.org aparecen unas **3,6 millones de atestaciones** solo en Base.

**Punto exacto.** Un esquema propio, por ejemplo `bytes32 commerceId, bytes32 deliverySha256, bytes32 paymentRef, string receiptURI`, con `refUID` encadenado al pago. No necesita permiso.

**Valor:** medio. La atestación EAS sigue siendo ECDSA; la firma post-cuántica va en el documento referenciado.

### 1.10 Solana Pay

- La especificación está en https://github.com/solana-foundation/pay. Ojo: el repositorio se reorientó a "CLI for Agentic payments (x402, MPP, AP2)".
- La *transfer request* lleva `reference` (32 bytes en base58, buscable con `getSignaturesForAddress`) y `memo`.

**Punto exacto.** `reference = sha256(recibo)`, de modo que el recibo queda **localizable en la cadena**, y `memo` = hash del contenido. La firma ML-DSA, de 3.309 bytes, no cabe en una transacción (límite de 1.232 bytes) y va fuera de la cadena. El kernel ya ancla en Solana con SPL Memo (§7.3).

---

## 2. Rieles instantáneos de LatAm

| Riel | Identificador único | Comprobante oficial y firma | ¿Lo verifica un tercero? | Qué necesita FractalAI | Encaje |
|---|---|---|---|---|---|
| **SPEI** (Banxico) | Clave de rastreo (≤30), más fecha, emisor y receptor | **CEP** en PDF/XML, emitido por Banxico con la información de la institución receptora. Hay validador XML (https://www.banxico.org.mx/validador-cep-spei/) que cubre 45 días hábiles. ⚠ El algoritmo y el certificado de firma no están verificados | **Sí**: https://www.banxico.org.mx/cep/ (con CAPTCHA), por lotes en https://www.banxico.org.mx/cep-scl/ | Datos de consulta que le pase el comercio receptor. Archivar el XML del CEP y ligarlo por hash | **4** |
| **PIX** (BCB) | `endToEndId` `[a-zA-Z0-9]{32}`; `txid` de 26 a 35 (≤25 en QR estático) | Comprobante del PSP (PDF o imagen) **sin firma del BCB**. Solo el payload del QR dinámico es un JWS del PSP receptor | **No**. Solo el receptor consulta `GET /pix/{e2eid}` en su PSP con mTLS y OAuth (https://github.com/bacen/pix-api) | Credenciales **delegadas** del comercio receptor en la API Pix de su PSP. Tener en cuenta MED y devoluciones | **3** |
| **Bre-B** (BanRep) | `TxId` de 35 caracteres (`yyyyMMdd` + NIT + sigla SPBVI + secuencia) y `EndToEndId` (DSP-465, Anexo 6, pacs.008) | "Comprobante descargable" del participante, **sin firma de BanRep** | **No**. DICE y MOL solo son accesibles para SPBVI y participantes; no hay API pública | Alianza con un participante o un SPBVI, o datos del comercio con verificación más débil | **2** |

**Fuentes de Bre-B:**
- Documento técnico de febrero de 2026: https://d1b4gd4m8561gs.cloudfront.net/sites/default/files/publicaciones/archivos/documento-tecnico-bre-b-febrero-2026.pdf. Operación plena desde el 2025-10-06; a enero de 2026, 218 participantes y 370 millones de operaciones.
- Resolución Externa 6 de 2023 de la JDBR: https://d1b4gd4m8561gs.cloudfront.net/sites/default/files/reglamentacion/archivos/bjd_40_2023.pdf
- Circular DSP-465: https://d1b4gd4m8561gs.cloudfront.net/sites/default/files/reglamentacion/archivos/junta-directiva-boletin-28-2024.pdf
- ⚠ Las cifras del primer aniversario salen de un resumen de banrep.gov.co/es/bre-b, no del texto literal: más de 1.000 millones de transacciones y 245 entidades.

**Fuentes de PIX:**
- Reglamento y manuales: https://www.bcb.gov.br/estabilidadefinanceira/pix-normas
- Relatório de Gestão 2023-2025: https://www.bcb.gov.br/content/estabilidadefinanceira/pix/relatorio_de_gestao_pix/relatorio_gestao_pix_2026.pdf. En 2025 hubo unos 80.000 millones de transacciones.

**Fuentes de SPEI y CoDi:**
- CoDi: https://www.banxico.org.mx/sistemas-de-pago/codi-avances-banco-mexico.html
- ⚠ No están verificados los requisitos de participante SPEI (la Circular 14/2017 devolvió 403) ni la fecha de lanzamiento de DiMo.

**Diseño concreto del "recibo de pago instantáneo".** Ver `docs/RECIBO-PAGO-INSTANTANEO-LATAM.md`. Resumen:
- usa el mismo `kind` con perfiles `spei.cep/1`, `pix.e2e/1` y `breb.txid/1`;
- las partes van como **HMAC con clave por comercio**, nunca como hash simple (un hash de un CPF, una CLABE o un celular se revierte por fuerza bruta y sigue siendo dato personal);
- el estado es actualizable, porque MED y las devoluciones pueden revertir un pago;
- FractalAI **no necesita ser participante** para emitir: en SPEI se consulta el CEP público; en PIX hacen falta credenciales delegadas del comercio; en Bre-B hace falta una alianza con un participante o un SPBVI.

---

## 3. Matriz alcance × facilidad × honestidad

Escala de 1 a 5. **Alcance** = adopción real verificable. **Facilidad** = encajar sin permiso ni romper el protocolo. **Honestidad** = si aporta algo que el protocolo no tiene. Puntaje = producto de los tres.

| # | Ecosistema | Alcance | Facilidad | Honestidad | **Puntaje** | Campo exacto | Decisión |
|---|---|---|---|---|---|---|---|
| 1 | **MCP** (`2026-07-28`) | 5 | 5 | 4 | **100** | `CallToolResult._meta["co.net.fractalai/receipt"]` | **CONSTRUIDO** (`src/mcp.ts`) |
| 2 | **A2A v1** | 4 | 5 | 4 | **80** | `Artifact.metadata[URI]` + `Artifact.extensions` + `AgentCard.capabilities.extensions` | **CONSTRUIDO** como transporte de AP2 (`src/a2a.ts`) |
| 3 | EAS | 4 | 5 | 3 | 60 | Esquema propio con `refUID` | Propuesta de esquema (sin construir) |
| 3 | SPEI (CEP) | 5 | 3 | 4 | 60 | Perfil `spei.cep/1` (hash del XML del CEP) | Diseño (`docs/`) |
| 5 | ERC-8004 | 3 | 4 | 4 | **48** | `validationResponse(responseURI, responseHash, tag)` / `feedbackURI` | **CONSTRUIDO** (`src/erc8004.ts`), con e2e contra los contratos oficiales en anvil |
| 5 | ACP | 3 | 4 | 4 | 48 | Extensión `extends:["$.Order.pqc_receipt"]` | Borrador de propuesta |
| 7 | Solana Pay | 3 | 4 | 3 | 36 | `reference = sha256(recibo)` | Nota de diseño (el kernel ya ancla en Solana) |
| 8 | **AP2 v0.2** | 3 | 3 | 3 | **27** | Contrafirma sobre los recibos ES256 + `reference` + entrega, transportada en A2A | **CONSTRUIDO** (`src/ap2.ts`), con fixtures del SDK oficial de AP2 |
| 9 | PIX | 5 | 2 | 3 | 30 | Perfil `pix.e2e/1` | Diseño |
| 10 | Bre-B | 4 | 1 | 3 | 12 | Perfil `breb.txid/1` | Diseño (requiere alianza) |
| 10 | L402 | 2 | 2 | 3 | 12 | Cabecera o cuerpo de la respuesta 200 | No |
| 12 | Visa TAP / VIC | 2 | 1 | 3 | 6 | Ninguno público | No |
| 12 | Mastercard Agent Pay / VI | 2 | 1 | 3 | 6 | Ninguno; propuesta L4 en Verifiable Intent | No |

**Por qué AP2 se construyó con puntaje bajo.** Lo pidió el fundador, y es la puerta a FIDO. Su valor real llega **a través de A2A** (puntaje 80): el adaptador AP2 produce el recibo y el adaptador A2A lo entrega en el `Artifact`.

**ERC-8004.** El Validation Registry aún no tiene dirección oficial. El adaptador funciona contra el contrato oficial compilado desde su repositorio, y ya existe en este monorepo `ERC8004-VALIDATOR-DEPLOY-READY.md` (validador en Solidity, 27 tests).

---

## 4. Resultados de la construcción (2026-10-09)

| Pieza | Ruta | Resultado |
|---|---|---|
| Trust Kernel spec 2.2, `kind` `agent-commerce-receipt` (JS + Python + spec §13 + 44 vectores) | `kernel-patch/0001-kind-agent-commerce-receipt.patch` (base `b51ed02`) | Corpus **217/217 en JS y 217/217 en Python**; los 173 vectores previos no cambian ni un byte |
| AP2 v0.2 + A2A v1 | `src/ap2.ts`, `src/a2a.ts`, `test/ap2-a2a.test.ts` | **9/9**, con fixtures del SDK oficial de AP2 |
| MCP | `src/mcp.ts`, `test/mcp.test.ts` | **5/5** sobre el SDK oficial `@modelcontextprotocol/sdk` 1.32.1 |
| ERC-8004 | `src/erc8004.ts`, `test/erc8004.test.ts` | **5/5** en anvil con los contratos oficiales sin modificar |
| Core | `src/core.ts`, `test/core.test.ts` | **4/4** |
| Interoperabilidad | `scripts/cross-verify-python.ts` | El port Python verifica 2/2 recibos emitidos en TS |
| Ejemplos ejecutables | `examples/*.ts` | Los 3 corren y quedan `accepted: true` |

Nota MCP: el SDK oficial de TypeScript 1.32.1 negocia la versión `2025-11-25`. La especificación vigente es `2026-07-28`. La convención solo usa `_meta`, que funciona igual en ambas.

## 5. Lo que NO se debe afirmar (regla de honestidad)

- "AP2 no tiene recibo" (sí lo tiene, ES256).
- "Pagos cuántico-seguros" (solo el recibo de ligadura es post-cuántico).
- "FractalAI valida la calidad del trabajo" (en ERC-8004, `response = 100` significa que la ligadura se verificó).
- "Integrado con Visa / Mastercard" (no hay punto público).
- "Validador oficial ERC-8004 en mainnet" (no existe un Validation Registry desplegado oficialmente).
- "Producción" para el `kind` `agent-commerce-receipt`: el directorio de producción (época 3) **no tiene clave `commerce-receipt`**. El vector `N-AC-production-directory-has-no-commerce-key` lo comprueba.
- Que el recibo sustituye al CEP o al comprobante del PSP: no lo hace, y no tiene valor legal propio.
