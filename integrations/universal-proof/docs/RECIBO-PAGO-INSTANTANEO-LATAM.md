# Recibo de pago instantáneo (SPEI · PIX · Bre-B) — diseño

**Estado:** diseño. No hay código, porque ningún riel ofrece hoy una API de lectura que FractalAI pueda usar sin un acuerdo previo; ver §4.
**Formato:** el mismo `kind` `agent-commerce-receipt` de la Trust Kernel spec 2.2 §13, de modo que el verificador es el mismo que el de AP2, MCP y ERC-8004.
**Fuentes:** las de `MAPA.md` §2.

## 1. Qué es y qué no es

Es un recibo ML-DSA-65 que liga cuatro cosas: el identificador oficial de una transferencia instantánea ya liquidada, el monto, las partes (seudonimizadas) y el hash del bien o servicio entregado por ese pago.

Sirve para:
1. **Disputas sobre la entrega.** Ningún comprobante oficial liga el pago con lo entregado.
2. **Verificación offline e indefinida.** El validador de CEP solo cubre 45 días hábiles, y los comprobantes de PIX y Bre-B son PDFs sin firma.
3. **Un formato común legible por máquinas** para los tres rieles y para los protocolos de agentes.

No es:
- la liquidación;
- un sustituto del CEP ni del comprobante del PSP;
- una prueba legal;
- "pago cuántico-seguro": el riel y sus comprobantes siguen siendo clásicos.

Además, solo vale lo que valga su fuente. Si FractalAI se limita a firmar lo que le dice el comercio, el recibo dice exactamente eso, y el perfil lo marca con `source=merchant-asserted`.

## 2. Perfiles

Todos usan `protocol` = el riel, `delivery.sha256` = el hash del bien o servicio entregado, y estas reglas comunes:

- **Partes:** `payer_ref` y `payee_ref` = `HMAC-SHA256(k_comercio, identificador)` en hex. El identificador es la CLABE, la llave PIX o Bre-B, el CPF o el NIT. Un hash simple de un CPF, una CLABE o un celular se revierte por fuerza bruta y sigue siendo dato personal (LGPD, Ley 1581, LFPDPPP). Con HMAC, solo quien tiene la clave del comercio puede comprobar a quién corresponde.
- **Monto:** cadena decimal canónica en la unidad de la moneda (`"1999.00"` no; `"1999"` o `"1999.5"`), con `currency` ISO 4217.
- **Fuente:** `source` ∈ `central-bank-document` (CEP), `psp-api` (API Pix del PSP), `participant-webhook` (Bre-B por un participante) o `merchant-asserted`.
- **Reversos:** el recibo es inmutable. Una devolución (MED en PIX, devolución en Bre-B o SPEI) se emite como **otro** recibo con perfil `*.reversal/1` y `bindings.supersedes = <commerce_id original>`. Quien verifica debe buscar si hay reversos (el registro de recibos es una decisión pendiente; ver §5).

### 2.1 `spei.cep/1` — el encaje más fuerte (4/5)

```json
{ "v": "fractalai.agent-commerce/1", "protocol": "spei", "profile": "spei.cep/1", "issued_at": 1791570000,
  "payment": { "clave_rastreo": "MBAN01002610090000123456", "fecha_operacion": "2026-10-09",
               "emisor": "40012", "receptor": "40014", "monto": "1999", "currency": "MXN",
               "source": "central-bank-document" },
  "bindings": { "cep_xml_sha256": "<sha256 del XML del CEP tal como lo sirvió Banxico>",
                "payee_ref": "<hmac>", "payer_ref": "<hmac>", "order_ref": "ord-0001" },
  "delivery": { "sha256": "<sha256 del servicio entregado>", "media_type": "application/json" } }
```

**Cómo se emite.** El comercio receptor (o su fintech) le pasa a FractalAI los datos de consulta del CEP: fecha, clave de rastreo, emisor, receptor, cuenta beneficiaria y monto. FractalAI descarga el CEP en XML del servicio público de Banxico (https://www.banxico.org.mx/cep/), lo valida (https://www.banxico.org.mx/validador-cep-spei/), lo archiva y liga su sha256.

**Cómo se verifica.** Durante 45 días hábiles cualquiera puede volver a descargar el CEP y comparar el hash. Después queda el recibo más el XML archivado.

**Bloqueos:**
- El formulario del CEP tiene CAPTCHA, y hay un servicio por lotes (https://www.banxico.org.mx/cep-scl/). Antes de automatizar hay que **confirmar con Banxico los términos de uso** de la consulta automatizada.
- ⚠ No está verificado qué algoritmo ni qué certificado firma el XML del CEP.

### 2.2 `pix.e2e/1` — encaje medio (3/5)

```json
{ "protocol": "pix", "profile": "pix.e2e/1",
  "payment": { "end_to_end_id": "E00000000202610091200abcdefghijk", "txid": "fractalord0001abcdefghijklmn",
               "valor": "49.90", "currency": "BRL", "horario": "2026-10-09T12:00:03Z", "source": "psp-api" },
  "bindings": { "psp_response_sha256": "<sha256(JCS(respuesta de GET /pix/{e2eid}))>", "payee_ref": "<hmac>",
                "payer_ref": "<hmac>", "psp_ispb": "00000000" },
  "delivery": { "sha256": "…" } }
```

**Cómo se emite.** El comercio receptor delega en FractalAI acceso **de solo lectura** a la API Pix de su PSP: OAuth client-credentials con el alcance de lectura de Pix recibidos, más mTLS (https://github.com/bacen/pix-api). FractalAI consulta `GET /pix/{e2eid}`, comprueba que el `txid` sea el de la cobranza y que el valor y el horario coincidan, y liga el hash de la respuesta.

**Cómo se verifica.** Solo el comercio, con su API, puede volver a consultar. Para un tercero, la confianza está en la clave de FractalAI y en que `source=psp-api` se aplicó como política.

**Riesgo.** El MED puede devolver fondos después de emitido el recibo, así que el perfil exige emitir el reverso.

### 2.3 `breb.txid/1` — encaje débil sin alianza (2/5)

```json
{ "protocol": "bre-b", "profile": "breb.txid/1",
  "payment": { "tx_id": "20261009900123456TFY000000000012345", "end_to_end_id": "…", "monto": "150000",
               "currency": "COP", "source": "participant-webhook" },
  "bindings": { "participant_msg_sha256": "<sha256 del mensaje de confirmación del participante>",
                "payee_ref": "<hmac de la llave Bre-B>", "spbvi": "TFY" },
  "delivery": { "sha256": "…" } }
```

**Cómo se emite.** No hay API pública: DICE y MOL solo son accesibles para SPBVI y participantes (Circular DSP-465). La vía fuerte es una **alianza con un participante o un SPBVI** que le envíe a FractalAI la confirmación del abono, con `TxId` y `EndToEndId` (pacs.008, ISO 20022). Sin esa alianza, solo cabe `source=merchant-asserted`.

## 3. Valor por actor (honesto)

| Actor | Qué gana | Qué no gana |
|---|---|---|
| Comercio o fintech que recibe | Prueba de entrega ligada al pago, portable y verificable offline. Sirve para contracargos, disputas y agentes que compran sin humano | No sustituye la conciliación ni el comprobante oficial |
| Agente comprador (AP2, MCP, A2A) | El mismo recibo, con el mismo verificador, que para pagos en cripto o con tarjeta | No hay garantía de reembolso |
| Regulador o auditor | Evidencia con firma post-cuántica y sello de tiempo anclable en cadena (§7 del kernel) | No es un registro oficial |

## 4. Qué participante o API se necesita (decisiones del fundador)

| Riel | Mínimo para emitir con `source` fuerte | Quién | Licencia de FractalAI |
|---|---|---|---|
| SPEI | Datos de consulta del CEP que le pase el comercio + permiso o términos de Banxico para la consulta automatizada | Un comercio piloto en México | No (no inicia pagos). Contrato de encargado de datos con el comercio |
| PIX | Credenciales delegadas de **solo lectura** de la API Pix del PSP del comercio | Un comercio piloto en Brasil y su PSP | No para leer. Ser ITP requiere autorización del BCB y solo haría falta para *iniciar* pagos |
| Bre-B | Alianza con un participante o un SPBVI (Transfiya, Redeban Entrecuentas, Credibanco, Servibanca, Visionamos) para recibir el webhook de abono | Un participante colombiano | No para recibir confirmaciones. ⚠ El Decreto 0368 de 2026 (finanzas abiertas) no está verificado en fuente primaria |

## 5. Pendientes técnicos (cuando haya piloto)

- Clave de producción con `use = commerce-receipt` publicada por la gobernanza del directorio (época nueva).
- Un registro de recibos por `commerce_id`, para poder buscar reversos. Podría ser un ancla en cadena (`PQCReceiptAnchor`) más un índice.
- Adaptadores `src/spei.ts`, `src/pix.ts` y `src/breb.ts`, con fixtures **reales** de un piloto. Nunca se construirán con datos simulados presentados como reales.
