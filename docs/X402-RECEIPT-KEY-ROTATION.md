# Rotación de la clave de recibos x402 (directorio firmado por épocas)

Estado al 2026-09-27 01:32 UTC: **época 2 ACTIVA** (run 36285810168; raíz `16e916f4…`; verificada desde fuera: `verifyDirectory` con gobernanza pineada + `expectedPrevRoot` = raíz de la época 1 → válida; watchtower sin alertas; recibo pagado posterior verificado con la clave nueva). npm publicados el 2026-09-27 03:55 UTC (aprobados por el fundador vía staging): `x402-pqc-witness` 0.1.3, `agent-passport-mcp` 0.2.4, `pqc-agent-receipts-conformance` 0.3.1. Pendiente: purgar `x402-receipt-seed.conf.epoch1.bak-20260927T013158Z` tras el soak.

## Qué se rota y qué no

| Clave | Dónde vive | Rota aquí |
|---|---|---|
| Clave de recibos ML-DSA-65 (firma `served proofs`, recibos, sello del witness) | `X402_RECEIPT_SEED` en `/etc/systemd/system/fractal-frontend.service.d/x402-receipt-seed.conf` (600) | **Sí** (época 2) |
| Clave de gobernanza del directorio | `FRACTAL_KEY_DIRECTORY_SEED` en `/etc/fractal/frontend.env` | **No** — nunca en la misma época que la clave de recibos (el watchtower lo marca HIGH) |
| Clave del validador del nodo (keystore) | `/opt/fractal/data-green/validator-keystore.json` | No — raíz de confianza distinta (ver `fractal-node keystore rotate`, solo contraseña) |

Los seeds **nunca salen del servidor**. Lo único que viaja es material público.

## Piezas

- **Ledger congelado**: `frontend/lib/key-directory-epochs.ts` — época 1 (raíz `a97d9bdb…`, clave `7cf9d6316ba6c628`) y época 2 (`prev_root` = esa raíz; claves `7cf9…` *retiring* hasta `overlap_until` = +90 días, `86c139c960bb274c` *active*). Misma clave de gobernanza (`8005759019a101f6`).
- **Ruta** `/.well-known/x402-receipt-keys`: renderiza la época que indica `FRACTAL_KEY_DIRECTORY_EPOCH` (por defecto 1) y firma con la gobernanza en runtime. Comprueba el proceso vivo contra el ledger y publica `warnings[]` si la clave que firma o la gobernanza no son las del ledger — nunca publica en silencio un directorio que el servidor no usa.
- **Tests**: `frontend/__tests__/key-directory-epoch.test.ts` (ledger + ruta), `integrations/pqc-agent-receipts-conformance/src/key-directory-live.test.mjs` (fixture real de la época 1, firma ML-DSA-65 real).
- **Consumidores con pin (aceptan cualquiera de las dos claves; nunca la que cita el recibo)**: `@fractalai/x402-pqc-witness` 0.1.3 (`notary.mjs`), `@fractalai/agent-passport-mcp` 0.2.4 (`pinnedMlDsa65Pubkeys()`), `enterprise-trial/verify-receipt.mjs`, `demos/all-things-agentic/fractalai/passport.py`. Además JWKS/`/api/x402/receipt-key` publican la clave en retiro con `status`/`not_after` desde la época 2.

## Procedimiento

1. `frontend-receipt-key-epoch2-prepare.yml` — genera `X402_RECEIPT_SEED_NEXT` en el servidor (si falta) e imprime SOLO la clave pública. Hecho el 2026-09-27 (run 36284485947). Idempotente.
2. Congelar la pública en el ledger + pines de consumidores → desplegar frontend (**hecho en este cambio**). Todavía sirve época 1.
3. **(hecho 2026-09-27)** Publicar en npm las versiones con ambos pines. Nota operativa: los tokens de npm que saltan 2FA ya solo permiten `npm stage publish`; la versión queda en staging y el dueño de la cuenta la aprueba en npmjs.com (o `npm stage approve <id>` con sesión). En esta cuenta no hay authenticator, así que ese es el camino.
4. **(hecho 2026-09-27 01:32 UTC)** `frontend-receipt-key-epoch2-activate.yml` con `confirm = ACTIVAR EPOCA 2` — verifica precondiciones (seed NEXT deriva el kid congelado, build desplegado contiene el ledger, gobernanza intacta), cambia el drop-in (respaldo `.epoch1.bak-<ts>`), reinicia, verifica en vivo con firma real y **hace rollback solo** si algo no cuadra.
5. Soak 24–48 h: `verifyDirectory(live, { governanceKey, expectedPrevRoot: EPOCH1_ROOT })` desde una máquina externa; prueba reina semanal (8/8, recibos verificados con el pin nuevo).
6. Purgar `x402-receipt-seed.conf.epoch1.bak-*` (contiene el seed viejo) con el mismo patrón que `node-secrets-purge-old-backups.yml`. La clave 1 sigue **listada** (solo-añadir) hasta `overlap_until`; en la época 3 pasa a `revoked` sin borrarse.

## Invariantes (los hace cumplir el paquete de conformance; el ledger los prueba)

- `kid = sha256(public_key_b64)[:16]`, jamás reasignado.
- `keys[]` solo-añadir entre épocas.
- `prev_root(n) == root(n-1)` exacto.
- Una sola clave `active` por época.
- La época 1 conserva su forma histórica exacta (sin campos de ciclo de vida) para que su raíz congelada recompute.

## Lo que NO afirma

El ancla on-chain del directorio sigue `tls-only` (`FractalCheckpoint` no lleva aún `keyDirectoryRoot`): la equivocación es detectable dada la clave de gobernanza pineada, no "trustless-of-TLS". `@noble/post-quantum` implementa el algoritmo FIPS 204; no es un módulo validado CMVP.

## Trust Kernel v2 (2026-10-07)

La verificación de este documento la decide ahora `kernel/` (especificación normativa: `spec/TRUST-KERNEL.md`,
corpus adversarial: `corpus/`). Cambios relevantes: el contrato de anclaje se fija por `chainId → (dirección, code
hash)` en `kernel/trust-roots.json` (una dirección traída por el sello se rechaza); la hora sale de la cabecera del
bloque y `observedAt` debe ser igual a la hora FIRMADA; Solana exige génesis del cluster, `finalized` + `blockTime`,
firmante anunciado y un único Memo v2 idéntico byte a byte; las redes de prueba quedan marcadas `test` y no cuentan
como prueba de tiempo salvo `allowTestnetAnchors`; el ciclo de vida de la clave se evalúa en la hora firmada y una
clave revocada solo vale con un anclaje anterior a `revoked_at`. Protocolo anti-squatting "anclar antes de publicar":
spec §10. Límites (RPC/consenso, raíces fijadas por TOFU, sin auditoría externa, librería no CMVP): spec §11.
