# FRC-55R — Proof-Born Assets (activos nacidos de prueba)

Estándar de tokenización de FractalAI para albergar los MVPs de KPITAPP SAS y
cualquier activo, producto o servicio real. **Todo en Rust, todo PQC, en consenso.**
Solidity (`WrappedTokenFactory` + `FractalCheckpoint`) es un espejo, nunca la fuente.

## Ley

> Un token vale exactamente lo que vale su prueba. El mint no lo ordena nadie:
> lo dispara la evidencia, firmada con ML-DSA por atestadores independientes.

Cada activo declara un `proof_level` inmutable y **nunca afirma más de lo probado**:

| `proof_level` | Significado | Política de mint permitida |
|---|---|---|
| `self_declared` | El creador lo dice. Nada independiente fue verificado. | `threshold = 0` (solo el creador) |
| `third_party_attested` | N-de-M atestadores con claves ML-DSA distintas firmaron la evidencia de cada mint. | `threshold ≥ 1` |
| `on_chain_reserve_verified` | Atestado y además la reserva es verificable on-chain. | `threshold ≥ 1` |

Declarar `third_party_attested` con `threshold = 0` es **rechazado en forma** (`validate_shape`).

## Tipos de activo

| `kind` | Qué es | Reglas |
|---|---|---|
| `fungible` | Unidades divisibles (commodities, créditos, participaciones) | — |
| `non_fungible` | Exactamente UNA unidad indivisible — **el pasaporte de un MVP**, una escritura, una licencia | `decimals = 0`, `max_supply = 1` |
| `service` | Capacidad consumible: N llamadas / N horas / N entregas | Se **quema** con `ServiceRedeem`, cada quema ancla un `receipt_hash` (p. ej. un settlement x402) |
| `governance` | Unidades de gobernanza de un venture | **Exige `parent_asset`** = pasaporte del MVP que gobierna; el validador comprueba que exista |

## Modelo KPITAPP

```
MVP (p. ej. HagalIA)  ──►  pasaporte  = non_fungible, max_supply 1, creador = KPITAPP
                            │
                            ├──►  gHAGALIA  = governance, parent_asset = pasaporte, 2-de-3 ML-DSA
                            └──►  ATTEST100 = service,   parent_asset = pasaporte, quemable vía x402
```

Un pasaporte por MVP vivo; el token de gobernanza y los cupones de servicio cuelgan de él.
Así el ecosistema es navegable on-chain: de cualquier token se llega a la identidad PQC de su venture.

## Transacciones (consenso, `core/src/transaction.rs`)

| Tipo | Discriminante | Autoridad | Efecto |
|---|---|---|---|
| `AssetCreate` | 11 | Firma ML-DSA del sobre (`from` = creador) | Ancla la declaración. **No crea supply.** |
| `AssetMint` | 12 | Sobre + bundle N-de-M de atestaciones ML-DSA sobre `signing_bytes()` | Nace supply hacia `to` |
| `AssetTransfer` | 13 | Sobre (`from` = tenedor) | Mueve unidades |
| `ServiceRedeem` | 14 | Sobre (`from` = tenedor) | Quema unidades de un `service` y ancla el recibo |

* `asset_id = SHA3("fractalai-asset-v1|id|" ‖ creator ‖ name ‖ "|" ‖ symbol)` — determinista; el duplicado se rechaza, nunca se sobreescribe.
* `AssetMint` lleva la declaración completa; el validador exige `declaration_hash()` igual al anclado en `AssetCreate` (la política no se puede debilitar a posteriori).
* Freshness kill-switch: `proof_ttl_secs` — evidencia más vieja que el TTL no mintea, la firme quien la firme. `issued_at` va en **segundos**; el bloque guarda milisegundos (`BlockCtx::timestamp_secs`). Tolerancia de reloj: 300 s.
* Aritmética `checked_*` en todo; `overflow-checks = true` también en release.

## Estado (dónde vive y qué cubre `state_root`)

Cada activo tiene una **cuenta de sistema** `asset_account(asset_id)`.
Su `AccountState.storage_root` es el **ledger head**: `R_n = SHA3(DOMAIN ‖ R_{n-1} ‖ block.parent_hash ‖ H(op))`,
escrito con `set_account` → entra en `state_root`. Balances, supply, kind, parent y contador de ops van en
slots `set_storage` de la misma cuenta. Ninguna regla depende de un índice local del nodo.

## Activación (disciplina de fork)

`ASSET_TX_ACTIVATION_HEIGHT` — default `u64::MAX` = **inerte**. Antes de la altura: la tx se rechaza en
admisión RPC y, si entrara en un bloque, falla sin gas, sin nonce, sin estado. Un nodo anterior a este
código no decodifica bloques con estos tipos → la activación es un upgrade coordinado (como el cut-over
Dilithium-3). Devnet/testnet: `ASSET_TX_ACTIVATION_HEIGHT=1`.

## RPC

* Escritura: `eth_sendRawTransaction` con `transaction.type ∈ {asset_create, asset_mint, asset_transfer, service_redeem}` y `data = 0x` + hex(bincode(params)). Firma sobre `Transaction::signing_bytes()` (canónico `fractalai-tx-v1`).
* Lectura: `fractal_assetActivation`, `fractal_assetGet [asset_id]`, `fractal_assetBalance [asset_id, holder]`.

## CLI (`fractal-wallet asset …`)

```bash
W="fractal-wallet --rpc-url https://api.fractalai.net.co --chain-id 1"
$W asset activation
$W asset template passport   > hagalia.json      # editar name/symbol/metadata_hash
$W asset declare hagalia.json --from kpitapp     # → asset id (AssetCreate)
$W asset template mint       > mint.json         # asset_id, declaración EXACTA, to, amount, evidence_hash, issued_at
$W asset attest mint.json --name auditor   --out att1.json   # cada atestador, offline
$W asset attest mint.json --name custodian --out att2.json
$W asset mint mint.json -a att1.json -a att2.json --from kpitapp   # AssetMint N-de-M
$W asset transfer --asset 0x… --to fractal1_pq_… --amount 400 --from holder
$W asset redeem   --asset 0x… --units 3 --receipt 0x<sha3 del settlement x402> --from holder
$W asset get 0x… ; $W asset balance 0x… fractal1_pq_…
```

`asset pubkey --name auditor` imprime la clave que se lista en `attesters`. Una atestación hecha sobre otro
`issued_at`/`amount`/declaración se detecta antes de enviar (`signed_bytes_sha3`).

## Rondas de financiación — FRC-55R/F (pieza 4)

**Capital que solo se libera cuando la realidad lo prueba.** El escrow es una cuenta de sistema
`offer_account(offer_id)`: su balance nativo es la custodia (auditable con `eth_getBalance`), su
`storage_root` el ledger de la ronda.

| Tipo | Disc. | Autoridad | Efecto |
|---|---|---|---|
| `AssetOffer` | 15 | Creador del activo **+ aprobación N-de-M de la política de mint del activo** sobre los términos | Ancla `offer_hash`; abre la ronda |
| `AssetSubscribe` | 16 | Sobre del inversor. Leg `Native`: `value = units × price_native` → va al escrow. Leg `Attested`: recibo de liquidación (USDC/FUSD en Base) firmado por los `settlement_attesters` (clave de recibos de FractalPay, `/.well-known/x402-receipt-keys`), `settlement_ref` de un solo uso | Mintea las unidades al inversor **al instante**; el dinero queda en custodia |
| `EscrowRelease` | 17 | Cualquiera lo lleva; manda la atestación N-de-M del **gate** (`tranches[i].attesters`) sobre `evidence_hash` | Tras `closes_at`, en orden A→B→…, antes del `deadline`: mueve `share_bps` del nativo al tesoro y autoriza la misma proporción del atestado para el espejo en Base |
| `EscrowRefund` | 18 | Sobre del inversor | Solo si algún gate venció sin prueba (ronda **muerta**, sin más liberaciones): devuelve la fracción no liberada de lo pagado; para legs atestados registra la autorización de reembolso |

Reglas de forma: `tranches` suman exactamente 10 000 bps, deadlines no decrecientes y posteriores a
`closes_at`, cada gate con sus atestadores (agentes con pasaporte FRC-55, auditor, builder) y umbral.
Los tokens entregados **no se queman** al reembolsar: representan el gate que sí se financió.

RPC de lectura: `fractal_offerGet [offer_id, n_gates]`, `fractal_offerPosition [offer_id, subscriber]`,
`fractal_offerList [asset_id]`. Desde 2026-09-28 (opción B) los **términos de cada tramo se anclan
on-chain** al abrir la ronda (`offer.gates.n`, `offer.gate.label[i]`, `offer.gate.share[i]`,
`offer.gate.deadline[i]`): `OfferView.terms_anchored`, `OfferView.tranches` (n real) y
`GateView.{gate, share_bps, deadline}` — la letra KPITECH (0=A Problem-Solution Fit, 1=B MVP, 2=C Beta,
3=D PMF, 4=E Scale) se lee de la cadena sin el JSON del emisor. Precios, monedas y atestadores siguen
solo hash-vinculados (`offer_hash`; `offerHash(p)` en el SDK). Rondas ancladas antes: `terms_anchored:false`,
`gate:null` y `n_gates` sigue acotando las filas. CLI: `asset round-approve` → `round-open` (escribe `<offer>.bound.json`,
los términos exactos que todos deben llevar) → `subscribe` → `gate-attest` / `gate-release` → `refund`
→ `round-get` / `round-position` / `round-list`.

Prueba en vivo: `cargo test -p fractal-node --test asset_round_live` (≈160 s, reloj real): ronda sin
aprobación rechazada, extraño no puede abrir, valor incorrecto, cap excedido, recibo con clave ajena,
recibo reutilizado, liberación con ronda abierta, gate B antes de A, 1 sola firma, reembolso sin
vencimiento, doble liberación, evidencia tardía — todo rechazado; liberación 40 % y reembolso 60 % exactos.

## Proyecciones con calibración verificable — FRC-55R/P (pieza 5)

**La "predictibilidad" no es una rentabilidad prometida: es el historial de aciertos del venture,
puntuado por consenso.**

| Tipo | Disc. | Autoridad | Efecto |
|---|---|---|---|
| `ForecastPublish` | 19 | Creador del activo | Ancla ANTES de la fecha: `metric`, `predicted`, `tolerance_bps`, `resolve_at`, `grace_secs`, `resolvers` (ML-DSA) + `threshold`, `rationale_hash`. Inmutable. |
| `ForecastResolve` | 20 | Cualquiera lo lleva; mandan las atestaciones N-de-M de los `resolvers` sobre `realized` + `evidence_hash` (fechadas ≥ `resolve_at`) | **hit** si `|realized − predicted| ≤ predicted × tolerance`, si no **miss**. Pasado `resolve_at + grace_secs` sin resolver → **expired** (la evasión cuenta como fallo). |

Contadores por venture en la cuenta del activo (`published`, `resolved`, `hits`, `expired`);
`fractal_ventureCalibration [asset]` devuelve `hit_rate` y `p_value_vs_coin` = P(X ≥ hits | n, ½) con el
binomial exacto de MIDAS (`decision_ledger::binom_p_ge`). Sin resoluciones no hay puntuación: no se inventa nada.
Lecturas: `fractal_forecastGet`, `fractal_forecastList`. CLI: `asset forecast-publish | forecast-attest |
forecast-resolve | forecast-list | calibration`.

Prueba en vivo: `cargo test -p fractal-node --test venture_forecast_live` (≈110 s): extraño publicando,
fecha en el pasado, resolver antes de tiempo, evidencia anterior a la fecha, resolver ajeno, 1 sola firma,
proyección manipulada (tolerancia ensanchada a posteriori), doble resolución — rechazados; hit, miss y
expiración puntuados; calibración 1/3 con p = 0,875 exacto.

## Bono de venture — FRC-55R/B (pieza 4b): el builder cobra por prueba, en su token

KPITAPP cobra en **KPICoin** (Governance, hijo del pasaporte KPITAPP) y **solo por resultado**:

| Tipo | Disc. | Autoridad | Efecto |
|---|---|---|---|
| `VentureBond` | 21 | **Creador** del pasaporte (emisor, p. ej. KPITAPP) **o tenedor de su unidad** (el fundador al que se le minteó), que posee las unidades del bono | Mueve `amount` de `bond_asset` (p. ej. KPICoin) del fundador a la **cuenta del pasaporte del MVP**. Nadie cobra aún. Un bono por venture. |
| `VentureBondSettle` | 22 | Cualquiera lo lleva | Antes del `deadline` y con atestación N-de-M de `attesters` → unidades al `beneficiary` (tesorería del builder). Después del `deadline` → `on_expiry`: `ReturnToFounder` o `Burn` (las atestaciones tardías no valen). |

Modelo de tenencia: el pasaporte lo **emite** el builder (creator = KPITAPP) y lo **controla** el fundador (la unidad única se mintea a su wallet; transferible). La cadena no codifica a ningún builder: `beneficiary` y `attesters` se declaran por bono, así cualquier venture
builder del mundo puede usar la misma regla. Lectura: `fractal_bondGet [venture_id]` → `posted | released |
returned | burned`. Prueba en vivo `venture_bond_live.rs` (≈110 s): KPITAPP → KPICoin 2-de-3 → 3 MVPs; MVP 1
liberado a tesorería por prueba, MVP 2 devuelto al fundador, MVP 3 quemado (supply baja); sabotajes: extraño,
saldo insuficiente, doble bono, clave ajena, 1 firma, términos manipulados, doble liquidación.

## Gobernanza — FRC-55R/G (pieza 8): un token de gobernanza que gobierna de verdad

El **tesoro DAO** de un activo Governance (p. ej. KPICoin) es **su propia cuenta de sistema**
(`asset_account(gov_asset)`): cualquiera lo fondea con un `AssetTransfer`; **solo una propuesta aprobada
lo vacía**. Los votos **bloquean** unidades en la cuenta de la propuesta (una unidad, un voto; sin
snapshots que confiar, sin doble voto) y se recuperan tras finalizar.

| Tipo | Disc. | Autoridad | Efecto |
|---|---|---|---|
| `GovProposal` | 23 | Tenedor del activo Governance (bloquea `proposer_bond`) | Ancla la propuesta: `actions` (`Anchor`, `TreasuryTransfer`, `TreasuryBurn`), ventana, `quorum_bps` (sobre el supply en la creación), `pass_bps` |
| `GovVote` | 24 | Tenedor (mueve `units` a la cuenta de la propuesta) | Suma FOR/AGAINST; un voto por dirección |
| `GovFinalize` | 25 | Cualquiera, tras `voting_ends` | **passed** (acciones ejecutadas atómicamente), **rejected** (quórum/umbral), **failed** (aprobada pero infactible → nada se ejecuta, nunca a medias); devuelve el bono al proponente |
| `GovReclaim` | 26 | Cada votante, tras finalizar | Recupera sus unidades bloqueadas |

Lectura: `fractal_govProposalList [gov_asset]` (incluye cuenta y saldo del tesoro DAO), `fractal_govProposalGet`,
`fractal_govVoteGet [proposal, voter]`. CLI: `asset gov-propose | gov-vote | gov-finalize | gov-reclaim | gov-list | gov-get`.
Prueba en vivo `asset_gov_live.rs` (≈105 s): grant de 300 KPICoin aprobado y ejecutado, propuesta sin quórum
rechazada, propuesta infactible fallida sin mover nada, supply conservado; sabotajes: activo no-Governance,
proponente sin unidades, voto antes de la ventana, doble voto, no tenedor, finalizar/reclamar en curso, doble finalización.

## Pruebas

* `cargo test -p fractal-core` — forma, ids, firma/tamper de atestaciones.
* `cargo test -p fractal-node --test asset_tx_live` — nodo real + minero real: gate, pasaporte, gobernanza 2-de-3, 7 sabotajes, transfer, redeem, ledger head.
* `cargo test -p fractal-wallet` — el CLI firma exactamente lo que el nodo verifica.

## Pendiente

Espejo EVM (`WrappedTokenFactory` contra `FractalCheckpoint` + prueba Merkle; el puente aún no entrega),
oráculo Chainlink para AURUM, registro de ventures (un pasaporte por MVP vivo de KPITAPP).
