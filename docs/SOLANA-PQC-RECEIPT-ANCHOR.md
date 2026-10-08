# PQC-signed receipts anchored on Solana (SPL Memo)

Estado: **mainnet anclado y verificado el 2026-10-08** — tx
[`cHiTTWYg…Ftw`](https://explorer.solana.com/tx/cHiTTWYgizzjyQAMdF4DyPdF7m6w21wJdgzCwb3G5r1Qy12wyFxi6zjPEHg271nj2tXNNFyMvGHR6S6gjgs6Ftw),
slot 454584215, `finalized`, comisión 5000 lamports; VALID en los cinco niveles con el núcleo JS y el Python (base
`pinned-root`). SOL de comisión adquirido desde la tesorería en Base vía Relay (0,000141 ETH → 0,003 SOL, tx Base
`0x7b2ada29…cab5`). Devnet probado desde el 2026-10-06. Mismo esquema `fractalai.pqc-receipt-anchor/1` y mismos identificadores que el
anclaje EVM de [ARC-PQC-RECEIPT-ANCHOR.md](./ARC-PQC-RECEIPT-ANCHOR.md); aquí no hay contrato: el registro es una
transacción del programa **SPL Memo** firmada por una clave Ed25519 dedicada y anunciada.

## 1. Qué se ancla

El recibo público `fe62b072…` (alerta MIDAS) está firmado con **ML-DSA-65 (FIPS 204)** por la clave `86c139c960bb274c`
(`active` en la época 3 del directorio `https://fractalai.net.co/.well-known/x402-receipt-keys`). El memo es una línea
UTF-8 canónica, sin espacios, hex en minúsculas sin `0x` (203 bytes):

```
fractalai.pqc-receipt-anchor/1|rid=<receipt_id>|ph=<payload_hash>|kid=<kid>|obs=<observed_at>
```

| Campo | Derivación (idéntica a `PQCReceiptAnchor`) | Valor para `fe62b072…` |
|---|---|---|
| `rid` | `sha256(bytes de la firma ML-DSA-65)` | `b9b47ba81d30d95a087ac40b4d7c1c07816148251c147121e7c4aac477cd94eb` |
| `ph` | `sha256(utf8("<served_domain>\n<receipt_id>"))` = bytes exactos firmados | `ef737f1ca8d99fabf58a81373188cc349183bfc8976c1ae3d3861238b498e065` |
| `kid` | `sha256(public_key_b64)[:16 hex]` (8 bytes; en EVM va alineado a la izquierda en un bytes32) | `86c139c960bb274c` |
| `obs` | `emitted_at` del recibo (unix s, declarado por FractalAI) | `1790473960` (2026-09-27 01:52:40 UTC) |

Los cuatro valores coinciden byte a byte con el evento `ReceiptAnchored` de Arc mainnet (lo comprueba un test). El
script **recalcula** el memo desde el recibo público y verifica antes la firma ML-DSA-65 y el estado de la clave; nunca
se copia a mano.

## 2. Límites honestos

- **El programa Memo no verifica nada.** Solo exige que las cuentas listadas firmen y que los datos sean UTF-8. Cualquiera
  puede escribir cualquier memo. El valor del anclaje está en *quién* lo firmó (la clave anunciada abajo) y *cuándo*.
- **ML-DSA-65 se verifica off-chain**, en `verifier/verify-solana-anchor.mjs`, con `@noble/post-quantum`. Solana no
  ejecuta verificación post-cuántica aquí.
- **Lo que prueba:** que la clave anunciada publicó exactamente esos bytes y que la transacción llegó a `finalized` en
  un slot/tiempo dados → *prueba de existencia por tiempo* del recibo (esa firma, esos bytes firmados, ese `kid`) no
  más tarde de ese bloque. `obs` es lo que FractalAI declara; el ancla solo acota por arriba.
- **Lo que no prueba:** que la posición Aave descrita fuera correcta, que la clave Ed25519 sea de FractalAI salvo por
  este anuncio (está fuera del directorio ML-DSA-65; pinéala), ni nada sobre seguridad post-cuántica de Solana (Ed25519
  no es PQC; el ancla es un sello de tiempo, la autenticidad del recibo la da ML-DSA-65).
- **No es único por recibo.** A diferencia del contrato EVM write-once, nada impide anclar el mismo memo dos veces; el
  verificador valida una transacción concreta. El script se niega a re-anclar si ya existe el registro (`--force` para
  forzarlo).
- Devnet se puede reiniciar o podar: el anclaje de devnet es una prueba del mecanismo, no un registro permanente.

## 3. Clave de anclaje anunciada

| Qué | Valor |
|---|---|
| Pubkey Ed25519 "FractalAI Solana anchor" | **`7cpTE4C7sRWsHyeGsiqTfwNv9ntyribrRJV3s8vmN624`** |
| Archivo de clave | `~/.config/fractalai/solana-anchor.json` (formato Solana CLI, `chmod 600`, fuera de todo repo) |
| Uso | Solo anclajes Memo. Sin poder sobre ningún otro activo de FractalAI. |

## 4. Devnet — probado el 2026-10-06

| Qué | Valor |
|---|---|
| Tx de anclaje | `5U5CQn94ix6Unbjk5ixKoRfyqmQ8HiPttwyssmUdoGdyCQzupnvNgKL3znnqN46UWLoWuhYHqaiFyynro6pP3qXi` — https://explorer.solana.com/tx/5U5CQn94ix6Unbjk5ixKoRfyqmQ8HiPttwyssmUdoGdyCQzupnvNgKL3znnqN46UWLoWuhYHqaiFyynro6pP3qXi?cluster=devnet |
| Slot / estado | 508315461 · `finalized` · `meta.err = null` · comisión 5000 lamports |
| Registro | `deployments/anchors/solana-devnet-fe62b072.json` (sello completo + `anchor`) |
| Reproducción desde clon limpio | `67qR1NNy1vP2hLoeqsxpV9twcxNNiktyZ5FPDzx3Z6m9tY4jt4NYYBuqNePHTMk6kRTUtLzGWWQejYjYZqLFWm3V` (slot 508316444, `--force`, mismo memo) → `VALID` |
| Fondeo devnet | 0,00125 SOL de prueba del faucet de devnet de Coinbase CDP (el faucet oficial devolvía 429). Sin fondos reales. |

Negativos ejecutados contra devnet real (todos `INVALID`, exit 1):

| Caso | Entrada | Motivo devuelto |
|---|---|---|
| Memo alterado | tx real `2WQGZ2oawJPzPPVbq31WJUX7KNrYU1zACVBDxahtGGRA6Z2BPCnWxT9n2SqGzUtULhcjYdJqFEnWUudGR6uhUK5Y` (misma clave, `obs` +1) | memo no idéntico byte a byte |
| Otro programa, mismos bytes | tx real `5ne4UnZNMs9xR7B6cPpjiUJVjqHKp92PDQ8bDuQWbiCNcvtmejwpgP4rFEmK3cUZLLFbtjjeAd5LBhapgwGShcT4` (Memo **v1** `Memo1Uhk…`, memo idéntico) | programa no es SPL Memo `MemoSq4g…` |
| Firmante distinto | tx genuina con `--signer` ajeno | firmante ≠ anunciado |
| Recibo alterado | `canonical` con `risk_tier=low` | `content_id != sha256(canonical)` |
| Cluster equivocado | tx de devnet consultada en mainnet-beta | tx no encontrada en `finalized` |

Más 8 tests offline (`verifier/test/solana-anchor.test.mjs`) con transacciones Ed25519 reales y RPC simulado: firma
Ed25519 falsificada, RPC que devuelve otra tx, tx fallida, no finalizada, clave ML-DSA no confiada, etc.

## 5. Mainnet-beta — pendiente de fondeo

Coste por anclaje: **5000 lamports = 0,000005 SOL** (una firma, sin priority fee). Pero una cuenta Solana no puede
existir por debajo del mínimo exento de renta (0,00065024 SOL hoy para una cuenta de 0 bytes) y el pagador no puede
quedar por debajo de él tras la comisión. Por eso: **enviar ≥0,001 SOL** a
`7cpTE4C7sRWsHyeGsiqTfwNv9ntyribrRJV3s8vmN624`. El script aborta si el saldo es <0,0001 SOL o si la comisión dejaría la
cuenta bajo el mínimo; en mainnet nunca pide airdrop.

Comando exacto (desde la raíz del repo, en la máquina que tiene la clave):

```bash
cd verifier && npm install && cd .. && node scripts/anchor-solana-memo.mjs --cluster mainnet-beta
```

Opcional: `--rpc <url>` si el RPC público (`https://api.mainnet-beta.solana.com`) limita peticiones. El script verifica
el recibo, simula, envía, espera `finalized`, se re-verifica contra el RPC como un tercero y escribe
`deployments/anchors/solana-mainnet-beta-fe62b072.json`.

## 6. Verificar sin confiar en FractalAI

```bash
cd verifier && npm install
node verify-solana-anchor.mjs --record ../deployments/anchors/solana-devnet-fe62b072.json
# o sin registro:
node verify-solana-anchor.mjs --sig <firma> --signer 7cpTE4C7sRWsHyeGsiqTfwNv9ntyribrRJV3s8vmN624 \
     --receipt fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee --cluster devnet [--rpc URL]
```

`VALID` (exit 0) solo si, todo a la vez: (1) `receipt_id = sha256(canonical)` y la firma ML-DSA-65 verifica sobre
`served_domain\nreceipt_id`; (2) la clave está `active`/`retiring` en el directorio (`--no-key-pin` lo omite y lo dice);
(3) `getTransaction` en `finalized` devuelve la tx, `meta.err = null` y `getSignatureStatuses` dice `finalized`;
(4) el verificador parsea los bytes crudos y comprueba **él mismo** la firma Ed25519 (no se fía del RPC), que la primera
firma es la pedida y que el pagador es la pubkey anunciada; (5) exactamente una instrucción, al programa
`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`, con el firmante entre sus cuentas y datos idénticos byte a byte al memo
recalculado. Cualquier otra cosa → `INVALID` con motivo. Sin SDK de Solana: base58, formato de transacción y Ed25519
(`node:crypto`) están en `verifier/src/solana-anchor.mjs` (~300 líneas auditables).

## Trust Kernel v2 (2026-10-07)

La verificación de este documento la decide ahora `kernel/` (especificación normativa: `spec/TRUST-KERNEL.md`,
corpus adversarial: `corpus/`). Cambios relevantes: el contrato de anclaje se fija por `chainId → (dirección, code
hash)` en `kernel/trust-roots.json` (una dirección traída por el sello se rechaza); la hora sale de la cabecera del
bloque y `observedAt` debe ser igual a la hora FIRMADA; Solana exige génesis del cluster, `finalized` + `blockTime`,
firmante anunciado y un único Memo v2 idéntico byte a byte; las redes de prueba quedan marcadas `test` y no cuentan
como prueba de tiempo salvo `allowTestnetAnchors`; el ciclo de vida de la clave se evalúa en la hora firmada y una
clave revocada solo vale con un anclaje anterior a `revoked_at`. Protocolo anti-squatting "anclar antes de publicar":
spec §10. Límites (RPC/consenso, raíces fijadas por TOFU, sin auditoría externa, librería no CMVP): spec §11.
