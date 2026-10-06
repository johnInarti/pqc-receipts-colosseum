# MIDAS Rescue V2 — rescate automático opt-in de posiciones Aave V3 en Base

**Estado (2026-10-02, tarde): CONTRATO DESPLEGADO EN BASE, UI CONSTRUIDA, KEEPER AÚN NO CONFIRMADO EN VIVO.** `MidasRescueVaultV2` está en Base en `0x654117c020BAD98Ce5c80C49BF318eF087E5D37C` (`smart-contracts/deployments/MidasRescueVaultV2-8453.json`, tx `0x6e5b57cc…2094`). Leído on-chain el 2026-10-02: `isKeeper(0x0f5a545F83581D1f0ad99Aaa6e6B8FA536AACceE) = true`, `rescueFeeWfrac = 50 wFRAC`, `paused = false`, `cooldownBlocks = 1800`, `minPostHfBps = 10500`, `guardianCount = 0`, saldo del keeper **0,0012 ETH** (por debajo del umbral "low gas" de 0,002 ETH de `/api/midas/ops`). Lo que NO está verificado desde el repo: si el droplet ya tiene `MIDAS_RESCUE_VAULT_V2_ADDRESS` y la clave del keeper (sin ellas el módulo del cron está `disabled`/`dry-run` y **no hay rescate automático**). La UI (sección 9) lee ese modo de `GET /api/midas/ops` y lo muestra tal cual: ACTIVE solo si el servidor dice `live`. V1 (`0x54b1Cfff86595Fb2450F5448Ee91A0F6a6D06403`) sigue siendo el autoservicio.

## 1. Qué problema resuelve

V1 salva una posición solo si el dueño está despierto, en la página, con la wallet conectada, en el minuto justo. Las alertas firmadas (`docs/MIDAS-SIGNED-ALERTS.md`) le avisan, pero el "y ahora qué" sigue siendo manual. V2 añade un **guardián**: el usuario declara ON-CHAIN, una vez, "si mi HF baja de X, repagad hasta Y de esta deuda con este colateral", y un *keeper* autorizado ejecuta ese mismo flujo atómico de V1 cuando toca. El keeper paga el gas; el usuario paga la fee en wFRAC (igual que en V1).

## 2. Diseño

### 2.1 Contrato `smart-contracts/contracts/MidasRescueVaultV2.sol`

Hereda `FlashLoanSimpleReceiverBase` + `Ownable2Step` y conserva TODOS los fixes de auditoría de V1 ([C1][C2][H1][H2][H3][M1][M2][L1][L2][V1][V2][V3]). Es un **superconjunto** de V1: `rescueMyPosition(...)` sigue existiendo con la misma semántica, así el frontend puede migrar a una sola dirección.

**Opt-in del usuario**

```
enableGuardian(debtAsset, rateMode, collateralAsset, swapFee, maxSlippageBps,
               triggerHfBps, maxRepayPerRescue, expiresAt)
disableGuardian()
```

- La política se guarda por usuario (`guardianOf(user)`), y el usuario queda enumerado (`guardianCount()`, `guardiansPage(offset, limit)`) para que el keeper lo encuentre sin escanear logs.
- Validación igual que V1 (rate mode 1/2, slippage 50–1000 bps, tier Uniswap 500/3000/10000 si hay swap) + `triggerHfBps ∈ [10 000, 30 000]` (1.00–3.00), `maxRepayPerRescue > 0`, `expiresAt` futuro y ≤ 365 días.
- **La fee queda congelada al opt-in** (`acceptedFeeWfrac = rescueFeeWfrac` del momento). Si el owner sube la fee después, a esa política se le cobra `min(actual, aceptada)`. Una subida de fee nunca se cobra a quien no la aceptó.
- `disableGuardian()` funciona siempre, incluso en pausa. Los approvals (aToken + wFRAC) NO se tocan: el usuario los revoca en su wallet si también quiere cortar el autoservicio.
- El owner puede `adminDisableGuardian(user)` (respuesta a abuso / keeper comprometido). **No existe `adminEnableGuardian`**: el opt-in es solo del usuario.

**Ejecución por keeper**

```
rescueFor(victim, repayAmount)   // onlyKeeper · nonReentrant · whenNotPaused
```

El contrato **nunca confía en el keeper**. El keeper solo elige *cuándo* y *cuánto* (≤ tope); todo lo demás sale de la política. Orden de comprobaciones on-chain:

1. `isKeeper[msg.sender]` (set por owner con `setKeeper(addr, bool)`).
2. Política `enabled`, `block.timestamp < expiresAt`, `0 < repayAmount ≤ maxRepayPerRescue`.
3. Cooldown por usuario: `block.number ≥ lastRescueBlock[victim] + cooldownBlocks`.
4. Tope global: como máximo `maxRescuesPerBlock` rescates de keeper por bloque.
5. **Disparo**: `Pool.getUserAccountData(victim).healthFactor < triggerHfBps · 1e14` (estricto). Sin deuda, Aave devuelve `type(uint256).max` → nunca dispara. Si la llamada al Pool falla, revierte (no adivina).
6. `flashLoanSimple` → `executeOperation` (repago en nombre del usuario → pull de aTokens → `withdraw` → swap `exactOutputSingle` si cross-asset → fee wFRAC 50 % quema / 50 % tesorería → devolución del préstamo → sobrantes al usuario). Idéntico a V1.
7. **Post-check**: `hfAfter > hfBefore` (el rescate tiene que haber ayudado) **y** `hfAfter ≥ minPostHfBps · 1e14`. Si no, revierte TODO (los aTokens y la fee vuelven al estado inicial; el keeper solo pierde gas).

`previewRescueFor(victim, repayAmount) view → (ok, reason, hf)` reproduce los pasos 2–5 y 7-pre sin necesitar ser keeper: devuelve el **mismo string de revert** que usaría `rescueFor`. Es lo que usa el keeper en dry-run.

**Eventos**: `GuardianEnabled`, `GuardianDisabled(user, by)`, `KeeperUpdated`, `GuardianLimitsUpdated`, y `RescueExecuted(victim, executor, debtAsset, repayAmount, flashPremium, collateralAsset, collateralWithdrawn, surplusReturned, wfracBurned, wfracToTreasury, sameAsset, hfBefore, hfAfter)` — `executor` es la víctima (autoservicio) o el keeper.

**Límites configurables por owner** (`setGuardianLimits`): `cooldownBlocks ≤ 302 400` (~7 días), `maxRescuesPerBlock > 0`, `minPostHfBps ∈ [10 000, 30 000]`.

### 2.2 Keeper fuera de cadena `frontend/lib/midas-rescue-keeper.ts`

Funciones puras (probadas con jest): `selectCandidates` (cruza el feed `prometheus_midas_atRisk` —solo filas de Base— con las políticas activas y no vencidas, HF del feed < trigger propio, peor HF primero), `planRepayAmount` (deuda actual + 0,1 % + 1, con tope en `maxRepayPerRescue`; sin lectura → tope), `resolveMode`, `describeRevert`, `encodeRescueFor`.

`runKeeperPass(feed, deps)` — una pasada, nunca lanza, todo acaba en el resumen:

| Variable de entorno | Efecto |
|---|---|
| `MIDAS_RESCUE_VAULT_V2_ADDRESS` ausente | `mode: 'disabled'` (V2 no desplegado). No toca el RPC. |
| Vault presente, sin `MIDAS_RESCUE_KEEPER_PRIVATE_KEY` | `mode: 'dry-run'`: lee guardianes, `previewRescueFor`, y si hay `MIDAS_RESCUE_KEEPER_ADDRESS` simula el calldata exacto con `eth_call` desde esa dirección. **No envía nada.** |
| Clave presente | `mode: 'live'`: solo envía si preview `ok` **y** la simulación `eth_call` desde la dirección del keeper pasa. Máximo `DEFAULT_MAX_RESCUES_PER_PASS = 3` envíos por pasada. |
| `MIDAS_RESCUE_KEEPER_DRY_RUN=1` | Fuerza dry-run aunque haya clave. |
| `MIDAS_RESCUE_BASE_RPC` | RPC de Base (default: `X402_BASE_RPC` / `BASE_RPC_URL` / `https://mainnet.base.org`). |

Enganchado al final de `GET /api/rpa/midas-alerts` (cron cada ~10 min, gated por `x-cron-secret`) como `rescue_keeper: {...}` en el JSON de resumen. El lector de deuda usa el `ProtocolDataProvider` de Aave en Base (`0xd82a…53Ad`).

## 3. Riesgos (lo que hay que tener claro antes de activar)

- **Gas del keeper.** Cada `rescueFor` que llega a la cadena y revierte (otro liquidador llegó antes, el precio se movió, el usuario revocó el approval) cuesta gas al keeper, no al usuario. La simulación previa reduce esto pero no lo elimina (el estado cambia entre `eth_call` y minado). Presupuestar ~0,01 ETH iniciales y vigilar el saldo.
- **Latencia del feed.** El nodo reescanea Base cada ~20 s y el cron corre cada ~10 min: una caída brusca puede liquidar al usuario antes de que el keeper actúe. **V2 reduce la ventana; no la cierra.** Para cerrarla haría falta un keeper que lea `getUserAccountData` por bloque (fuera del alcance de esta pieza).
- **MEV / front-running.** La tx del keeper es pública en el mempool de Base (secuenciador centralizado, sin mempool público abierto hoy, pero no es garantía). Un liquidador que vea la posición antes puede liquidarla; el `rescueFor` entonces revierte en el paso 5 o 7 (sin pérdida para el usuario, gas para el keeper).
- **Slippage.** El swap cross-asset usa `maxSlippageBps` de la política como tope de colateral extra a gastar; el usuario fija ese tope al opt-in. Si el pool Uniswap está ilíquido, `exactOutputSingle` revierte → el rescate completo revierte.
- **Prima del flash loan sobre exceso.** Si `repayAmount` supera la deuda real, el exceso de principal vuelve al usuario ([V1]) pero la prima (0,05 %) sobre ese exceso la paga el colateral del usuario. El keeper lee la deuda real antes para ajustar; sin lectura, usa el tope.
- **Fee por rescate.** Cada rescate cobra `acceptedFeeWfrac`. Un keeper malicioso no puede inventar rescates (el HF se lee on-chain), pero mientras el HF esté bajo el trigger podría repetir cada `cooldownBlocks`. El usuario limita la exposición total **aprobando exactamente N × fee en wFRAC** (no `MaxUint256`), igual que la UI de V1 aprueba justo la fee.
- **Keeper comprometido.** Daño máximo: gastar su propio gas y forzar rescates válidos (que mejoran el HF del usuario) dentro de cooldown/tope. Mitigación: `setKeeper(addr, false)` + `setPaused(true)` + `adminDisableGuardian`.
- **Owner.** Puede pausar, cambiar límites (acotados), fee (acotada a 10 000 wFRAC y congelada por política) y tesorería. No puede activar guardianes ni retirar wFRAC (`emergencyWithdraw` lo prohíbe, [H1]).

## 4. Qué NO promete

- No garantiza evitar la liquidación. Es *best effort* acotado por latencia del feed, gas, liquidez y competencia de liquidadores.
- No actúa sin opt-in on-chain del usuario y sin sus approvals (aToken + wFRAC). La política sola no mueve nada.
- No cubre otras cadenas: solo Base (donde vive el vault). Las alertas sí cubren 6 cadenas.
- No es un oráculo de HF verificado por consenso: el contrato lee `Pool.getUserAccountData` de Aave; el feed del nodo es solo un prefiltro.
- No hay "capa cuántica" en este contrato: es Solidity estándar (OZ 5 + Aave core-v3). La parte PQC de MIDAS está en las alertas firmadas ML-DSA-65, no aquí.

## 5. Pruebas (ejecutadas 2026-10-02 en el worktree, sin red)

- `cd smart-contracts && npx hardhat test test/MidasRescueVaultV2.test.js test/MidasRescueVault.test.js` → **106 passing** (53 V2 nuevas + 53 V1 intactas). Mocks: `contracts/mocks/MockAaveV3Guardian.sol` (`MockAavePoolGuardian` con `getUserAccountData` configurable antes/después del repago, `MockKeeperBatch` para probar el tope por bloque en una sola tx) + los mocks existentes de V1.
- `cd frontend && npx jest __tests__/midas-rescue-keeper.test.ts` → **18 passed**.

## 6. Pasos de despliegue (para el fundador o VISION — NINGUNO ejecutado por el agente)

Prerrequisitos: llave del fundador con ≥ 0,002 ETH en Base, `BASESCAN_KEY`, y haber aprobado los parámetros de la sección 7.

1. **Compilar**
   ```bash
   cd smart-contracts && npm ci && npx hardhat compile && npx hardhat test test/MidasRescueVaultV2.test.js
   ```
2. **Desplegar en Base** (parámetros por env, defaults = sección 7):
   ```bash
   PRIVATE_KEY=<llave fundador> BASESCAN_KEY=<key> \
   V2_FEE_WFRAC=50 V2_COOLDOWN_BLOCKS=1800 V2_MAX_PER_BLOCK=3 V2_MIN_POST_HF_BPS=10500 \
   V2_KEEPER_ADDRESS=<dirección del keeper, opcional> \
   npx hardhat run scripts/deploy-midas-rescue-vault-v2.js --network base
   ```
   El script aborta si `chainId ≠ 8453`, guarda `deployments/MidasRescueVaultV2-8453.json` y actualiza `deployments/addresses.json`.
3. **`setKeeper`** (si no se pasó `V2_KEEPER_ADDRESS`): desde la llave del fundador, `vault.setKeeper(<keeper>, true)`. Usar una wallet NUEVA solo para esto (no la tesorería `0xC137…`), fondearla con ~0,01 ETH.
4. **Verificar en Basescan**: el script llama a `verify:verify`; si falla, `npx hardhat verify --network base <address> <los 8 argumentos del constructor>`. Comprobar en `https://basescan.org/address/<address>#code` que el código coincide y que `owner()` es el fundador.
5. **Dry-run en producción** (droplet, systemd env del frontend): `MIDAS_RESCUE_VAULT_V2_ADDRESS=<address>` y `MIDAS_RESCUE_KEEPER_ADDRESS=<keeper>`. Sin clave. Observar `rescue_keeper` en la salida del cron `/api/rpa/midas-alerts` al menos un ciclo con guardianes reales: `mode: 'dry-run'`, `preview_ok`, `simulated`.
6. **Live**: añadir `MIDAS_RESCUE_KEEPER_PRIVATE_KEY` por stdin heredoc (nunca argv, ver [[fix-deploy-ci-gate-secretos-argv-2026-09-24]]). Opcional: `MIDAS_RESCUE_KEEPER_DRY_RUN=1` como freno de emergencia sin borrar la clave.
7. **Frontend — HECHO 2026-10-02** (`frontend/app/midas/rescue/GuardianSection.tsx`, montado bajo el rescate manual en `/midas/rescue`): bloque "Guardian — automatic rescue" apuntando a `MIDAS_RESCUE_VAULT_V2_BASE` (`frontend/lib/midas-rescue-keeper.ts`). Flujo del usuario en la sección 9.
8. **Rollback**: `setPaused(true)` detiene rescates (keeper y autoservicio); `setKeeper(addr, false)` corta solo el keeper; quitar `MIDAS_RESCUE_VAULT_V2_ADDRESS` apaga el módulo del cron.

## 7. Decisiones que debe aprobar el fundador antes de desplegar

| Parámetro | Propuesta | Alternativas / razón |
|---|---|---|
| Fee por rescate | **50 wFRAC** (paridad V1) | 0 wFRAC las primeras semanas como en el lanzamiento de V1. Congelada por política al opt-in. |
| `cooldownBlocks` | **1 800** (~1 h) | 300 (~10 min) si se quiere permitir rescates parciales encadenados; 7 200 (~4 h) si se prefiere limitar fees. |
| `maxRescuesPerBlock` | **3** | Tope global anti-ráfaga. Con 0 clientes hoy, 3 sobra. |
| `minPostHfBps` | **10 500** (1.05) | 11 000 (1.10) es más conservador pero hará revertir rescates pequeños. |
| Rango de trigger | 1.00–3.00 (constante) | Cambiarlo exige redeploy. |
| Duración máx. política | 365 días (constante) | Ídem. |
| Keeper | Wallet nueva dedicada, ~0,01 ETH | ¿Quién custodia la clave: droplet (systemd env) o GitHub Actions secret? Recomendación: droplet, mismo patrón que `PROMETHEUS_ADMIN_TOKEN`. |
| Envíos por pasada | 3 (`DEFAULT_MAX_RESCUES_PER_PASS`) | Constante en el keeper; subir si hay muchos guardianes. |
| V1 | Mantener desplegado | V2 es superconjunto; migrar la UI cuando V2 esté verificado. |

## 8. Archivos

- `frontend/app/midas/rescue/GuardianSection.tsx` — bloque Guardian (UI + firmas del usuario; sin claves).
- `frontend/lib/midas-rescue-guardian-ui.ts` — lógica pura de la UI (validación, tope de aTokens, HF↔bps, gauge, estado del keeper).
- `frontend/lib/midas-rescue-chain.ts` — plumbing de Base compartido por el formulario V1 y el Guardian (extraído de `page.tsx`, sin cambio de comportamiento).
- `frontend/__tests__/midas-rescue-guardian-ui.test.ts` — 28 pruebas.
- `frontend/app/api/midas/ops/route.ts` — expone `rescue_keeper` (modo del keeper según env del servidor + `isKeeper`/`paused`/gas leídos on-chain).
- `smart-contracts/contracts/MidasRescueVaultV2.sol` — contrato.
- `smart-contracts/contracts/mocks/MockAaveV3Guardian.sol` — mocks nuevos (Pool con HF, keeper-contrato).
- `smart-contracts/test/MidasRescueVaultV2.test.js` — 53 pruebas.
- `smart-contracts/scripts/deploy-midas-rescue-vault-v2.js` — despliegue (no ejecutado).
- `frontend/lib/midas-rescue-keeper.ts` — keeper (puro + `runKeeperPass`).
- `frontend/__tests__/midas-rescue-keeper.test.ts` — 18 pruebas.
- `frontend/app/api/rpa/midas-alerts/route.ts` — enganche `rescue_keeper` (dry-run por defecto, `disabled` sin dirección).

## 9. Flujo del usuario en `/midas/rescue` → bloque "Guardian — automatic rescue"

Todo lo firma el usuario con su wallet (MetaMask/Coinbase Wallet vía `window.ethereum`, misma conexión que el rescate manual). No hay claves en el frontend. La dirección del vault V2 sale de `MIDAS_RESCUE_VAULT_V2_BASE` y la del keeper de `MIDAS_RESCUE_KEEPER_BASE` (`frontend/lib/midas-rescue-keeper.ts`).

**Lecturas (RPC público de Base, sin wallet):** `guardianOf(wallet)`, `rescueFeeWfrac()`, `paused()`, `cooldownBlocks()`, `minPostHfBps()`, `isKeeper(keeper)`; reservas Aave del usuario (`ProtocolDataProvider`), aToken del colateral, precios del oráculo Aave (vía `PoolAddressesProvider.getPriceOracle()`, el mismo que usa el vault), allowances aToken/wFRAC hacia V2. Auto-chequeo del selector: `eth_call` de `enableGuardian` con `rateMode = 3` debe revertir con el `"Invalid rate mode"` del propio contrato; hasta entonces la firma queda bloqueada.

**Estado del keeper:** `GET /api/midas/ops` devuelve `rescue_keeper: { mode: 'disabled'|'dry-run'|'live', reason, keeper, keeper_authorized_onchain, keeper_eth, low_gas, vault_paused }` calculado con el MISMO `resolveMode(process.env)` del cron (nunca expone la clave). Si el endpoint no responde, la UI cae a `NEXT_PUBLIC_MIDAS_RESCUE_KEEPER_LIVE` (default: "Simulation"). Pill del hero: **ACTIVE** (política on-chain + keeper `live`), **SIMULATION** (política on-chain pero keeper dry-run/off), **INACTIVE**, **PAUSED**, **EXPIRED**.

**Activación (stepper 1 Configure → 2 Approvals → 3 Activate):**

1. *Configure.* Deuda a repagar y colateral (preseleccionados desde la posición real en Base), rate mode fijo en variable (2), tier Uniswap 500/3000/10000 (solo si hay swap), slippage (default 200 bps), **trigger HF** (slider 1.00–3.00 + input numérico + marcas 1.05/1.15/1.30; default 1.15), **cap por rescate** en unidades del activo de deuda (default 50 % de la deuda actual; atajos 25/50/75/deuda completa), **duración** (default 90 días, máx 365; muestra fecha absoluta y relativa), **N rescates cubiertos** por los approvals (default 3, 1–20) y la **fee** leída de `rescueFeeWfrac()` con la nota de que se congela al activar. Validación en vivo con los mismos rangos que `enableGuardian` (`validateGuardianForm`). Nada se firma aquí. "Review approvals" relee precios, fee y allowances on-chain y construye el plan.
2. *Approvals.* Tabla "Before you sign" con lo que concede cada tx:
   - `aToken.approve(V2, cap)` con `cap = min(saldo aToken, N × ceil(collateralToPull × stress))`. `collateralToPull` se calcula como en `executeOperation` (`amountOwed = cap + prima flash`; mismo activo → `× (1 + slippage)`; cross-asset → conversión por oráculo con decimales `× (1 + slippage)`). `stress = HF actual / 1.00` (acotado a 1×–3×, solo cross-asset): el colateral necesario escala con 1/HF, así que un tope a precios de hoy sería corto justo cuando dispara. **Nunca `MaxUint256`.**
   - `wFRAC.approve(V2, N × fee)`.
   - Resumen de `enableGuardian(...)` y de lo que podrá hacer el keeper (solo mientras HF on-chain < trigger, máx. una vez por `cooldownBlocks`, hasta la expiración, dejando HF mayor y ≥ `minPostHfBps`).
   Cada approve se simula con `staticCall` desde la dirección del usuario antes de abrir la wallet; si la allowance ya cubre el objetivo se marca "Skipped". Filas de tx con estado pending/confirmed/failed, hash abreviado + copiar + enlace a basescan.org (`aria-live`).
3. *Activate.* `enableGuardian(debtAsset, 2, collateralAsset, swapFee, slippageBps, triggerHfBps, maxRepayPerRescue, expiresAt)` — relee `paused()` y `rescueFeeWfrac()` (aborta si la fee cambió desde la revisión), `staticCall`, `estimateGas` +20 %, envío, espera 1 confirmación y recarga `guardianOf`. `expiresAt` se recalcula en el momento del envío para que nunca quede en el pasado.

**Tarjeta "Your guardian" (política activa):** trigger vs HF actual, expiración (relativa + absoluta), cap por rescate, colateral/swap, fee congelada (y cuántos rescates cubre el saldo wFRAC), **rescates restantes por approvals** (`min(allowance wFRAC / fee, min(allowance aToken, saldo) / pull estimado)`) con alerta si alguno está agotado, avisos si la política expiró, el vault está en pausa, el keeper no está autorizado o el keeper no está `live`. Botón discreto **Disable** → `disableGuardian()` (simulado y enviado; los approvals NO se tocan, se revocan desde la wallet).

**Texto honesto integrado (en inglés, como la página):** el trigger es on-chain; la ventana de liquidación se reduce (~20 s de feed + ~10 min de bucle) pero no se elimina; el usuario paga la fee en wFRAC y el keeper el gas; sin approvals vigentes el rescate revierte; "best-effort … not guaranteed protection".

**Pruebas:** `cd frontend && npx tsc --noEmit -p tsconfig.json` → 0 errores · `npx jest __tests__/midas-rescue-guardian-ui.test.ts __tests__/midas-rescue-keeper.test.ts` → 46 passed (28 nuevas).
