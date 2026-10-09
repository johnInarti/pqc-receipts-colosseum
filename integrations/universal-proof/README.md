# universal-proof — recibos post-cuánticos de pago ↔ entrega para cualquier protocolo de agentes

Un solo tipo de recibo, `agent-commerce-receipt` (Trust Kernel spec 2.2 §13), ligado a cada protocolo por **perfiles**. Un solo verificador: el Trust Kernel v2 público, con implementaciones en JS y en Python.

- `MAPA.md`: protocolos y rieles, fuentes primarias y la matriz alcance × facilidad × honestidad.
- `kernel-patch/`: el `kind` nuevo (kernel JS, port Python, spec §13 y 44 vectores) sobre `johnInarti/pqc-receipts-colosseum@b51ed02`.
- `src/`: los adaptadores.
  - `ap2.ts`: AP2 v0.2, perfil `ap2.fulfillment/1`.
  - `a2a.ts`: transporte en A2A v1, por `Artifact.metadata`.
  - `mcp.ts`: perfil `mcp.tool-result/1`, en `_meta["co.net.fractalai/receipt"]`.
  - `erc8004.ts`: perfil `erc8004.validation/1`, FractalAI como validador.
- `docs/RECIBO-PAGO-INSTANTANEO-LATAM.md`: diseño para SPEI, PIX y Bre-B.
- `proposals/`: borradores en inglés, uno por ecosistema. **Ninguno se ha enviado.**

**Privado:** no se publica en npm.

## Cómo correrlo

```bash
cd integrations/universal-proof
npm run setup        # clona el kernel público en el commit fijado, aplica el parche, regenera el corpus (verifica sha256 del manifest) → 217/217
npm test             # 23/23 (core 4, AP2+A2A 9, MCP 5, ERC-8004 5; el de ERC-8004 necesita `anvil`)
npm run typecheck    # tsc --noEmit sin errores
node examples/ap2-a2a-fulfillment.ts
node examples/mcp-paid-tool.ts
node examples/erc8004-validator.ts   # requiere anvil (Foundry)
node scripts/cross-verify-python.ts <python con .kernel/python instalado>   # el port Python verifica recibos emitidos en TS
```

Usa Node ≥ 23.6, que ejecuta `.ts` directamente sin paso de compilación.

## Contra qué implementaciones oficiales se probó

| Ecosistema | Implementación de referencia | Cómo |
|---|---|---|
| AP2 v0.2 | `google-agentic-commerce/AP2@e1ea56db` (SDK Python) | `scripts/gen_ap2_fixtures.py` produce un flujo real: mandatos SD-JWT abiertos y cerrados, recibos ES256, auto-verificados con `ReceiptClient.verify_receipt` → `fixtures/ap2/flow-v0.2.json` |
| A2A v1 | `a2aproject/A2A` `specification/a2a.proto` | Forma JSON de `Artifact`, `Part` y `AgentExtension` según el proto (sin SDK) |
| MCP | `@modelcontextprotocol/sdk` 1.32.1 | `Server` + `Client` reales sobre `InMemoryTransport` |
| ERC-8004 | `erc-8004/erc-8004-contracts@b9e466c2` (sin modificar) | Compilado con su configuración, desplegado en anvil detrás de ERC1967Proxy como en su suite oficial |
| Trust Kernel | `johnInarti/pqc-receipts-colosseum@b51ed02` + parche | Corpus 217/217 en JS y en Python; el port Python verifica recibos emitidos por los adaptadores TS (2/2) |

## Qué significa un recibo aceptado (`Decision.accepted`)

Se aceptan solo los recibos que cumplen las dos condiciones:

1. **El kernel lo valida:** la firma ML-DSA-65 es correcta sobre el mensaje reconstruido y la clave está autorizada (`use = commerce-receipt`, ciclo de vida vigente en `issued_at`) por un directorio anclado a raíces fijadas.
2. **El perfil lo valida:** cada `binding` se vuelve a derivar de los artefactos del protocolo que tiene quien verifica (los JWT de AP2, el estado en cadena de ERC-8004, el `CallToolResult` de MCP) y del contenido recibido.

Un recibo aceptado **no** dice que el contenido sea correcto ni que el pago se liquidó. Lo segundo solo lo dice si el perfil lo comprueba contra un artefacto firmado por el riel (por ejemplo, el recibo ES256 de AP2).

## Estado honesto

- **No hay clave de producción con `use = commerce-receipt`.** Los tests usan una PKI de prueba, que el kernel reporta como `trust_basis: "override"`. Con las raíces de producción el recibo da `KEY_NOT_LISTED`, y hay un test que lo comprueba.
- Nada se ha desplegado ni enviado, y no se ha abierto ningún PR. No hay auditoría externa.
