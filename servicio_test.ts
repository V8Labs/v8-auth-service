/**
 * Banco de pruebas de `v8-auth-service`.
 *
 *     deno test --allow-none servicio_test.ts
 *
 * Los casos que importan NO son "¿acepta un token bueno?". Son los cuatro que ya
 * costaron caro en este ecosistema:
 *   · una base caída NO puede leerse como credencial inválida (01-sep)
 *   · el scope lo decide la fila, no el que llama (el defecto de roadmap-api)
 *   · un token revocado deja de valer YA, sin esperar expiración
 *   · el telemetry no puede tumbar la autorización
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  acunar,
  hashear,
  ServicioIndeterminado,
  verificarServicio,
  verificarToken,
  type Almacen,
  type FilaToken,
} from "./servicio.ts";

/** Un almacén de mentira. `modo` fuerza los fallos que importan. */
function almacenCon(filas: FilaToken[], modo: "ok" | "tira" = "ok"): Almacen & { usos: string[] } {
  const usos: string[] = [];
  return {
    usos,
    buscar: (id) => {
      if (modo === "tira") return Promise.reject(new Error("connection timeout"));
      return Promise.resolve(filas.find((f) => f.id === id) ?? null);
    },
    marcarUso: (id) => { usos.push(id); return Promise.resolve(); },
  };
}

async function filaDe(agente: string, scopes: string[], secreto: string, activo = true) {
  return { id: "abc123XYZ", agente, hash: await hashear(secreto), scopes, activo };
}

const SCOPE = "contactos:escribir";

// ── Lo que tiene que pasar ───────────────────────────────────────────────────

Deno.test("token bueno con el scope exigido → verificado, y trae el agente", async () => {
  const alm = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")]);
  const r = await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, alm);
  assertEquals(r.estado, "verificado");
  if (r.estado === "verificado") {
    assertEquals(r.agente, "whatsapp");   // el autor que hay que estampar
    assertEquals(r.tokenId, "abc123XYZ");
  }
});

Deno.test("acunar produce un token que su propio hash valida", async () => {
  const t = await acunar("whatsapp", [SCOPE]);
  const alm = almacenCon([{ id: t.id, agente: t.agente, hash: t.hash, scopes: t.scopes, activo: true }]);
  const r = await verificarToken(t.token, SCOPE, alm);
  assertEquals(r.estado, "verificado");
});

Deno.test("dos acuñaciones nunca dan el mismo secreto", async () => {
  const a = await acunar("x", []); const b = await acunar("x", []);
  assert(a.secreto !== b.secreto && a.id !== b.id);
});

// ── ⭐ EL CASO DEL 01-SEP: la base caída NO es una credencial inválida ────────

Deno.test("la base no contesta → ServicioIndeterminado, NUNCA rechazado", async () => {
  const alm = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")], "tira");
  await assertRejects(
    () => verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, alm),
    ServicioIndeterminado,
  );
  // Si esto devolviera `rechazado`, el consumidor emitiría 401 y el agente
  // concluiría que su token murió — el error que costó dos días de POS.
});

// ── ⭐ EL SCOPE LO DECIDE LA FILA, NO EL QUE LLAMA ───────────────────────────

Deno.test("token válido SIN el scope exigido → sin_alcance (403), no verificado", async () => {
  const alm = almacenCon([await filaDe("whatsapp", ["identidades:escribir"], "s3cr3to")]);
  const r = await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, alm);
  assertEquals(r.estado, "sin_alcance");
  if (r.estado === "sin_alcance") assertEquals(r.exigido, SCOPE);
});

Deno.test("el mismo token pasa para el scope que SÍ tiene", async () => {
  const alm = almacenCon([await filaDe("whatsapp", ["identidades:escribir"], "s3cr3to")]);
  const r = await verificarToken("v8svc_abc123XYZ_s3cr3to", "identidades:escribir", alm);
  assertEquals(r.estado, "verificado");
});

Deno.test("scopes vacíos no pasan nada (default cerrado)", async () => {
  const alm = almacenCon([await filaDe("whatsapp", [], "s3cr3to")]);
  const r = await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, alm);
  assertEquals(r.estado, "sin_alcance");
});

Deno.test("no hay comodín: 'contactos:*' NO habilita 'contactos:escribir'", async () => {
  // Explícito por diseño. Un comodín se escribe una vez y se olvida qué abrió.
  const alm = almacenCon([await filaDe("whatsapp", ["contactos:*"], "s3cr3to")]);
  const r = await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, alm);
  assertEquals(r.estado, "sin_alcance");
});

// ── ⭐ REVOCACIÓN INMEDIATA ──────────────────────────────────────────────────

Deno.test("token revocado (activo=false) → rechazado en la llamada siguiente", async () => {
  const alm = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to", false)]);
  const r = await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, alm);
  assertEquals(r.estado, "rechazado");
  if (r.estado === "rechazado") assertEquals(r.motivo, "revocado");
});

// ── Rechazos ────────────────────────────────────────────────────────────────

Deno.test("id inexistente → rechazado/desconocido", async () => {
  const alm = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")]);
  const r = await verificarToken("v8svc_noExiste9_s3cr3to", SCOPE, alm);
  assertEquals(r.estado, "rechazado");
});

Deno.test("secreto incorrecto → rechazado, aunque el id exista", async () => {
  const alm = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")]);
  const r = await verificarToken("v8svc_abc123XYZ_otroSecreto", SCOPE, alm);
  assertEquals(r.estado, "rechazado");
  if (r.estado === "rechazado") assertEquals(r.motivo, "secreto_invalido");
});

Deno.test("formas malformadas → sin_credencial, no rechazado", async () => {
  const alm = almacenCon([]);
  for (const malo of ["", "   ", "v8svc_", "v8svc_abc", "v8svc__secreto", "otracosa", "v8svc_ab!c_x"]) {
    const r = await verificarToken(malo, SCOPE, alm);
    assertEquals(r.estado, "sin_credencial", `debía ser sin_credencial: ${JSON.stringify(malo)}`);
  }
});

// ── El Request ──────────────────────────────────────────────────────────────

Deno.test("lo lee del Authorization: Bearer", async () => {
  const alm = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")]);
  const req = new Request("https://x.co", { headers: { Authorization: "Bearer v8svc_abc123XYZ_s3cr3to" } });
  assertEquals((await verificarServicio(req, SCOPE, alm)).estado, "verificado");
});

Deno.test("lo lee de X-V8-Service-Token", async () => {
  const alm = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")]);
  const req = new Request("https://x.co", { headers: { "X-V8-Service-Token": "v8svc_abc123XYZ_s3cr3to" } });
  assertEquals((await verificarServicio(req, SCOPE, alm)).estado, "verificado");
});

Deno.test("⭐ un Bearer de SESIÓN DE PERSONA → sin_credencial, no rechazado", async () => {
  // Si esto devolviera `rechazado`, un operador legítimo recibiría "credencial de
  // servicio inválida" — un mensaje que no le dice nada y lo manda a ningún lado.
  // Esa la verifica v8-auth-jwt; acá simplemente no es nuestra.
  const alm = almacenCon([]);
  const req = new Request("https://x.co", { headers: { Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def" } });
  assertEquals((await verificarServicio(req, SCOPE, alm)).estado, "sin_credencial");
});

Deno.test("sin header → sin_credencial", async () => {
  assertEquals((await verificarServicio(new Request("https://x.co"), SCOPE, almacenCon([]))).estado, "sin_credencial");
});

// ── El telemetry no manda ───────────────────────────────────────────────────

Deno.test("marcarUso se llama SOLO cuando se verificó", async () => {
  const alm = almacenCon([await filaDe("whatsapp", ["otro:scope"], "s3cr3to")]);
  await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, alm);
  assertEquals(alm.usos.length, 0, "sin_alcance no debe contar como uso");
  const ok = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")]);
  await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, ok);
  assertEquals(ok.usos, ["abc123XYZ"]);
});

Deno.test("⭐ si marcarUso TIRA, la verificación sobrevive", async () => {
  const base = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")]);
  const alm: Almacen = { buscar: base.buscar, marcarUso: () => Promise.reject(new Error("read-only replica")) };
  const r = await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, alm);
  assertEquals(r.estado, "verificado", "un dato de conveniencia no puede tumbar la autorización");
});

Deno.test("un almacén SIN marcarUso funciona igual (es opcional)", async () => {
  const base = almacenCon([await filaDe("whatsapp", [SCOPE], "s3cr3to")]);
  const r = await verificarToken("v8svc_abc123XYZ_s3cr3to", SCOPE, { buscar: base.buscar });
  assertEquals(r.estado, "verificado");
});

// ── El camino de `mirror`: la base verifica, el hash nunca sale ──────────────

const UUID = "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607";

Deno.test("⭐ id UUID: mi regex original lo habría rechazado y ningún token real habría entrado", async () => {
  // `mirror` hizo el id un uuid al aplicar la tabla. La versión original de
  // `partir` exigía alfanumérico puro — habría dado sin_credencial SIEMPRE.
  const alm: Almacen = { verificarEnServidor: () => Promise.resolve({ agente: "whatsapp" }) };
  const r = await verificarToken(`v8svc_${UUID}_s3cr3to`, SCOPE, alm);
  assertEquals(r.estado, "verificado");
  if (r.estado === "verificado") assertEquals(r.tokenId, UUID);
});

Deno.test("verificarEnServidor null → rechazado (sin_alcance colapsa acá, y está documentado)", async () => {
  const alm: Almacen = { verificarEnServidor: () => Promise.resolve(null) };
  assertEquals((await verificarToken(`v8svc_${UUID}_x`, SCOPE, alm)).estado, "rechazado");
});

Deno.test("⭐ si el RPC TIRA → indeterminado, nunca rechazado", async () => {
  const alm: Almacen = { verificarEnServidor: () => Promise.reject(new Error("connection timeout")) };
  await assertRejects(() => verificarToken(`v8svc_${UUID}_x`, SCOPE, alm), ServicioIndeterminado);
});

Deno.test("verificarEnServidor gana sobre buscar cuando están los dos", async () => {
  let usoBuscar = false;
  const alm: Almacen = {
    verificarEnServidor: () => Promise.resolve({ agente: "porRpc" }),
    buscar: () => { usoBuscar = true; return Promise.resolve(null); },
  };
  const r = await verificarToken(`v8svc_${UUID}_x`, SCOPE, alm);
  assertEquals(r.estado === "verificado" && r.agente, "porRpc");
  assertEquals(usoBuscar, false, "el hash no debe salir de la base si hay RPC");
});

Deno.test("un almacén sin ningún camino → indeterminado, no un falso rechazo", async () => {
  await assertRejects(() => verificarToken(`v8svc_${UUID}_x`, SCOPE, {}), ServicioIndeterminado);
});

// ── La corrida: procedencia DECLARADA, no identidad verificada ───────────────

Deno.test("⭐ la corrida viaja del header al resultado (para poder deshacer un lote)", async () => {
  const alm: Almacen = { verificarEnServidor: () => Promise.resolve({ agente: "whatsapp" }) };
  const req = new Request("https://x.co", {
    headers: { Authorization: `Bearer v8svc_${UUID}_s`, "X-V8-Run-Id": "carga-2026-09-02-a" },
  });
  const r = await verificarServicio(req, SCOPE, alm);
  assertEquals(r.estado === "verificado" && r.corrida, "carga-2026-09-02-a");
});

Deno.test("sin header de corrida, no se inventa ninguna", async () => {
  const alm: Almacen = { verificarEnServidor: () => Promise.resolve({ agente: "whatsapp" }) };
  const req = new Request("https://x.co", { headers: { Authorization: `Bearer v8svc_${UUID}_s` } });
  const r = await verificarServicio(req, SCOPE, alm);
  assertEquals(r.estado === "verificado" && r.corrida, undefined);
});

Deno.test("una corrida basura se descarta — se va a estampar en una base", async () => {
  const alm: Almacen = { verificarEnServidor: () => Promise.resolve({ agente: "whatsapp" }) };
  for (const mala of ["con espacios", "'; drop--", "x".repeat(65), "acentós"]) {
    const req = new Request("https://x.co", {
      headers: { Authorization: `Bearer v8svc_${UUID}_s`, "X-V8-Run-Id": mala },
    });
    const r = await verificarServicio(req, SCOPE, alm);
    assertEquals(r.estado === "verificado" && r.corrida, undefined, `debía descartarse: ${mala}`);
  }
});

Deno.test("la corrida NO altera la autorización (es procedencia, no permiso)", async () => {
  const alm: Almacen = { verificarEnServidor: () => Promise.resolve(null) };
  const req = new Request("https://x.co", {
    headers: { Authorization: `Bearer v8svc_${UUID}_s`, "X-V8-Run-Id": "la-que-sea" },
  });
  assertEquals((await verificarServicio(req, SCOPE, alm)).estado, "rechazado");
});

Deno.test("⭐ acunar emite un id UUID — la tabla lo exige y rechazaría cualquier otro", async () => {
  const t = await acunar("whatsapp", ["contactos:escribir"]);
  assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(t.id), `no es uuid: ${t.id}`);
  assert(t.token.startsWith(`v8svc_${t.id}_`));
});
