/**
 * v8-auth-service — identidad NO HUMANA para el ecosistema V8.
 *
 * Hermano de `v8-auth-jwt` (que verifica la sesión de una PERSONA) y de
 * `v8-auth-session` (el llavero del navegador). Misma frase de gobierno:
 *
 *     «Mecanismo, no política: distingue "no vale" de "no pude verificar".»
 *
 * ── POR QUÉ EXISTE ────────────────────────────────────────────────────────────
 * `contactos-api` y `identidades-api` exigen un Bearer de sesión de un OPERADOR
 * logueado en XO. Es deliberado, no un olvido — pero deja al ecosistema sin
 * ningún camino para que un AGENTE escriba en el padrón de personas. El caso que
 * lo destapó: 2.034 contactos de la agenda de Andy, ya reconciliados por
 * `whatsapp`. Ningún agente puede cargarlos, y un humano tampoco: son 2.034
 * submits a mano.
 *
 * Andy aprobó un token de servicio **acotado a esas dos escrituras**, y esta
 * librería es ese mecanismo, definido UNA vez para que dos APIs no improvisen
 * cada una el suyo.
 *
 * ── TRES DECISIONES QUE VALE LA PENA ENTENDER ANTES DE TOCAR ESTO ─────────────
 *
 * ⭐ 1. EL TOKEN ES OPACO Y SE VERIFICA CONTRA UNA FILA. NO es un JWT firmado.
 *
 * Un JWT era mi primer instinto: más elegante, sin ida a la base. Y por eso mismo
 * **no se puede revocar** — vale hasta que expira, haga lo que haga quien lo
 * emitió. Con `jwt_exp = 28800` en este proyecto, revocar significaría *"deja de
 * valer en algún momento de las próximas 8 horas"*.
 *
 * Para una credencial que escribe en el padrón de PERSONAS, eso no alcanza. Una
 * fila se apaga con un `update` y surte efecto en la llamada siguiente.
 *
 * El costo es una lectura indexada por invocación. Esto es carga masiva, no
 * camino caliente: se paga sin despeinarse.
 *
 * ⭐ 2. EL ALCANCE LO DECLARA EL QUE RECIBE, NUNCA EL QUE LLAMA.
 *
 *     const svc = await verificarServicio(req, "contactos:escribir", { sql });
 *
 * La función que atiende declara qué scope exige; el verificador lo compara
 * contra la fila. **El llamador solo presenta un token — lo que ese token puede
 * hacer no lo decide él.**
 *
 * ⚠ Esto es exactamente lo que hoy hace mal `roadmap-api`: su `X-Agent-Token` es
 * COMPARTIDO y el campo `agent` lo escribe quien llama. Su propio contrato lo
 * admite: *"la identidad nunca estuvo enforced"*. No se repite ese diseño.
 *
 * ⭐ 3. SIN AUTOR NO HAY ESCRITURA.
 *
 * `verificado` trae `agente`, y el consumidor DEBE estamparlo como autor. Andy
 * aprobó el token; no aprobó perder el registro de quién escribió qué. Una carga
 * de 2.034 contactos sin autor es justo lo que después no se puede desarmar.
 */

/** El resultado de verificar una credencial de servicio.
 *
 *  Deliberadamente **la misma forma** que `Verificacion` de `v8-auth-jwt`: si un
 *  consumidor ya aprendió a ramificar por `estado` para personas, no aprende una
 *  segunda gramática para agentes. */
export type VerificacionServicio =
  /** No vino credencial de servicio, o no tiene la forma. Nada que reintentar. */
  | { estado: "sin_credencial" }
  /** El token existe pero NO vale: revocado, inexistente, o secreto incorrecto. */
  | { estado: "rechazado"; motivo: "desconocido" | "revocado" | "secreto_invalido" }
  /** El token vale, pero NO tiene el scope exigido. Es 403, no 401: la credencial
   *  es buena, lo que falta es el permiso. Mandarlo a re-autenticarse no arregla
   *  nada — es la misma familia que el `sin_email` TERMINAL de `v8-auth-jwt`. */
  | { estado: "sin_alcance"; agente: string; exigido: string; tiene: string[] }
  /** Vale y alcanza.
   *
   *  ⚠ **`agente` está VERIFICADO; `corrida` está DECLARADA.** No son lo mismo y
   *  no se pueden tratar igual:
   *   · `agente` sale de la fila del token — el llamador no lo elige.
   *   · `corrida` sale de un header del llamador — es procedencia, NO una
   *     afirmación de identidad. Sirve para poder DESHACER un lote, no para
   *     autorizar nada. Nunca ramifiques permisos por `corrida`. */
  | { estado: "verificado"; agente: string; tokenId: string; scopes: string[]; corrida?: string };

/**
 * No se pudo verificar. **NO significa que el token sea malo**: significa que el
 * verificador no pudo correr (la base no contestó, timeout, permisos).
 *
 * El consumidor responde **503 con `reintentable: true`**, nunca 401. Es la
 * lección del 01-sep un escalón más abajo: durante una caída, decirle "tu
 * credencial es inválida" a quien tiene una credencial buena lo empuja al único
 * gesto que tampoco funciona, y le tira más carga al sistema que ya no da abasto.
 */
export class ServicioIndeterminado extends Error {
  constructor(motivo: string) {
    super(`No se pudo verificar la credencial de servicio: ${motivo}`);
    this.name = "ServicioIndeterminado";
  }
}

/** Una fila de `service_tokens`, con solo lo que esta librería lee. */
export type FilaToken = {
  id: string;
  agente: string;
  hash: string;
  scopes: string[];
  activo: boolean;
};

/**
 * Cómo llega esta librería a la tabla. Se inyecta a propósito: el módulo no abre
 * conexiones ni conoce credenciales — eso es del consumidor, que ya tiene su
 * cliente `service_role`.
 *
 * `buscar` devuelve `null` si no existe la fila, y **TIRA** si no pudo consultar.
 * Esa diferencia es todo el punto: "no existe" es un rechazo, "no pude preguntar"
 * es indeterminado. Un adaptador que devuelva `null` ante un timeout convierte
 * una caída de la base en un rechazo de credencial — el bug que este ecosistema
 * ya se comió tres veces esta semana.
 */
export type Almacen = {
  /**
   * ⭐ PREFERIDA: delega la verificación al servidor, así **el hash nunca sale de
   * la base**. Es mejor que `buscar` y no es un detalle de gusto — con `buscar`,
   * el hash de cada credencial viaja por la red hasta la edge function en cada
   * llamada. Lo propuso `mirror` al aplicar la migración y tenía razón.
   *
   * Devuelve el agente si el token vale Y alcanza; `null` si no.
   * **TIRA** si no pudo consultar → indeterminado.
   *
   * ⚠ Costo conocido: con un solo `null` para «no existe», «secreto malo» y «sin
   * scope», el estado `sin_alcance` (403 terminal) **colapsa en `rechazado`
   * (401)**. Es deliberado del lado de `mirror` —distinguir sería un oráculo para
   * quien prueba tokens— y está pedida la variante que solo pueda llamar
   * `service_role` para recuperar la distinción sin exponerla hacia afuera.
   */
  verificarEnServidor?: (id: string, secreto: string, scope: string) => Promise<{ agente: string; scopes?: string[] } | null>;
  /** Alternativa: traer la fila y comparar acá. Se conserva para almacenes que no
   *  puedan ofrecer la verificación server-side. */
  buscar?: (id: string) => Promise<FilaToken | null>;
  /** Best-effort, para `ultimo_uso`. Si falla, NO puede romper la verificación. */
  marcarUso?: (id: string) => Promise<void>;
};

const PREFIJO = "v8svc_";

/** `v8svc_<id>_<secreto>`. El `id` es público (va en claro y sirve para buscar);
 *  el secreto nunca se guarda, solo su hash. */
function partir(token: string): { id: string; secreto: string } | null {
  if (!token.startsWith(PREFIJO)) return null;
  const resto = token.slice(PREFIJO.length);
  const corte = resto.indexOf("_");
  if (corte <= 0) return null;
  const id = resto.slice(0, corte);
  const secreto = resto.slice(corte + 1);
  if (!id || !secreto) return null;
  // El id viaja a una consulta: se acota su alfabeto acá y no se confía en que el
  // adaptador parametrice bien. Defensa en profundidad, no reemplazo del bind.
  // ⚠ Admite guiones porque `mirror` hizo el `id` un **uuid** al aplicar la tabla,
  // y mi versión original (alfanumérico puro) habría rechazado TODO token real.
  if (!/^[A-Za-z0-9-]{4,64}$/.test(id)) return null;
  return { id, secreto };
}

/** Charset acotado para la corrida: se estampa en una base, así que no se acepta
 *  cualquier cosa que mande el llamador. No es autorización — es higiene. */
function corridaDe(req: Request): string | undefined {
  const v = (req.headers.get("X-V8-Run-Id") ?? "").trim();
  if (!v || v.length > 64 || !/^[A-Za-z0-9_.:-]+$/.test(v)) return undefined;
  return v;
}

/** SHA-256 en hex. Web Crypto: disponible en Deno sin dependencias. */
export async function hashear(secreto: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secreto));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Comparación en tiempo constante.
 *
 * ⚠ No es paranoia de manual: sin esto, `a === b` corta en el primer byte que
 * difiere, y el atacante que puede medir la diferencia adivina el hash byte por
 * byte en vez de por fuerza bruta. Es barato hacerlo bien y caro descubrirlo mal.
 */
function igualesEnTiempoConstante(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let dif = 0;
  for (let i = 0; i < a.length; i++) dif |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return dif === 0;
}

/**
 * Verifica una credencial de servicio contra el scope que EXIGE quien atiende.
 *
 * @param token   el valor crudo (`v8svc_...`)
 * @param exigido el scope que esta operación requiere, p.ej. `contactos:escribir`
 * @param almacen cómo llegar a la tabla
 */
export async function verificarToken(
  token: string,
  exigido: string,
  almacen: Almacen,
  corrida?: string,
): Promise<VerificacionServicio> {
  const partes = partir((token ?? "").trim());
  if (!partes) return { estado: "sin_credencial" };

  // ⭐ Camino preferido: la base verifica y el hash nunca sale de ahí.
  if (almacen.verificarEnServidor) {
    let r: { agente: string; scopes?: string[] } | null;
    try {
      r = await almacen.verificarEnServidor(partes.id, partes.secreto, exigido);
    } catch (e) {
      throw new ServicioIndeterminado(e instanceof Error ? e.message : String(e));
    }
    // Un solo `null` para los tres «no». Ver la nota en `Almacen`: hoy
    // `sin_alcance` no se puede distinguir por este camino y colapsa en 401.
    if (!r) return { estado: "rechazado", motivo: "desconocido" };
    if (almacen.marcarUso) {
      try { await almacen.marcarUso(partes.id); } catch { /* no rompe nada */ }
    }
    return {
      estado: "verificado",
      agente: r.agente,
      tokenId: partes.id,
      scopes: r.scopes ?? [exigido],
      ...(corrida ? { corrida } : {}),
    };
  }

  if (!almacen.buscar) {
    throw new ServicioIndeterminado("el almacén no ofrece ni verificarEnServidor ni buscar");
  }

  let fila: FilaToken | null;
  try {
    fila = await almacen.buscar(partes.id);
  } catch (e) {
    // La base no contestó. NO sabemos nada sobre este token.
    throw new ServicioIndeterminado(e instanceof Error ? e.message : String(e));
  }

  if (!fila) return { estado: "rechazado", motivo: "desconocido" };
  if (!fila.activo) return { estado: "rechazado", motivo: "revocado" };

  const hash = await hashear(partes.secreto);
  if (!igualesEnTiempoConstante(hash, fila.hash)) {
    // ⚠ Se responde `secreto_invalido` y NO "el token id X existe pero la clave
    // está mal" hacia afuera: el consumidor debe devolver el MISMO 401 que para
    // `desconocido`. Distinguirlos en la respuesta HTTP le confirma a quien
    // prueba que ese id existe. Acá se distinguen para el LOG, no para el cliente.
    return { estado: "rechazado", motivo: "secreto_invalido" };
  }

  const scopes = Array.isArray(fila.scopes) ? fila.scopes : [];
  if (!scopes.includes(exigido)) {
    // Credencial buena, permiso ausente → 403 TERMINAL. Re-autenticarse no lo
    // arregla, así que mandarlo a pedir otro token es mandarlo a dar vueltas.
    return { estado: "sin_alcance", agente: fila.agente, exigido, tiene: scopes };
  }

  // Best-effort y DESPUÉS de decidir: `ultimo_uso` es telemetría, no autorización.
  // Si esta escritura falla —réplica de solo lectura, permisos, la base lenta— la
  // verificación ya está tomada y no puede caerse por un dato de conveniencia.
  if (almacen.marcarUso) {
    try { await almacen.marcarUso(fila.id); } catch { /* no rompe nada */ }
  }

  return {
    estado: "verificado",
    agente: fila.agente,
    tokenId: fila.id,
    scopes,
    ...(corrida ? { corrida } : {}),
  };
}

/**
 * Igual que `verificarToken`, pero saca la credencial del `Request`.
 *
 * Acepta `Authorization: Bearer v8svc_...` o el header `X-V8-Service-Token`.
 * ⚠ Si el `Authorization` trae algo que NO empieza con `v8svc_`, devuelve
 * `sin_credencial` en vez de `rechazado`: casi seguro es un Bearer de sesión de
 * persona, y esa la verifica `v8-auth-jwt`. Tratarlo como rechazo haría que un
 * operador legítimo reciba "credencial de servicio inválida", que no le dice nada.
 */
export async function verificarServicio(
  req: Request,
  exigido: string,
  almacen: Almacen,
): Promise<VerificacionServicio> {
  const corrida = corridaDe(req);
  const propio = req.headers.get("X-V8-Service-Token");
  if (propio) return verificarToken(propio, exigido, almacen, corrida);

  const auth = req.headers.get("Authorization") ?? req.headers.get("authorization");
  if (!auth) return { estado: "sin_credencial" };
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return { estado: "sin_credencial" };
  const crudo = m[1].trim();
  if (!crudo.startsWith(PREFIJO)) return { estado: "sin_credencial" };
  return verificarToken(crudo, exigido, almacen, corrida);
}

/**
 * Acuña un token nuevo. Devuelve el secreto EN CLARO una sola vez y su hash.
 *
 * Se guarda el hash; el secreto se muestra una vez y se copia al vault. Si se
 * pierde, se acuña otro y se revoca el anterior — no hay recuperación, a
 * propósito: un secreto recuperable es un secreto que alguien más puede recuperar.
 */
export async function acunar(
  agente: string,
  scopes: string[],
  idLargo = 12,
  secretoLargo = 32,
): Promise<{ id: string; secreto: string; token: string; hash: string; agente: string; scopes: string[] }> {
  const alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const azar = (n: number) => {
    const bytes = new Uint8Array(n);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map((b) => alfabeto[b % alfabeto.length]).join("");
  };
  const id = azar(idLargo);
  const secreto = azar(secretoLargo);
  return {
    id,
    secreto,
    token: `${PREFIJO}${id}_${secreto}`,
    hash: await hashear(secreto),
    agente,
    scopes,
  };
}
