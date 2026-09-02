/**
 * El adaptador contra Supabase, para que NINGÚN consumidor escriba su propia
 * consulta.
 *
 * ⚠ Esto no es azúcar: es el punto exacto donde nace la divergencia. Si cada API
 * escribe su propio lookup, en tres meses hay tres, y una de ellas devuelve
 * `null` ante un timeout — que convierte una caída de la base en un rechazo de
 * credencial. Ese error ya se cometió tres veces en este ecosistema esta semana.
 *
 * La regla que este archivo hace cumplir por construcción:
 *
 *     no vale            →  null   (rechazo)
 *     no pude preguntar  →  TIRA   (indeterminado)
 *
 * ── DÓNDE VIVE LA TABLA (aplicada por `mirror`, 2026-09-02) ───────────────────
 *     v8_auth.service_tokens
 *     v8_auth.verificar_token(p_id uuid, p_secreto text, p_scope text) → text | null
 *
 * NO está en el schema `auth`: ese es de GoTrue y ni siquiera se puede escribir
 * ahí (`42501 permission denied`, medido por `mirror`). Y `v8_auth` **no está
 * expuesto por PostgREST**, que para una tabla de hashes de credenciales es mejor,
 * no peor.
 *
 * ⚠ **Y de ahí sale el requisito de este archivo:** si el schema no está expuesto,
 * `supabase.rpc()` NO puede llamar a `v8_auth.verificar_token` directamente. Hace
 * falta un envoltorio en un schema expuesto —`public.verificar_service_token`,
 * `security definer`, revocado de `anon`/`authenticated`— que llame al de adentro.
 * El default de `rpcVerificar` apunta a ese envoltorio.
 */
import type { Almacen, FilaToken } from "./servicio.ts";

/** Lo mínimo del cliente de Supabase que necesitamos. Se tipa así y no con el
 *  `SupabaseClient` real para no arrastrar su dependencia a este módulo. */
export type ClienteMinimo = {
  rpc: (fn: string, args: Record<string, unknown>) => Promise<{ data: unknown; error: unknown }>;
  from?: (tabla: string) => {
    select: (cols: string) => {
      eq: (col: string, val: string) => {
        maybeSingle: () => Promise<{ data: unknown; error: unknown }>;
      };
    };
  };
};

export type OpcionesAlmacen = {
  /** Envoltorio en schema EXPUESTO que llama a `v8_auth.verificar_token`.
   *  Devuelve el nombre del agente, o `null` si el token no vale o no alcanza. */
  rpcVerificar?: string;
  /** RPC aparte para `ultimo_uso`. **Normalmente NO se pasa.**
   *  `mirror` lo metió adentro de `verificar_token` (tope 1 escritura/min), y su
   *  razón es buena: una llamada separada alguien la olvida, y `ultimo_uso` pasa a
   *  mentir por omisión — peor que no tenerlo. Queda solo para almacenes que no
   *  puedan marcarlo por dentro. */
  rpcUso?: string;
  /** Solo para el camino de respaldo `buscar`. */
  tabla?: string;
};

/** `PGRST116` = «no rows», que es un NO legítimo. **Cualquier otro error
 *  —timeout, permisos, la base caída— es NO PUDE PREGUNTAR** y tiene que
 *  propagarse para que `verificarToken` lo convierta en `ServicioIndeterminado`. */
function esAusencia(error: { code?: string } | null): boolean {
  return !!error && error.code === "PGRST116";
}

export function almacenSupabase(cliente: ClienteMinimo, opts: OpcionesAlmacen = {}): Almacen {
  const rpcVerificar = opts.rpcVerificar ?? "verificar_service_token";
  const tabla = opts.tabla ?? "service_tokens";

  return {
    /** ⭐ El camino bueno: la base compara el hash y **el hash nunca sale de ahí**.
     *  Con `buscar`, el hash de cada credencial viaja por la red hasta la edge
     *  function en cada llamada. Lo señaló `mirror` y tenía razón. */
    verificarEnServidor: async (id, secreto, scope) => {
      const { data, error } = await cliente.rpc(rpcVerificar, {
        p_id: id,
        p_secreto: secreto,
        p_scope: scope,
      });
      const err = error as { code?: string; message?: string } | null;
      if (err) {
        // ⚠ TIRAR, no devolver null. Un `return null` acá haría que una base caída
        // se lea como «ese token no vale» → 401 → el agente concluye que su
        // credencial murió. Es el bug del 01-sep un nivel más abajo.
        throw new Error(err.message ?? `el RPC ${rpcVerificar} falló sin mensaje`);
      }
      // La función devuelve el AGENTE o NULL. Un solo `null` para «no existe»,
      // «secreto malo» y «sin scope», a propósito: distinguirlos hacia afuera
      // sería un oráculo para quien prueba tokens.
      const agente = typeof data === "string" ? data.trim() : "";
      return agente ? { agente } : null;
    },

    /** Respaldo, para almacenes que no puedan ofrecer verificación server-side. */
    buscar: opts.tabla && cliente.from
      ? async (id: string): Promise<FilaToken | null> => {
        const { data, error } = await cliente.from!(tabla)
          .select("id,agente,secreto_hash,scopes,activo").eq("id", id).maybeSingle();
        const err = error as { code?: string; message?: string } | null;
        if (err && !esAusencia(err)) throw new Error(err.message ?? "la consulta falló sin mensaje");
        if (!data) return null;
        const f = data as Record<string, unknown>;
        // ⚠ La columna es `secreto_hash` (nombre de `mirror`), no `hash`.
        if (typeof f.id !== "string" || typeof f.secreto_hash !== "string" || typeof f.agente !== "string") {
          return null; // una fila a medias es peor que ninguna
        }
        return {
          id: f.id,
          agente: f.agente,
          hash: f.secreto_hash,
          scopes: Array.isArray(f.scopes) ? (f.scopes as string[]) : [],
          activo: f.activo !== false, // ausente = activo: la revocación es explícita
        };
      }
      : undefined,

    marcarUso: opts.rpcUso
      ? async (id: string) => { await cliente.rpc(opts.rpcUso!, { p_id: id }); }
      : undefined,
  };
}
