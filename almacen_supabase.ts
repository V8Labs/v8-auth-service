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
 *     no existe la fila  →  null   (rechazo)
 *     no pude consultar  →  TIRA   (indeterminado)
 *
 * Usalo con un cliente **`service_role`**: la tabla no es legible por `anon` ni
 * por `authenticated`, a propósito — un padrón de tokens legible por cualquier
 * sesión no vale nada.
 */
import type { Almacen, FilaToken } from "./servicio.ts";

/** Lo mínimo del cliente de Supabase que necesitamos. Se tipa así y no con el
 *  `SupabaseClient` real para no arrastrar su dependencia a este módulo. */
export type ClienteMinimo = {
  from: (tabla: string) => {
    select: (cols: string) => {
      eq: (col: string, val: string) => {
        maybeSingle: () => Promise<{ data: unknown; error: unknown }>;
      };
    };
  };
  rpc?: (fn: string, args: Record<string, unknown>) => Promise<{ error: unknown }>;
};

export type OpcionesAlmacen = {
  /** Por si `mirror` decide otra ubicación. Default: la acordada. */
  tabla?: string;
  /** RPC que estampa `ultimo_uso`. Si no existe, no se marca y no pasa nada. */
  rpcUso?: string;
};

/** Distingue "PostgREST contestó que no hay fila" de "no pude preguntar".
 *
 *  `PGRST116` = «no rows» con `maybeSingle`, que es un NO legítimo. Cualquier
 *  otro error —timeout, permisos, la base caída— es NO PUDE PREGUNTAR y tiene
 *  que propagarse como excepción para que `verificarToken` lo convierta en
 *  `ServicioIndeterminado`. */
function esAusencia(error: { code?: string } | null): boolean {
  return !!error && error.code === "PGRST116";
}

export function almacenSupabase(cliente: ClienteMinimo, opts: OpcionesAlmacen = {}): Almacen {
  const tabla = opts.tabla ?? "service_tokens";

  return {
    buscar: async (id: string): Promise<FilaToken | null> => {
      const { data, error } = await cliente
        .from(tabla)
        .select("id,agente,hash,scopes,activo")
        .eq("id", id)
        .maybeSingle();

      const err = error as { code?: string; message?: string } | null;
      if (err && !esAusencia(err)) {
        // ⚠ TIRAR, no devolver null. Un `return null` acá haría que una base
        // caída se lea como "ese token no existe" → 401 → el agente concluye que
        // su credencial murió. Es exactamente el bug del 01-sep, un nivel abajo.
        throw new Error(err.message ?? "la consulta a service_tokens falló sin mensaje");
      }
      if (!data) return null;

      const f = data as Record<string, unknown>;
      // Una fila a medias es peor que ninguna: si el hash o el agente faltan, no
      // podemos ni verificar ni estampar autor. Se trata como no encontrada.
      if (typeof f.id !== "string" || typeof f.hash !== "string" || typeof f.agente !== "string") {
        return null;
      }
      return {
        id: f.id,
        agente: f.agente,
        hash: f.hash,
        scopes: Array.isArray(f.scopes) ? (f.scopes as string[]) : [],
        activo: f.activo !== false, // ausente se trata como activo: la revocación es explícita
      };
    },

    marcarUso: opts.rpcUso && cliente.rpc
      ? async (id: string) => { await cliente.rpc!(opts.rpcUso!, { p_id: id }); }
      : undefined,
  };
}
