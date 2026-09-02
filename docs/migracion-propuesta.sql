-- PROPUESTA de migración para `mirror` — la ubicación y los tipos son suyos.
-- Si algo acá está mal, la versión correcta es la de mirror, no ésta.
--
-- Contexto: contactos-api e identidades-api exigen Bearer de sesión de OPERADOR,
-- así que ningún agente puede escribir en el padrón de personas. Andy aprobó un
-- token de servicio acotado a esas dos escrituras (2026-09-02).

create table if not exists public.service_tokens (
  id           text primary key,                    -- prefijo PÚBLICO, viaja en el token
  agente       text        not null,                -- 'whatsapp', 'estratega', ...
  hash         text        not null,                -- sha256(secreto) en hex. El secreto NO se guarda.
  scopes       text[]      not null default '{}',   -- {'contactos:escribir','identidades:escribir'}
  activo       boolean     not null default true,
  creado_en    timestamptz not null default now(),
  revocado_en  timestamptz,
  ultimo_uso   timestamptz,
  constraint service_tokens_id_ck     check (id ~ '^[A-Za-z0-9]{4,32}$'),
  constraint service_tokens_agente_ck check (length(agente) between 2 and 64)
);

comment on table  public.service_tokens is
  'Credenciales de agente (identidad no humana). Verificadas por v8-auth-service. '
  'OPACAS y no JWT a propósito: un JWT no se puede revocar, y con jwt_exp=28800 revocar '
  'significaría "deja de valer en algún momento de las próximas 8 horas" — insuficiente '
  'para una credencial que escribe en el padrón de PERSONAS.';
comment on column public.service_tokens.hash is
  'sha256 del secreto. Si se pierde el secreto se acuña otro y se revoca éste: no hay '
  'recuperación a propósito — un secreto recuperable es uno que alguien más puede recuperar.';

-- ⭐ LO ÚNICO QUE PIDO NO NEGOCIAR: nadie más que service_role la lee.
-- Un padrón de tokens legible por una sesión cualquiera no vale nada.
alter table public.service_tokens enable row level security;
revoke all on public.service_tokens from anon, authenticated;
-- (service_role saltea RLS por diseño; no se crea ninguna policy a propósito:
--  sin policies y con RLS activo, anon/authenticated no ven NADA aunque alguien
--  les otorgue un GRANT por error más adelante. Default cerrado.)

-- La revocación es el punto de todo el diseño: un update, efecto inmediato.
--   update public.service_tokens set activo=false, revocado_en=now() where id='...';

-- `ultimo_uso` es telemetría, NO autorización. Va por RPC para que el módulo no
-- necesite permisos de escritura sobre la tabla, y si falla no rompe nada.
create or replace function public.service_token_marcar_uso(p_id text)
returns void
language sql
security definer
set search_path = public, pg_temp   -- ⚠ SECURITY DEFINER sin search_path fijo es escalable
as $$
  update public.service_tokens set ultimo_uso = now() where id = p_id and activo;
$$;

revoke all on function public.service_token_marcar_uso(text) from public, anon, authenticated;
