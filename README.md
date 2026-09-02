# v8-auth-service

Identidad **no humana** para el ecosistema V8: un agente demostrando quién es, con alcance
verificable y revocación inmediata.

Hermano de [`v8-auth-jwt`](https://github.com/V8Labs/v8-auth-jwt) (la sesión de una *persona*)
y de `v8-auth-session` (el llavero del navegador). Misma frase de gobierno:

> **Mecanismo, no política: distingue «no vale» de «no pude verificar».**

---

## Por qué existe

`contactos-api` y `identidades-api` exigen un Bearer de sesión de un **operador logueado en
XO**. Es deliberado — pero deja al ecosistema sin ningún camino para que un **agente** escriba
en el padrón de personas. Lo destapó un caso concreto: 2.034 contactos de la agenda de Andy,
ya reconciliados por `whatsapp`. Ningún agente puede cargarlos, y un humano tampoco: son 2.034
submits a mano.

Andy aprobó (2026-09-02) un token de servicio **acotado a esas dos escrituras**. Esto es ese
mecanismo, definido **una vez**, para que dos APIs no improvisen cada una el suyo.

## Uso

```ts
import { verificarServicio, ServicioIndeterminado }
  from "https://raw.githubusercontent.com/V8Labs/v8-auth-service/<SHA>/servicio.ts";
import { almacenSupabase }
  from "https://raw.githubusercontent.com/V8Labs/v8-auth-service/<SHA>/almacen_supabase.ts";

const almacen = almacenSupabase(serviceRoleClient);
// ⚠ NO se pasa `rpcUso`: `mirror` metió el marcado de uso ADENTRO de
// `verificar_token`, con tope de 1 escritura/minuto. Su razón es buena: si marcar
// el uso es una llamada aparte, alguien la va a olvidar y `ultimo_uso` va a mentir
// por omisión — y un campo que miente por omisión es peor que no tenerlo.

try {
  const svc = await verificarServicio(req, "contactos:escribir", almacen);

  switch (svc.estado) {
    case "sin_credencial": return json({ error: "no_auth" }, 401);
    case "rechazado":      return json({ error: "no_auth" }, 401);   // ⚠ mismo 401 que arriba
    case "sin_alcance":    return json({ error: "sin_alcance" }, 403);
    case "verificado":     break;
  }

  // ⭐ svc.agente es el AUTOR. Estampalo. Si no podés registrarlo, rechazá.
  await escribir({ ...datos, creado_por: svc.agente });

} catch (e) {
  if (e instanceof ServicioIndeterminado) {
    return json({ error: "auth_no_disponible", reintentable: true }, 503);
  }
  throw e;
}
```

> ⚠ **`rechazado` y `sin_credencial` devuelven el MISMO 401 hacia afuera.** El módulo los
> distingue para tu log, no para el cliente: responder distinto le confirma a quien prueba
> tokens que un id existe.

## Las tres decisiones de diseño

### 1 · El token es opaco, **no** un JWT

Un JWT firmado era el primer instinto: más elegante, sin ida a la base. Y por eso mismo **no
se puede revocar** — vale hasta que expira. Con `jwt_exp = 28800` en este proyecto, revocar
significaría *«deja de valer en algún momento de las próximas 8 horas»*.

Para una credencial que escribe en el padrón de **personas**, eso no alcanza.

```sql
update service_tokens set activo=false, revocado_en=now() where id='...';
```

Efecto en la llamada siguiente. Sin deploy. El costo —una lectura indexada por invocación— lo
paga una carga masiva sin despeinarse; esto no es camino caliente.

### 2 · El alcance lo declara **quien recibe**, nunca quien llama

```ts
await verificarServicio(req, "contactos:escribir", almacen);
```

La función que atiende dice qué exige; el verificador compara contra la fila. El llamador solo
presenta un token — **lo que ese token puede hacer no lo decide él**.

> ⚠ Es lo que hoy hace mal `roadmap-api`: su `X-Agent-Token` es **compartido** y el campo
> `agent` **lo escribe quien llama**. Su propio contrato lo admite: *«la identidad nunca estuvo
> enforced»*. No se repite ese diseño.

**No hay comodines.** `contactos:*` no habilita `contactos:escribir`. Un comodín se escribe una
vez y después nadie recuerda qué abrió.

### 3 · Sin autor no hay escritura

`verificado` trae `agente`, y el consumidor **debe** estamparlo. Andy aprobó el token; no
aprobó perder el registro de quién escribió qué. Una carga de 2.034 contactos sin autor es
justo lo que después no se puede desarmar.

## Los cuatro estados

| estado | qué pasó | respuesta |
|---|---|---|
| `sin_credencial` | no vino, o no tiene la forma | **401** |
| `rechazado` | no existe · revocado · secreto inválido | **401** |
| `sin_alcance` | credencial buena, permiso ausente | **403 terminal** |
| `verificado` | vale y alcanza | seguir, estampando `agente` |
| *lanza* `ServicioIndeterminado` | **el verificador no pudo correr** | **503 `reintentable:true`** |

La última fila es la que importa y la que cuesta caro olvidar: el 01-sep, seis consumidores le
dijeron *«tu sesión es inválida»* a operadores con sesión válida durante una caída de Auth. El
re-login que eso provoca **no funciona y le tira más carga al sistema que ya no daba abasto**.

`sin_alcance` es **403 y terminal**: re-autenticarse no lo arregla, así que mandarlo a pedir
otro token es mandarlo a dar vueltas. Misma familia que el `sin_email` de `v8-auth-jwt`.

## Banco de pruebas

```
deno test servicio_test.ts      # 28 casos
```

Los que importan no son «¿acepta un token bueno?»:

- la base caída lanza `ServicioIndeterminado`, **nunca** `rechazado`
- un token sin el scope da `sin_alcance` aunque sea válido
- un token revocado deja de valer **en la llamada siguiente**
- si el `marcarUso` (telemetría) falla, **la verificación sobrevive**
- un Bearer de **sesión de persona** da `sin_credencial`, no `rechazado` — ésa la verifica
  `v8-auth-jwt`, y tratarla como rechazo le diría a un operador legítimo «credencial de
  servicio inválida», que no le dice nada

## La tabla — aplicada por `mirror` (2026-09-02)

    v8_auth.service_tokens
    v8_auth.verificar_token(p_id uuid, p_secreto text, p_scope text) → text | null

**NO está en el schema `auth`**: ese es de GoTrue y ni siquiera se puede escribir ahí
(`42501 permission denied`, medido). Y `v8_auth` **no está expuesto por PostgREST** — que
para una tabla de hashes de credenciales es mejor, no peor.

`mirror` mejoró el diseño en un punto que yo tenía peor: **la verificación ocurre en la
base, así el hash nunca sale de ahí.** Mi versión traía la fila y comparaba en la edge
function, o sea que el hash de cada credencial viajaba por la red en cada llamada.

⚠ **Requisito pendiente:** como `v8_auth` no está expuesto, `supabase.rpc()` no puede llamar
a `v8_auth.verificar_token` directamente. Hace falta un envoltorio
`public.verificar_service_token` (`security definer`, revocado de `anon`/`authenticated`).
Es el default de `rpcVerificar`. Pedido a `mirror`.

⚠ **Costo conocido y documentado:** la función devuelve el agente o `NULL`, con un solo
`NULL` para «no existe», «secreto malo» y «sin scope». Es deliberado —distinguirlos sería un
oráculo para quien prueba tokens— pero hace que **`sin_alcance` (403 terminal) colapse en
`rechazado` (401)** por ese camino. Pedida a `mirror` una variante llamable solo por
`service_role` que recupere la distinción sin exponerla hacia afuera.

## Import por SHA, nunca por tag

Un tag se puede mover (`git tag -f && git push -f`) y todos los consumidores traen otro código
sin cambiar una línea del suyo. En un módulo que decide si una credencial vale, esa comodidad
no paga la superficie. Misma regla que `v8-auth-jwt`.

| versión | SHA | notas |
|---|---|---|
| `1.0.0` | `868f2fa8eae85359d74a3fe52856c0753d884d90` | primera |
| `1.1.0` | _(este commit)_ | esquema real de `mirror` (uuid, `secreto_hash`, RPC) + `corrida` |

La línea completa, lista para pegar:

```ts
import { verificarServicio, ServicioIndeterminado }
  from "https://raw.githubusercontent.com/V8Labs/v8-auth-service/868f2fa8eae85359d74a3fe52856c0753d884d90/servicio.ts";
import { almacenSupabase }
  from "https://raw.githubusercontent.com/V8Labs/v8-auth-service/868f2fa8eae85359d74a3fe52856c0753d884d90/almacen_supabase.ts";
```

Verificado importando ese SHA desde Deno, igual que lo hará una edge function.
