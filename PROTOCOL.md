# Protocolo de eventos NFC, versión 1

Ejecutar `nfc-agent.exe -stdio`. Cada mensaje es un objeto JSON UTF-8 terminado
en salto de línea (NDJSON). `stdout` contiene exclusivamente eventos; los
diagnósticos se escriben en `stderr`. El proceso arranca con la lectura pausada.

## Órdenes por stdin

```json
{"version":1,"id":"solicitud-1","command":"resume"}
```

| Orden | Resultado |
| --- | --- |
| `status` | Devuelve `paused`, `connected` y `reader`. |
| `pause` | Pausa la lectura de credenciales. |
| `resume` | Reanuda la lectura y consulta una tarjeta ya presente. |
| `refresh_keys` | Descarga, autentica y guarda las claves; falla en modo offline. |
| `shutdown` | Responde, emite `stopped` y termina el proceso. |

Cada orden válida recibe un evento `response` con el mismo `id`. Un error se
devuelve en `error`; una respuesta correcta contiene `data`. El identificador
admite de 1 a 128 letras, números, guiones y guiones bajos. El límite de entrada
es 16 KiB por línea. Se procesan las órdenes y las lecturas en secuencia.

```json
{"version":1,"type":"response","id":"solicitud-1","data":{"paused":false,"connected":true,"reader":"ACS ACR122U PICC Interface 0"}}
```

Cerrar stdin también termina el agente. Una lectura de tarjeta o una consulta
de claves en curso puede retrasar una orden; el cliente debe aplicar un tiempo
de espera y finalizar su proceso hijo si no consigue cerrarlo.

## Eventos por stdout

| Evento | Datos |
| --- | --- |
| `ready` | Estado inicial; el agente está preparado para recibir órdenes. |
| `reader_status` | Estado al conectar/desconectar un lector. |
| `card_present` | Se detectó una tarjeta. No implica credencial válida. |
| `card_removed` | El lector quedó sin tarjeta. |
| `credential` | Credencial cuya firma se verificó con claves autenticadas. |
| `keys_status` | `keyCount` y `source` al sincronizar. |
| `error` | Descripción en `error`; no entrega una credencial. |
| `stopped` | El agente terminó normalmente. |

```json
{"version":1,"type":"credential","data":{"uid":"04D317023C3E03","atr":"3B8F8001804F0CA0000003060300030000000068","technology":"type2","userId":"22820079","keyId":1,"credentialVersion":1,"signatureValid":true,"keysSource":"caché"}}
```

`technology` puede ser `classic1k` o `type2`. `userId` siempre es texto de ocho
dígitos, para conservar ceros iniciales. No se envían claves privadas ni firmas
sin verificar. La lectura se deduplica hasta retirar la tarjeta; `resume`
permite volver a procesar una tarjeta que permanece en el lector.

El UID identifica el chip; el usuario se obtiene del contenido firmado. El
cliente todavía debe consultar el estado y permisos de la persona en el sistema
bibliotecario antes de registrar un préstamo.
