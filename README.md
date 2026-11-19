# Agente NFC

Lee credenciales emitidas por la app Android de `../nfc`, usando un ACS ACR122U
y tarjetas MIFARE Classic 1K o Ultralight/NTAG (NFC Type 2) con NDEF estándar.
No escribe ni modifica tarjetas.

## Ejecutar

```powershell
go run .
```

Por defecto descarga `https://nfc.eliyya.dev/keys`, verifica el manifiesto Ed25519
con la raíz pública de `keys/root-public.pem`, integrada en el ejecutable, y admite
solamente claves ACTIVE.
Las claves autenticadas se guardan en disco y se conservan en memoria durante
la ejecución. Las lecturas siguientes reutilizan la memoria sin leer archivos ni
volver a verificar el manifiesto. La vigencia máxima sigue siendo una hora desde
la sincronización original; cargar desde disco no reinicia ese plazo. La firma
de cada tarjeta se verifica siempre. Al reiniciar el proceso se carga la caché
del usuario y se verifica su firma raíz antes de conservarla en memoria.
La orden `refresh_keys` fuerza la descarga y sustituye las claves en memoria.
El origen `memoria` aparece en `keysSource` cuando se reutilizan.
Cuando caduca, se descarga un manifiesto nuevo; si no es posible, la validación falla.

### Descargar y comprobar la caché sin tarjeta

```powershell
.\nfc-agent.exe -check-keys
.\nfc-agent.exe -check-keys -offline
```

El primer comando fuerza una descarga, verifica la firma y guarda el manifiesto
firmado. El segundo lo vuelve a leer del disco sin acceder al servidor y vuelve a
verificar la firma. Ambos muestran el origen y la ruta del archivo.

En Windows se guarda normalmente en
`%LOCALAPPDATA%\BiblioDesk\nfc-agent\keys-manifest.json`.
`-keys-cache ruta` permite elegir otra ubicación. El archivo conserva el manifiesto
original, su firma, el servidor y la fecha de descarga. Solo se guarda después de
autenticarlo; una respuesta inválida no reemplaza la caché. `-offline` exige una
caché válida con antigüedad máxima de una hora. Los cambios de revocación en el
servidor se conocen al refrescar las claves, no mientras se usa una copia previa.

### Instalar la raíz de confianza

La raíz se exporta desde el backend por un canal de confianza y se copia antes de
compilar. `go:embed` la incluye en el binario: el equipo de destino solo necesita
el ejecutable, sin archivos PEM adicionales.

```powershell
# Desde ~/code/nfc-backend, con DATABASE_URL apuntando a la base correcta:
pnpm keys:export-root
# Desde ~/code/nfc-agent:
Copy-Item ../nfc-backend/keys/root-public.pem keys/root-public.pem
go build -o nfc-agent.exe .
.\nfc-agent.exe -check-keys
```

`-check-keys` descarga y autentica el manifiesto sin necesitar lector ni tarjeta.
Si cambia la raíz del backend, provisiona la nueva raíz de confianza y recompila;
el agente no descarga ni acepta automáticamente una raíz sustituta. Android debe
usar la misma raíz. Las tarjetas emitidas con una emisora anterior solo podrán
validarse si el manifiesto incluye esa emisora con un estado admitido.

Si aparece un tiempo de espera, la lectura de la tarjeta puede haber terminado
correctamente, pero falta obtener las claves para verificarla. El agente no cambia
automáticamente al modo local. Para elegir otro servidor con un manifiesto firmado
por la misma raíz, usa `-keys-url https://servidor/keys`.

Para probar con la clave pública de confianza del backend local, sin servidor:

```powershell
go run . -once -issuer-public-key ../nfc-backend/keys/issuer-1-public.pem -issuer-key-id 1
```

Este modo verifica la firma con la clave seleccionada explícitamente; no consulta
revocación ni caducidad de la clave. Nunca necesita claves privadas.

`-once` finaliza después del primer intento de lectura; devuelve código 1 si falla.
Sin esa opción espera tarjetas hasta pulsar Ctrl+C. Usa `-stdio` para el protocolo JSON de Electron documentado en `PROTOCOL.md`.

## Compilar y comprobar

```powershell
go test ./...
go build -o nfc-agent.exe .
```

Prueba opcional contra el backend de producción (requiere Internet):

```powershell
go test -tags integration -run TestProductionTrustChain -v .
```

Esta prueba pide una credencial sintética de ocho dígitos, verifica el manifiesto
con la raíz integrada y verifica la credencial con la emisora autenticada. No
escribe ninguna tarjeta.

En Windows usa la biblioteca del sistema `winscard.dll` y el controlador PC/SC
del lector. No requiere instalar Go en el equipo de destino.

## Formato compatible

- Registro NDEF MIME `application/vnd.eli.access`.
- V1: 70 bytes, versión (1), keyId (1), userId big endian (4), firma (64).
  Se interpreta como estudiante y conserva los ocho dígitos del número de control.
- V2: versión (1), keyId (1), tipo (1), longitud UTF-8 (1), identificador (N),
  firma (64). La longitud total debe ser exactamente 4 + N + 64 bytes.
- Tipos v2: 1 = `student`, 2 = `teacher`, 3 = `book`.
- Identificadores: estudiante `[0-9]{8}`; docente
  `[A-ZÑ&]{4}[0-9]{6}[A-Z0-9]{3}`; ejemplar
  `[A-Z0-9]{3}-[0-9]{3}-[0-9]{4}-[0-9]{2}`.
  Se exige UTF-8 válido y coincidencia completa, sin normalizar el contenido.
- Firma Ed25519 sobre todos los bytes anteriores a la firma: seis en v1,
  4 + N en v2, incluidos tipo y longitud. Se rechazan versiones y tipos desconocidos.
- Por ejemplo, `ISC-001-0044-01` ocupa 15 bytes: la credencial v2 ocupa 83 bytes.
- El evento JSON incluye `type` e `identifier` para ambas versiones;
  `userId` solo aparece para estudiantes, como alias compatible.
- Lectura del directorio MAD1 y de sectores asignados a NDEF usando las claves
  públicas estándar MAD y NDEF. No admite claves MIFARE personalizadas.
- Selecciona el método de lectura por el ATR: Classic 1K usa sectores/MAD;
  Ultralight/NTAG usa páginas de 4 bytes y el tamaño del Capability Container.
- Type 2 admite memoria NDEF contigua y legible públicamente, hasta la página 255;
  no admite selección de sectores ni áreas reservadas intercaladas.
- No admite registros NDEF fragmentados.

Una firma válida autentica los datos emitidos; no prueba que el chip sea incopiable
ni confirma que el usuario esté autorizado actualmente para realizar un préstamo.
