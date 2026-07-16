# Backend de CargaSur

Este servidor maneja las cuentas de usuario (shippers y carriers), el tablero
de cargas, y los cobros de Stripe (membresias mensuales y pago por carga).

---

## Que necesitas antes de empezar

1. Cuenta de Stripe: https://dashboard.stripe.com/register
2. Una base de datos Postgres. Las mas faciles para empezar:
   - Render (Postgres administrado, tiene capa gratis limitada)
   - Railway.app
   - Supabase (Postgres gratis generoso)
3. Node.js 18 o mas nuevo instalado (si vas a probarlo en tu computadora antes
   de subirlo).

---

## Paso 1 - Crear la base de datos

1. Crea una base de datos Postgres en el proveedor que elijas.
2. Copia la "Connection String" (URL de conexion) que te dan - se ve asi:
   `postgres://usuario:password@host:5432/nombre_db`
3. Corre el archivo `schema.sql` contra esa base de datos. La forma mas facil:
   - En Render/Railway, hay una pestana "Query" o "Shell" donde puedes pegar
     el contenido completo de `schema.sql` y ejecutarlo.
   - O desde tu computadora, con `psql "TU_CONNECTION_STRING" -f schema.sql`
     (necesitas tener `psql` instalado).

## Paso 2 - Configurar Stripe

1. En el Dashboard de Stripe > **Product catalog** > Add product, crea dos
   productos con **precio recurrente mensual**:
   - "CargaSur - Shipper Mensual" — precio ej. $129/mes
   - "CargaSur - Carrier Mensual" — precio ej. $45/mes
2. Copia el **Price ID** de cada uno (empieza con `price_...`).
3. En Developers > **API keys**, copia tu **Secret key** (empieza con `sk_...`,
   usa la de modo "Test" mientras pruebas todo).

## Paso 3 - Variables de entorno

1. Copia `.env.example` como `.env`.
2. Llena:
   - `DATABASE_URL` (Paso 1)
   - `JWT_SECRET` (invéntate una frase larga y aleatoria)
   - `STRIPE_SECRET_KEY` (Paso 2)
   - `STRIPE_PRICE_SHIPPER_MONTHLY` y `STRIPE_PRICE_CARRIER_MONTHLY` (Paso 2)
   - `PER_LOAD_PRICE_USD` (ej. 12)
   - `FRONTEND_URL` (la direccion de tu landing page o app; puedes usar un
     valor temporal como `https://ejemplo.com` mientras no tengas la app final)

El webhook (`STRIPE_WEBHOOK_SECRET`) lo llenas en el Paso 5, despues de
desplegar.

## Paso 4 - Desplegar el servidor

Igual que el servidor de llamadas: sube esta carpeta a un repositorio de
GitHub y crea un **Web Service** en Render (o Railway):

- **Build command:** `npm install`
- **Start command:** `npm start`
- Agrega todas las variables de entorno del archivo `.env` en la seccion
  **Environment** de Render.

Render te da una URL publica, por ejemplo:
`https://cargasur-api.onrender.com`

## Paso 5 - Conectar el Webhook de Stripe

1. En el Dashboard de Stripe > Developers > **Webhooks** > Add endpoint.
2. URL del endpoint: `https://cargasur-api.onrender.com/api/billing/webhook`
3. Eventos a escuchar (selecciona estos):
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
4. Guarda, y copia el **Signing secret** (empieza con `whsec_...`).
5. Pega ese valor en la variable `STRIPE_WEBHOOK_SECRET` en Render, y vuelve a
   desplegar el servicio para que tome el nuevo valor.

---

## Como probar que funciona

Con el servidor ya desplegado, puedes probar con `curl` o Postman:

```bash
# Crear una cuenta de shipper
curl -X POST https://cargasur-api.onrender.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"shipper@ejemplo.com","password":"123456","role":"shipper","company_name":"Mi Empresa"}'

# Esto te devuelve un "token" - usalo en las siguientes peticiones:
curl https://cargasur-api.onrender.com/api/auth/me \
  -H "Authorization: Bearer TU_TOKEN_AQUI"

# Suscribirse a la membresia mensual de shipper
curl -X POST https://cargasur-api.onrender.com/api/billing/subscribe \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{"plan":"shipper_monthly"}'
# Esto te devuelve un "checkout_url" - abrelo en el navegador para pagar
# (usa una tarjeta de prueba de Stripe: 4242 4242 4242 4242, cualquier fecha
# futura y cualquier CVC, mientras uses la clave de modo "Test")

# Ver el tablero de cargas (publico, no necesita token)
curl https://cargasur-api.onrender.com/api/loads
```

---

## Que falta para tener la plataforma completa

Este servidor es el **motor** (API) - todavia falta la parte visual que un
usuario normal va a usar (formularios de registro, el tablero de cargas
navegable, botones de pago). Eso seria un sitio web o app que llame a estos
mismos endpoints. Si quieres, el siguiente paso logico es construir esa
interfaz web conectada a esta API.

## Seguridad

- Nunca compartas tu archivo `.env` ni lo subas a un repositorio publico.
- Usa las claves de Stripe en modo "Test" hasta que todo funcione bien: solo
  cambia a las claves "Live" cuando estes listo para cobrar de verdad.
- Cambia `JWT_SECRET` por un valor unico y dificil de adivinar, distinto al
  que uses en cualquier otro proyecto.
