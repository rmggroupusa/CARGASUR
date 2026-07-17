require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Stripe = require('stripe');

const { query } = require('./db');
const { hashPassword, comparePassword, signToken } = require('./auth');
const { requireAuth, requireRole } = require('./middleware');

const crypto = require('crypto');

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

async function sendEmail(to, subject, html) {
  if (!process.env.RESEND_API_KEY) {
    console.warn('RESEND_API_KEY no configurada: no se pudo enviar el correo a', to);
    return { skipped: true };
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + process.env.RESEND_API_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL || 'CargaSur <onboarding@resend.dev>',
      to: [to],
      subject,
      html,
    }),
  });
  if (!res.ok) {
    const errText = await res.text();
    console.error('Error enviando correo con Resend:', errText);
  }
  return res;
}
const app = express();
app.use(cors());

// ============================================================
// WEBHOOK DE STRIPE
// Tiene que ir ANTES de express.json(), porque Stripe necesita
// el cuerpo de la peticion "crudo" (sin procesar) para verificar
// la firma de seguridad.
// ============================================================
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Firma de webhook invalida:', err.message);
    return res.status(400).send('Webhook Error: ' + err.message);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      await handleCheckoutCompleted(event.data.object);
    } else if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
      await handleSubscriptionChange(event.data.object);
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Error procesando el webhook:', err);
    res.status(500).send('Error interno procesando el webhook.');
  }
});

// A partir de aqui, todas las rutas reciben y devuelven JSON normal.
app.use(express.json());

// ============================================================
// AUTENTICACION
// ============================================================

app.post('/api/auth/register', async (req, res) => {
  const {
    email, password, role, company_name, phone, city, state,
    mc_number, vehicle_type, vehicle_make, vehicle_model, vehicle_year,
    vehicle_plate, license_number, license_state, ein_number, business_address,
  } = req.body;

  if (!email || !password || !role) {
    return res.status(400).json({ error: 'Faltan campos obligatorios: email, password, role.' });
  }
  if (!['shipper', 'carrier'].includes(role)) {
    return res.status(400).json({ error: 'El rol debe ser "shipper" o "carrier".' });
  }

  try {
    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length) {
      return res.status(409).json({ error: 'Ya existe una cuenta con ese correo.' });
    }

    const password_hash = await hashPassword(password);
    const result = await query(
      `INSERT INTO users (
         email, password_hash, role, company_name, phone, city, state,
         mc_number, vehicle_type, vehicle_make, vehicle_model, vehicle_year,
         vehicle_plate, license_number, license_state, ein_number, business_address
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
       RETURNING id, email, role, company_name, phone, city, state,
                 mc_number, vehicle_type, vehicle_make, vehicle_model, vehicle_year,
                 vehicle_plate, license_number, license_state, ein_number, business_address, subscription_status`,
      [
        email, password_hash, role, company_name || null, phone || null, city || null, state || null,
        mc_number || null, vehicle_type || null, vehicle_make || null, vehicle_model || null,
        vehicle_year || null, vehicle_plate || null, license_number || null, license_state || null,
        ein_number || null, business_address || null,
      ]
    );

    const user = result.rows[0];
    const token = signToken(user);

    const roleLabel = role === 'shipper' ? 'Shipper' : 'Carrier';
    sendEmail(
      user.email,
      'Your CargaSur account is ready / Tu cuenta de CargaSur ya está creada',
      `<p>Hello${company_name ? ' ' + company_name : ''},</p>
       <p>This confirms that your CargaSur account was created successfully.</p>
       <ul>
         <li><strong>Email:</strong> ${user.email}</li>
         <li><strong>Role:</strong> ${roleLabel}</li>
       </ul>
       <p>You can now log in and start using the platform.</p>
       <p>If you did not create this account, please ignore this email.</p>
       <hr style="margin:24px 0;border:none;border-top:1px solid #ddd;">
       <p>Hola${company_name ? ' ' + company_name : ''},</p>
       <p>Confirmamos que tu cuenta de CargaSur se creó correctamente.</p>
       <ul>
         <li><strong>Correo:</strong> ${user.email}</li>
         <li><strong>Rol:</strong> ${roleLabel}</li>
       </ul>
       <p>Ya puedes iniciar sesión y empezar a usar la plataforma.</p>
       <p>Si tú no creaste esta cuenta, por favor ignora este correo.</p>`
    ).catch((err) => console.error('No se pudo enviar el correo de bienvenida:', err));

    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo crear la cuenta. Intenta de nuevo.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Faltan el correo o la contrasena.' });
  }
  try {
    const result = await query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Correo o contrasena incorrectos.' });
    }
    const valid = await comparePassword(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Correo o contrasena incorrectos.' });
    }
    const token = signToken(user);
    delete user.password_hash;
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo iniciar sesion.' });
  }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const result = await query(
    `SELECT id, email, role, company_name, phone, city, state, mc_number, vehicle_type,
            vehicle_make, vehicle_model, vehicle_year, vehicle_plate, license_number, license_state,
            ein_number, business_address, subscription_status, subscription_plan
     FROM users WHERE id = $1`,
    [req.user.id]
  );
  res.json({ user: result.rows[0] });
});

// Completar/actualizar el perfil despues del registro (vehiculo, licencia, EIN, direccion, etc.)
app.put('/api/auth/profile', requireAuth, async (req, res) => {
  const {
    company_name, phone, city, state,
    mc_number, vehicle_type, vehicle_make, vehicle_model, vehicle_year, vehicle_plate,
    license_number, license_state, ein_number, business_address,
  } = req.body;

  try {
    const result = await query(
      `UPDATE users SET
         company_name = $1, phone = $2, city = $3, state = $4,
         mc_number = $5, vehicle_type = $6, vehicle_make = $7, vehicle_model = $8,
         vehicle_year = $9, vehicle_plate = $10, license_number = $11, license_state = $12,
         ein_number = $13, business_address = $14
       WHERE id = $15
       RETURNING id, email, role, company_name, phone, city, state, mc_number, vehicle_type,
                 vehicle_make, vehicle_model, vehicle_year, vehicle_plate, license_number, license_state,
                 ein_number, business_address, subscription_status, subscription_plan`,
      [
        company_name || null, phone || null, city || null, state || null,
        mc_number || null, vehicle_type || null, vehicle_make || null, vehicle_model || null,
        vehicle_year || null, vehicle_plate || null, license_number || null, license_state || null,
        ein_number || null, business_address || null, req.user.id,
      ]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo actualizar el perfil.' });
  }
});

// Solicitar recuperacion de contrasena: siempre responde "ok" (exista o no
// el correo), para no revelar que correos estan registrados.
app.post('/api/auth/forgot-password', async (req, res) => {
  const email = (req.body.email || '').trim();
  if (!email) {
    return res.status(400).json({ error: 'Falta el correo electronico.' });
  }

  try {
    const result = await query('SELECT id, email FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

      await query(
        'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3',
        [token, expires, user.id]
      );

      const resetUrl = `${process.env.FRONTEND_URL}?reset_token=${token}`;
      await sendEmail(
        user.email,
        'Reset your CargaSur password / Recupera tu contraseña de CargaSur',
        `<p>We received a request to reset your password.</p>
         <p><a href="${resetUrl}">Click here to choose a new password</a></p>
         <p>This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
         <hr style="margin:24px 0;border:none;border-top:1px solid #ddd;">
         <p>Recibimos una solicitud para restablecer tu contraseña.</p>
         <p><a href="${resetUrl}">Haz clic aquí para elegir una nueva contraseña</a></p>
         <p>Este enlace expira en 1 hora. Si tú no pediste esto, puedes ignorar este correo.</p>`
      );
    }

    // Misma respuesta exista o no el correo, por seguridad.
    res.json({ ok: true, message: 'Si el correo esta registrado, te llegara un enlace para restablecer tu contrasena.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo procesar la solicitud.' });
  }
});

// Confirmar recuperacion: recibe el token del correo + la nueva contrasena.
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ error: 'Faltan datos: token y password.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'La contrasena debe tener al menos 6 caracteres.' });
  }

  try {
    const result = await query(
      'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expires > now()',
      [token]
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(400).json({ error: 'El enlace es invalido o ya expiro. Solicita uno nuevo.' });
    }

    const password_hash = await hashPassword(password);
    await query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [password_hash, user.id]
    );

    res.json({ ok: true, message: 'Contrasena actualizada correctamente.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo restablecer la contrasena.' });
  }
});

// ============================================================
// CARGAS (LOAD BOARD)
// ============================================================

// Publicar una carga nueva (solo shippers con membresia activa)
app.post('/api/loads', requireAuth, requireRole('shipper'), async (req, res) => {
  const me = (await query('SELECT subscription_status FROM users WHERE id = $1', [req.user.id])).rows[0];
  if (me.subscription_status !== 'active') {
    return res.status(402).json({ error: 'Necesitas una membresia de Shipper activa para publicar cargas.' });
  }

  const { origin, destination, equipment_type, rate, miles, pickup_date, payment_terms } = req.body;
  if (!origin || !destination || !equipment_type || !rate) {
    return res.status(400).json({ error: 'Faltan campos obligatorios: origin, destination, equipment_type, rate.' });
  }

  const result = await query(
    `INSERT INTO loads (shipper_id, origin, destination, equipment_type, rate, miles, pickup_date, payment_terms)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [req.user.id, origin, destination, equipment_type, rate, miles || null, pickup_date || null, payment_terms || null]
  );
  res.json({ load: result.rows[0] });
});

// Ver cargas disponibles (publico - cualquiera puede ver el tablero)
app.get('/api/loads', async (req, res) => {
  const { state, equipment_type } = req.query;
  const params = [];
  let sql = `
    SELECT loads.*, users.company_name AS shipper_name
    FROM loads
    JOIN users ON users.id = loads.shipper_id
    WHERE loads.status = 'open'
  `;
  if (equipment_type) {
    params.push(equipment_type);
    sql += ` AND loads.equipment_type = $${params.length}`;
  }
  if (state) {
    params.push('%' + state + '%');
    sql += ` AND (loads.origin ILIKE $${params.length} OR loads.destination ILIKE $${params.length})`;
  }
  sql += ' ORDER BY loads.created_at DESC';

  const result = await query(sql, params);
  res.json({ loads: result.rows });
});

// Ver las cargas propias de un shipper, con los datos del carrier asignado (si ya fue reservada)
app.get('/api/loads/mine', requireAuth, requireRole('shipper'), async (req, res) => {
  const result = await query(
    `SELECT
       loads.*,
       bookings.id AS booking_id,
       bookings.payment_status AS booking_payment_status,
       carrier.id AS carrier_id,
       carrier.company_name AS carrier_company_name,
       carrier.email AS carrier_email,
       carrier.phone AS carrier_phone,
       carrier.mc_number AS carrier_mc_number,
       carrier.vehicle_type AS carrier_vehicle_type,
       carrier.vehicle_make AS carrier_vehicle_make,
       carrier.vehicle_model AS carrier_vehicle_model,
       carrier.vehicle_year AS carrier_vehicle_year,
       carrier.vehicle_plate AS carrier_vehicle_plate,
       carrier.license_number AS carrier_license_number,
       carrier.license_state AS carrier_license_state
     FROM loads
     LEFT JOIN bookings ON bookings.load_id = loads.id AND bookings.payment_status = 'paid'
     LEFT JOIN users carrier ON carrier.id = bookings.carrier_id
     WHERE loads.shipper_id = $1
     ORDER BY loads.created_at DESC`,
    [req.user.id]
  );
  res.json({ loads: result.rows });
});

// Reservar una carga (solo carriers)
app.post('/api/loads/:id/book', requireAuth, requireRole('carrier'), async (req, res) => {
  const loadId = req.params.id;

  const load = (await query('SELECT * FROM loads WHERE id = $1', [loadId])).rows[0];
  if (!load) return res.status(404).json({ error: 'Esa carga no existe.' });
  if (load.status !== 'open') return res.status(409).json({ error: 'Esta carga ya no esta disponible.' });

  const carrier = (await query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];

  // Si tiene membresia mensual activa de carrier: reserva directa, sin cobro extra
  if (carrier.subscription_status === 'active' && carrier.subscription_plan === 'carrier_monthly') {
    await query('UPDATE loads SET status = $1 WHERE id = $2', ['booked', loadId]);
    await query(
      `INSERT INTO bookings (load_id, carrier_id, payment_type, payment_status, amount)
       VALUES ($1,$2,'subscription','paid',0)`,
      [loadId, req.user.id]
    );
    return res.json({ ok: true, message: 'Carga reservada con tu membresia mensual.' });
  }

  // Si no tiene membresia: cobrar por carga con Stripe Checkout
  try {
    const perLoadPrice = Number(process.env.PER_LOAD_PRICE_USD || 12);
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: carrier.email,
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `Reserva de carga #${load.id} (${load.origin} -> ${load.destination})`,
            },
            unit_amount: Math.round(perLoadPrice * 100),
          },
          quantity: 1,
        },
      ],
      success_url: `${process.env.FRONTEND_URL}/loads?booked=success&load=${load.id}`,
      cancel_url: `${process.env.FRONTEND_URL}/loads?booked=cancelled`,
      metadata: { load_id: String(load.id), carrier_id: String(req.user.id), kind: 'per_load' },
    });

    await query(
      `INSERT INTO bookings (load_id, carrier_id, payment_type, payment_status, amount, stripe_checkout_session_id)
       VALUES ($1,$2,'per_load','pending',$3,$4)`,
      [loadId, req.user.id, perLoadPrice, session.id]
    );

    res.json({ checkout_url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo iniciar el cobro de la reserva.' });
  }
});

// ============================================================
// MEMBRESIAS (Stripe Checkout + Billing Portal)
// ============================================================

app.post('/api/billing/subscribe', requireAuth, async (req, res) => {
  const { plan } = req.body; // 'shipper_monthly' | 'carrier_monthly'

  const priceId =
    plan === 'shipper_monthly' ? process.env.STRIPE_PRICE_SHIPPER_MONTHLY :
    plan === 'carrier_monthly' ? process.env.STRIPE_PRICE_CARRIER_MONTHLY :
    null;

  if (!priceId) {
    return res.status(400).json({ error: 'Plan invalido. Usa "shipper_monthly" o "carrier_monthly".' });
  }

  const user = (await query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];

  let customerId = user.stripe_customer_id;
  if (!customerId) {
    const customer = await stripe.customers.create({ email: user.email });
    customerId = customer.id;
    await query('UPDATE users SET stripe_customer_id = $1 WHERE id = $2', [customerId, user.id]);
  }

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    customer: customerId,
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${process.env.FRONTEND_URL}/billing?status=success`,
    cancel_url: `${process.env.FRONTEND_URL}/billing?status=cancelled`,
    metadata: { user_id: String(user.id), plan },
  });

  res.json({ checkout_url: session.url });
});

// Portal para que el usuario administre o cancele su propia membresia
app.post('/api/billing/portal', requireAuth, async (req, res) => {
  const user = (await query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];
  if (!user.stripe_customer_id) {
    return res.status(400).json({ error: 'Este usuario todavia no tiene una membresia.' });
  }
  const portalSession = await stripe.billingPortal.sessions.create({
    customer: user.stripe_customer_id,
    return_url: `${process.env.FRONTEND_URL}/account`,
  });
  res.json({ url: portalSession.url });
});

// ============================================================
// Funciones que procesan los eventos del webhook
// ============================================================

async function handleCheckoutCompleted(session) {
  if (session.mode === 'subscription') {
    const userId = session.metadata && session.metadata.user_id;
    const plan = session.metadata && session.metadata.plan;
    if (userId) {
      await query(
        `UPDATE users SET subscription_status = 'active', subscription_plan = $1, stripe_customer_id = $2 WHERE id = $3`,
        [plan, session.customer, userId]
      );
    }
  } else if (session.mode === 'payment') {
    const loadId = session.metadata && session.metadata.load_id;
    if (loadId) {
      await query('UPDATE bookings SET payment_status = $1 WHERE stripe_checkout_session_id = $2', ['paid', session.id]);
      await query('UPDATE loads SET status = $1 WHERE id = $2', ['booked', loadId]);
    }
  }
}

async function handleSubscriptionChange(subscription) {
  const status = subscription.status === 'active' ? 'active' : 'inactive';
  await query('UPDATE users SET subscription_status = $1 WHERE stripe_customer_id = $2', [status, subscription.customer]);
}

// ============================================================
app.get('/api/health', (req, res) => res.json({ ok: true, service: 'cargasur-api' }));

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log('CargaSur API escuchando en el puerto ' + port);
});
