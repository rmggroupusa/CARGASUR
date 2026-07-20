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
         vehicle_plate, license_number, license_state, ein_number, business_address, terms_accepted_at
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,now())
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
       <p><a href="https://app.cargasurfreight.com">https://app.cargasurfreight.com</a></p>
       <p>If you did not create this account, please ignore this email.</p>
       <hr style="margin:24px 0;border:none;border-top:1px solid #ddd;">
       <p>Hola${company_name ? ' ' + company_name : ''},</p>
       <p>Confirmamos que tu cuenta de CargaSur se creó correctamente.</p>
       <ul>
         <li><strong>Correo:</strong> ${user.email}</li>
         <li><strong>Rol:</strong> ${roleLabel}</li>
       </ul>
       <p>Ya puedes iniciar sesión y empezar a usar la plataforma.</p>
       <p><a href="https://app.cargasurfreight.com">https://app.cargasurfreight.com</a></p>
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
    if (user.deleted_at) {
      return res.status(401).json({ error: 'Esta cuenta fue eliminada.' });
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
            ein_number, business_address, attestation_signed, attestation_name, attestation_signed_at,
            subscription_status, subscription_plan, profile_photo_url, deleted_at
     FROM users WHERE id = $1`,
    [req.user.id]
  );
  const user = result.rows[0];
  if (!user || user.deleted_at) {
    return res.status(401).json({ error: 'Esta cuenta fue eliminada.' });
  }
  res.json({ user });
});

// Completar/actualizar el perfil despues del registro (vehiculo, licencia, EIN, direccion, etc.)
app.put('/api/auth/profile', requireAuth, async (req, res) => {
  const {
    company_name, phone, city, state,
    mc_number, vehicle_type, vehicle_make, vehicle_model, vehicle_year, vehicle_plate,
    license_number, license_state, ein_number, business_address,
    attestation_signed, attestation_name,
  } = req.body;

  try {
    // Si ya estaba firmada antes, no permitir "des-firmar"; si se envia una firma nueva, guardar fecha actual.
    const existing = (await query('SELECT attestation_signed, attestation_signed_at FROM users WHERE id = $1', [req.user.id])).rows[0];
    const willBeSigned = existing.attestation_signed || !!attestation_signed;
    const signedAt = existing.attestation_signed_at || (attestation_signed ? new Date() : null);

    const result = await query(
      `UPDATE users SET
         company_name = $1, phone = $2, city = $3, state = $4,
         mc_number = $5, vehicle_type = $6, vehicle_make = $7, vehicle_model = $8,
         vehicle_year = $9, vehicle_plate = $10, license_number = $11, license_state = $12,
         ein_number = $13, business_address = $14, attestation_signed = $15, attestation_name = $16,
         attestation_signed_at = $17
       WHERE id = $18
       RETURNING id, email, role, company_name, phone, city, state, mc_number, vehicle_type,
                 vehicle_make, vehicle_model, vehicle_year, vehicle_plate, license_number, license_state,
                 ein_number, business_address, attestation_signed, attestation_name, attestation_signed_at,
                 subscription_status, subscription_plan, profile_photo_url`,
      [
        company_name || null, phone || null, city || null, state || null,
        mc_number || null, vehicle_type || null, vehicle_make || null, vehicle_model || null,
        vehicle_year || null, vehicle_plate || null, license_number || null, license_state || null,
        ein_number || null, business_address || null, willBeSigned, attestation_name || existing.attestation_name || null,
        signedAt, req.user.id,
      ]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo actualizar el perfil.' });
  }
});

// Subir/actualizar la foto de perfil. Recibe una imagen en base64 (data URL),
// la sube al bucket "avatars" de Supabase Storage, y guarda la URL publica en el usuario.
app.put('/api/account/photo', requireAuth, async (req, res) => {
  const { image } = req.body;
  if (!image || typeof image !== 'string' || !image.startsWith('data:image/')) {
    return res.status(400).json({ error: 'Imagen invalida.' });
  }

  const match = image.match(/^data:image\/(png|jpeg|jpg|webp);base64,(.+)$/);
  if (!match) {
    return res.status(400).json({ error: 'Formato de imagen no soportado. Usa PNG, JPG o WEBP.' });
  }
  const ext = match[1] === 'jpg' ? 'jpeg' : match[1];
  const base64Data = match[2];
  const buffer = Buffer.from(base64Data, 'base64');

  // Limite de 3MB para evitar subidas gigantes
  if (buffer.length > 3 * 1024 * 1024) {
    return res.status(400).json({ error: 'La imagen no puede pesar mas de 3MB.' });
  }

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ error: 'Almacenamiento de imagenes no configurado en el servidor.' });
  }

  try {
    const fileName = `user-${req.user.id}-${Date.now()}.${ext}`;
    const uploadUrl = `${process.env.SUPABASE_URL}/storage/v1/object/avatars/${fileName}`;

    const uploadRes = await fetch(uploadUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
        'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
        'Content-Type': `image/${ext}`,
        'x-upsert': 'true',
      },
      body: buffer,
    });

    if (!uploadRes.ok) {
      const errText = await uploadRes.text();
      console.error('Supabase storage upload error:', errText);
      return res.status(500).json({ error: 'No se pudo subir la imagen.' });
    }

    const publicUrl = `${process.env.SUPABASE_URL}/storage/v1/object/public/avatars/${fileName}`;

    const result = await query(
      'UPDATE users SET profile_photo_url = $1 WHERE id = $2 RETURNING profile_photo_url',
      [publicUrl, req.user.id]
    );

    res.json({ profile_photo_url: result.rows[0].profile_photo_url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo subir la imagen.' });
  }
});

// Eliminar la cuenta propia. No se borra el historial de cargas/reservas/calificaciones
// (para no romper los registros de la otra parte), pero se anonimizan todos los datos
// personales, se cancela cualquier membresia activa en Stripe, y se bloquea el login.
app.delete('/api/account', requireAuth, async (req, res) => {
  try {
    const me = (await query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];
    if (!me) return res.status(404).json({ error: 'Usuario no encontrado.' });
    if (me.deleted_at) return res.status(400).json({ error: 'Esta cuenta ya fue eliminada.' });

    // No permitir eliminar la cuenta si hay una carga reservada (booked) sin resolver todavia,
    // ya sea como shipper (dueno de la carga) o como carrier (quien la reservo).
    const activeAsShipper = await query(
      `SELECT id FROM loads WHERE shipper_id = $1 AND status = 'booked'`,
      [req.user.id]
    );
    const activeAsCarrier = await query(
      `SELECT loads.id FROM bookings
       JOIN loads ON loads.id = bookings.load_id
       WHERE bookings.carrier_id = $1 AND bookings.payment_status = 'paid' AND loads.status = 'booked'`,
      [req.user.id]
    );
    if (activeAsShipper.rows.length || activeAsCarrier.rows.length) {
      return res.status(409).json({
        error: 'Tienes cargas reservadas sin entregar o cancelar todavia. Resuelve esas cargas antes de eliminar tu cuenta.',
      });
    }

    // Cancelar cualquier membresia activa en Stripe, para no seguir cobrando a una cuenta eliminada.
    if (me.stripe_customer_id) {
      try {
        const subs = await stripe.subscriptions.list({ customer: me.stripe_customer_id, status: 'active' });
        for (const sub of subs.data) {
          await stripe.subscriptions.cancel(sub.id);
        }
      } catch (stripeErr) {
        console.error('No se pudo cancelar la suscripcion de Stripe al eliminar la cuenta:', stripeErr);
      }
    }

    // Cancelar cualquier carga abierta (todavia no reservada) que quede huerfana al eliminar al shipper.
    await query(`UPDATE loads SET status = 'cancelled' WHERE shipper_id = $1 AND status IN ('open','pending_payment')`, [req.user.id]);

    // Anonimizar: se reemplazan todos los datos personales identificables por valores genericos.
    // Un password aleatorio e imposible de adivinar bloquea el login por partida doble (ademas del check de deleted_at).
    const unusablePasswordHash = await hashPassword(crypto.randomBytes(32).toString('hex'));
    await query(
      `UPDATE users SET
         email = $1, password_hash = $2, company_name = 'Deleted user', phone = NULL, city = NULL, state = NULL,
         mc_number = NULL, vehicle_type = NULL, vehicle_make = NULL, vehicle_model = NULL, vehicle_year = NULL,
         vehicle_plate = NULL, license_number = NULL, license_state = NULL, ein_number = NULL, business_address = NULL,
         profile_photo_url = NULL, stripe_customer_id = NULL, subscription_status = 'cancelled', subscription_plan = NULL,
         reset_token = NULL, reset_token_expires = NULL, deleted_at = now()
       WHERE id = $3`,
      [`deleted-user-${req.user.id}@cargasurfreight.com`, unusablePasswordHash, req.user.id]
    );

    res.json({ ok: true, message: 'Tu cuenta fue eliminada. Tus datos personales fueron anonimizados.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo eliminar la cuenta.' });
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
  const me = (await query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];

  const {
    origin, destination, equipment_type, rate, miles, pickup_date, delivery_date, payment_terms,
    weight, weight_unit, notes, origin_address, destination_address,
    origin_lat, origin_lng, destination_lat, destination_lng, wants_insurance,
    length_feet, length_inches,
  } = req.body;
  if (!origin || !destination || !equipment_type || !rate) {
    return res.status(400).json({ error: 'Faltan campos obligatorios: origin, destination, equipment_type, rate.' });
  }

  // Codigo de 6 digitos que el shipper debe entregar a la persona que recibe la carga en destino.
  // El carrier necesita este codigo para poder marcar la carga como entregada.
  const deliveryCode = String(Math.floor(100000 + Math.random() * 900000));

  const hasMembership = me.subscription_status === 'active';
  const initialStatus = hasMembership ? 'open' : 'pending_payment';

  const result = await query(
    `INSERT INTO loads (
       shipper_id, origin, destination, equipment_type, rate, miles, pickup_date, delivery_date, payment_terms,
       weight, weight_unit, notes, origin_address, destination_address,
       origin_lat, origin_lng, destination_lat, destination_lng, delivery_code, status, wants_insurance,
       length_feet, length_inches
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23) RETURNING *`,
    [
      req.user.id, origin, destination, equipment_type, rate, miles || null, pickup_date || null, delivery_date || null, payment_terms || null,
      weight || null, weight_unit || 'lb', notes || null, origin_address || null, destination_address || null,
      origin_lat || null, origin_lng || null, destination_lat || null, destination_lng || null, deliveryCode, initialStatus, !!wants_insurance,
      length_feet || null, length_inches || null,
    ]
  );
  const load = result.rows[0];

  if (hasMembership) {
    return res.json({ load });
  }

  // Sin membresia: cobrar una tarifa unica de publicacion (para shippers ocasionales, ej. una sola mudanza o entrega personal).
  try {
    const postFee = Number(process.env.SHIPPER_PER_LOAD_POST_PRICE_USD || 9.99);
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: me.email,
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `Publicacion de carga #${load.id} (${load.origin} -> ${load.destination})`,
            },
            unit_amount: Math.round(postFee * 100),
          },
          quantity: 1,
        },
      ],
      success_url: `${process.env.FRONTEND_URL}/?posted=success&load=${load.id}`,
      cancel_url: `${process.env.FRONTEND_URL}/?posted=cancelled&load=${load.id}`,
      metadata: { load_id: String(load.id), kind: 'shipper_post_fee' },
    });
    res.json({ load, checkout_url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'No se pudo iniciar el cobro de publicacion.' });
  }
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
  // El codigo de entrega es privado: solo el shipper que publico la carga debe verlo.
  const loads = result.rows.map(({ delivery_code, ...rest }) => rest);
  res.json({ loads });
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
       carrier.license_state AS carrier_license_state,
       carrier.attestation_signed AS carrier_attestation_signed,
       carrier.profile_photo_url AS carrier_photo_url,
       rating_summary.avg_rating AS carrier_avg_rating,
       rating_summary.review_count AS carrier_review_count,
       my_review.rating AS my_review_rating
     FROM loads
     LEFT JOIN bookings ON bookings.load_id = loads.id AND bookings.payment_status = 'paid'
     LEFT JOIN users carrier ON carrier.id = bookings.carrier_id
     LEFT JOIN LATERAL (
       SELECT AVG(rating)::numeric(3,1) AS avg_rating, COUNT(*) AS review_count
       FROM reviews WHERE reviews.carrier_id = carrier.id AND reviews.review_type = 'shipper_to_carrier'
     ) rating_summary ON true
     LEFT JOIN reviews my_review ON my_review.load_id = loads.id AND my_review.review_type = 'shipper_to_carrier'
     WHERE loads.shipper_id = $1
     ORDER BY loads.created_at DESC`,
    [req.user.id]
  );
  res.json({ loads: result.rows });
});

// Ver las cargas reservadas por el carrier (su historial/record)
app.get('/api/loads/booked', requireAuth, requireRole('carrier'), async (req, res) => {
  const result = await query(
    `SELECT
       loads.*,
       bookings.id AS booking_id,
       bookings.created_at AS booked_at,
       shipper.id AS shipper_id_ref,
       shipper.company_name AS shipper_company_name,
       shipper.email AS shipper_email,
       shipper.phone AS shipper_phone,
       shipper.business_address AS shipper_business_address,
       shipper.profile_photo_url AS shipper_photo_url,
       shipper_rating_summary.avg_rating AS shipper_avg_rating,
       shipper_rating_summary.review_count AS shipper_review_count,
       my_review.rating AS my_review_of_shipper_rating
     FROM bookings
     JOIN loads ON loads.id = bookings.load_id
     JOIN users shipper ON shipper.id = loads.shipper_id
     LEFT JOIN LATERAL (
       SELECT AVG(rating)::numeric(3,1) AS avg_rating, COUNT(*) AS review_count
       FROM reviews WHERE reviews.shipper_id = shipper.id AND reviews.review_type = 'carrier_to_shipper'
     ) shipper_rating_summary ON true
     LEFT JOIN reviews my_review ON my_review.load_id = loads.id AND my_review.review_type = 'carrier_to_shipper'
     WHERE bookings.carrier_id = $1 AND bookings.payment_status = 'paid'
     ORDER BY bookings.created_at DESC`,
    [req.user.id]
  );
  // El codigo de entrega es privado: el carrier no debe verlo en la respuesta,
  // debe pedirselo directamente a la persona que recibe la carga.
  const loads = result.rows.map(({ delivery_code, ...rest }) => rest);
  res.json({ loads });
});

// Cancelar la asignacion de una carga ya reservada (solo el shipper dueno, ej. si al verificar el FMCSA no le da confianza el carrier).
// La carga regresa al tablero como disponible para que otro carrier la reserve.
app.post('/api/loads/:id/cancel-booking', requireAuth, requireRole('shipper'), async (req, res) => {
  const loadId = req.params.id;
  const load = (await query('SELECT * FROM loads WHERE id = $1', [loadId])).rows[0];
  if (!load) return res.status(404).json({ error: 'Esa carga no existe.' });
  if (load.shipper_id !== req.user.id) {
    return res.status(403).json({ error: 'No puedes cancelar una carga que no es tuya.' });
  }
  if (load.status !== 'booked') {
    return res.status(409).json({ error: 'Solo puedes cancelar la asignacion de cargas que esten reservadas (sin entregar todavia).' });
  }

  const booking = (await query(
    `SELECT * FROM bookings WHERE load_id = $1 AND payment_status = 'paid' ORDER BY created_at DESC LIMIT 1`,
    [loadId]
  )).rows[0];

  await query('UPDATE loads SET status = $1 WHERE id = $2', ['open', loadId]);
  if (booking) {
    await query('UPDATE bookings SET payment_status = $1 WHERE id = $2', ['cancelled', booking.id]);
    createNotification(booking.carrier_id, loadId, 'booking_cancelled').catch((err) => console.error(err));
  }

  const wasPerLoad = booking && booking.payment_type === 'per_load';
  res.json({
    ok: true,
    message: wasPerLoad
      ? 'Asignacion cancelada. La carga volvio a estar disponible. Nota: el carrier ya habia pagado por esta carga (per-load); si corresponde un reembolso, procesalo manualmente desde tu Stripe Dashboard.'
      : 'Asignacion cancelada. La carga volvio a estar disponible.',
  });
});

// Marcar una carga como entregada (solo el carrier que la reservo)
app.post('/api/loads/:id/deliver', requireAuth, requireRole('carrier'), async (req, res) => {
  const loadId = req.params.id;
  const { delivery_code } = req.body;
  const load = (await query('SELECT * FROM loads WHERE id = $1', [loadId])).rows[0];
  if (!load) return res.status(404).json({ error: 'Esa carga no existe.' });
  if (load.status !== 'booked') {
    return res.status(409).json({ error: 'Solo puedes marcar como entregadas las cargas que esten asignadas.' });
  }

  const booking = (await query(
    `SELECT * FROM bookings WHERE load_id = $1 AND carrier_id = $2 AND payment_status = 'paid'`,
    [loadId, req.user.id]
  )).rows[0];
  if (!booking) {
    return res.status(403).json({ error: 'Esta carga no esta asignada a ti.' });
  }

  if (load.delivery_code) {
    if (!delivery_code || String(delivery_code).trim() !== String(load.delivery_code).trim()) {
      return res.status(400).json({ error: 'Codigo de entrega incorrecto. Pidele el codigo a la persona que recibio la carga.' });
    }
  }

  await query('UPDATE loads SET status = $1 WHERE id = $2', ['delivered', loadId]);
  createNotification(load.shipper_id, loadId, 'load_delivered').catch((err) => console.error(err));

  res.json({ ok: true, message: 'Carga marcada como entregada.' });
});

// Calificar a un carrier despues de que se entrego la carga (solo el shipper dueno de la carga)
app.post('/api/loads/:id/review', requireAuth, requireRole('shipper'), async (req, res) => {
  const loadId = req.params.id;
  const { rating, comment } = req.body;

  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'La calificacion debe ser entre 1 y 5.' });
  }

  const load = (await query('SELECT * FROM loads WHERE id = $1', [loadId])).rows[0];
  if (!load) return res.status(404).json({ error: 'Esa carga no existe.' });
  if (load.shipper_id !== req.user.id) {
    return res.status(403).json({ error: 'No puedes calificar una carga que no es tuya.' });
  }
  if (load.status !== 'delivered') {
    return res.status(409).json({ error: 'Solo puedes calificar cargas que ya fueron entregadas.' });
  }

  const booking = (await query('SELECT * FROM bookings WHERE load_id = $1 AND payment_status = \'paid\'', [loadId])).rows[0];
  if (!booking) return res.status(404).json({ error: 'No se encontro el carrier de esta carga.' });

  const existing = await query('SELECT id FROM reviews WHERE load_id = $1 AND review_type = \'shipper_to_carrier\'', [loadId]);
  if (existing.rows.length) {
    return res.status(409).json({ error: 'Ya calificaste esta carga.' });
  }

  await query(
    `INSERT INTO reviews (load_id, shipper_id, carrier_id, review_type, rating, comment) VALUES ($1,$2,$3,'shipper_to_carrier',$4,$5)`,
    [loadId, req.user.id, booking.carrier_id, rating, comment || null]
  );

  res.json({ ok: true, message: 'Calificacion guardada correctamente.' });
});

// Calificar al shipper despues de entregar la carga (solo el carrier que la entrego)
app.post('/api/loads/:id/review-shipper', requireAuth, requireRole('carrier'), async (req, res) => {
  const loadId = req.params.id;
  const { rating, comment } = req.body;

  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'La calificacion debe ser entre 1 y 5.' });
  }

  const load = (await query('SELECT * FROM loads WHERE id = $1', [loadId])).rows[0];
  if (!load) return res.status(404).json({ error: 'Esa carga no existe.' });
  if (load.status !== 'delivered') {
    return res.status(409).json({ error: 'Solo puedes calificar cargas que ya fueron entregadas.' });
  }

  const booking = (await query(
    `SELECT * FROM bookings WHERE load_id = $1 AND carrier_id = $2 AND payment_status = 'paid'`,
    [loadId, req.user.id]
  )).rows[0];
  if (!booking) return res.status(403).json({ error: 'Esta carga no esta asignada a ti.' });

  const existing = await query('SELECT id FROM reviews WHERE load_id = $1 AND review_type = \'carrier_to_shipper\'', [loadId]);
  if (existing.rows.length) {
    return res.status(409).json({ error: 'Ya calificaste esta carga.' });
  }

  await query(
    `INSERT INTO reviews (load_id, shipper_id, carrier_id, review_type, rating, comment) VALUES ($1,$2,$3,'carrier_to_shipper',$4,$5)`,
    [loadId, load.shipper_id, req.user.id, rating, comment || null]
  );

  res.json({ ok: true, message: 'Calificacion guardada correctamente.' });
});

// Ver el resumen de calificaciones de un carrier (promedio + total de entregas)
app.get('/api/carriers/:id/rating', async (req, res) => {
  const carrierId = req.params.id;
  const result = await query(
    `SELECT
       COALESCE(AVG(rating), 0) AS avg_rating,
       COUNT(*) AS review_count
     FROM reviews WHERE carrier_id = $1 AND review_type = 'shipper_to_carrier'`,
    [carrierId]
  );
  const deliveredCount = await query(
    `SELECT COUNT(*) AS delivered_count
     FROM bookings
     JOIN loads ON loads.id = bookings.load_id
     WHERE bookings.carrier_id = $1 AND loads.status = 'delivered' AND bookings.payment_status = 'paid'`,
    [carrierId]
  );
  res.json({
    avg_rating: parseFloat(result.rows[0].avg_rating).toFixed(1),
    review_count: parseInt(result.rows[0].review_count, 10),
    delivered_count: parseInt(deliveredCount.rows[0].delivered_count, 10),
  });
});

// Ver el resumen de calificaciones de un shipper (promedio + total de cargas entregadas)
app.get('/api/shippers/:id/rating', async (req, res) => {
  const shipperId = req.params.id;
  const result = await query(
    `SELECT
       COALESCE(AVG(rating), 0) AS avg_rating,
       COUNT(*) AS review_count
     FROM reviews WHERE shipper_id = $1 AND review_type = 'carrier_to_shipper'`,
    [shipperId]
  );
  const deliveredCount = await query(
    `SELECT COUNT(*) AS delivered_count FROM loads WHERE shipper_id = $1 AND status = 'delivered'`,
    [shipperId]
  );
  res.json({
    avg_rating: parseFloat(result.rows[0].avg_rating).toFixed(1),
    review_count: parseInt(result.rows[0].review_count, 10),
    delivered_count: parseInt(deliveredCount.rows[0].delivered_count, 10),
  });
});

// Ranking publico de los mejores carriers y shippers (por calificacion promedio)
app.get('/api/rankings', async (req, res) => {
  const role = req.query.role === 'shipper' ? 'shipper' : 'carrier';

  if (role === 'carrier') {
    const result = await query(
      `SELECT
         users.id, users.company_name, users.email,
         COALESCE(AVG(reviews.rating), 0)::numeric(3,1) AS avg_rating,
         COUNT(reviews.id) AS review_count
       FROM users
       JOIN reviews ON reviews.carrier_id = users.id AND reviews.review_type = 'shipper_to_carrier'
       WHERE users.role = 'carrier'
       GROUP BY users.id
       HAVING COUNT(reviews.id) >= 1
       ORDER BY avg_rating DESC, review_count DESC
       LIMIT 10`
    );
    return res.json({ rankings: result.rows });
  }

  const result = await query(
    `SELECT
       users.id, users.company_name, users.email,
       COALESCE(AVG(reviews.rating), 0)::numeric(3,1) AS avg_rating,
       COUNT(reviews.id) AS review_count
     FROM users
     JOIN reviews ON reviews.shipper_id = users.id AND reviews.review_type = 'carrier_to_shipper'
     WHERE users.role = 'shipper'
     GROUP BY users.id
     HAVING COUNT(reviews.id) >= 1
     ORDER BY avg_rating DESC, review_count DESC
     LIMIT 10`
  );
  res.json({ rankings: result.rows });
});

// Reservar una carga (solo carriers)
// Editar una carga propia (solo shippers, y solo si sigue abierta)
app.put('/api/loads/:id', requireAuth, requireRole('shipper'), async (req, res) => {
  const loadId = req.params.id;
  const load = (await query('SELECT * FROM loads WHERE id = $1', [loadId])).rows[0];
  if (!load) return res.status(404).json({ error: 'Esa carga no existe.' });
  if (load.shipper_id !== req.user.id) {
    return res.status(403).json({ error: 'No puedes editar una carga que no es tuya.' });
  }
  if (load.status !== 'open') {
    return res.status(409).json({ error: 'Solo puedes editar cargas que sigan abiertas (sin reservar).' });
  }

  const {
    origin, destination, equipment_type, rate, miles, pickup_date, delivery_date, payment_terms,
    weight, weight_unit, notes, origin_address, destination_address,
    origin_lat, origin_lng, destination_lat, destination_lng, wants_insurance,
    length_feet, length_inches,
  } = req.body;
  if (!origin || !destination || !equipment_type || !rate) {
    return res.status(400).json({ error: 'Faltan campos obligatorios: origin, destination, equipment_type, rate.' });
  }

  const result = await query(
    `UPDATE loads SET origin=$1, destination=$2, equipment_type=$3, rate=$4, miles=$5, pickup_date=$6, delivery_date=$7, payment_terms=$8,
            weight=$9, weight_unit=$10, notes=$11, origin_address=$12, destination_address=$13,
            origin_lat=$14, origin_lng=$15, destination_lat=$16, destination_lng=$17, wants_insurance=$18,
            length_feet=$19, length_inches=$20
     WHERE id=$21 RETURNING *`,
    [
      origin, destination, equipment_type, rate, miles || null, pickup_date || null, delivery_date || null, payment_terms || null,
      weight || null, weight_unit || 'lb', notes || null, origin_address || null, destination_address || null,
      origin_lat || null, origin_lng || null, destination_lat || null, destination_lng || null, !!wants_insurance,
      length_feet || null, length_inches || null, loadId,
    ]
  );
  res.json({ load: result.rows[0] });
});

// Cancelar (eliminar) una carga propia - solo si sigue abierta, sin reservar
app.delete('/api/loads/:id', requireAuth, requireRole('shipper'), async (req, res) => {
  const loadId = req.params.id;
  const load = (await query('SELECT * FROM loads WHERE id = $1', [loadId])).rows[0];
  if (!load) return res.status(404).json({ error: 'Esa carga no existe.' });
  if (load.shipper_id !== req.user.id) {
    return res.status(403).json({ error: 'No puedes eliminar una carga que no es tuya.' });
  }
  if (load.status !== 'open') {
    return res.status(409).json({ error: 'Solo puedes eliminar cargas que sigan abiertas (sin reservar).' });
  }

  await query('UPDATE loads SET status = $1 WHERE id = $2', ['cancelled', loadId]);
  res.json({ ok: true, message: 'Carga eliminada correctamente.' });
});

async function createNotification(userId, loadId, type){
  try {
    await query(
      `INSERT INTO notifications (user_id, load_id, type) VALUES ($1,$2,$3)`,
      [userId, loadId, type]
    );
  } catch (err) {
    console.error('No se pudo crear la notificacion:', err);
  }
}

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
    sendLoadAssignedEmail(req.user.id, loadId).catch((err) => console.error(err));
    createNotification(load.shipper_id, loadId, 'load_assigned').catch((err) => console.error(err));
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
      success_url: `${process.env.FRONTEND_URL}/?booked=success&load=${load.id}`,
      cancel_url: `${process.env.FRONTEND_URL}/?booked=cancelled`,
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

  if (user.subscription_status === 'active') {
    return res.status(400).json({ error: 'Ya tienes una membresia activa. Usa "Manage my membership" para administrarla o cambiarla.' });
  }

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
    success_url: `${process.env.FRONTEND_URL}/?status=success`,
    cancel_url: `${process.env.FRONTEND_URL}/?status=cancelled`,
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
    return_url: `${process.env.FRONTEND_URL}/?section=account`,
  });
  res.json({ url: portalSession.url });
});

// ============================================================
// Funciones que procesan los eventos del webhook
// ============================================================

function escapeHtmlServer(str){
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function formatDateServer(d){
  if (!d) return 'N/A';
  const str = (d instanceof Date) ? d.toISOString() : String(d);
  return str.split('T')[0];
}

async function sendLoadAssignedEmail(carrierId, loadId){
  try {
    const result = await query(
      `SELECT loads.*, carrier.email AS carrier_email,
              shipper.company_name AS shipper_company_name, shipper.phone AS shipper_phone,
              shipper.email AS shipper_email, shipper.business_address AS shipper_business_address
       FROM loads
       JOIN users carrier ON carrier.id = $1
       JOIN users shipper ON shipper.id = loads.shipper_id
       WHERE loads.id = $2`,
      [carrierId, loadId]
    );
    const row = result.rows[0];
    if (!row) return;

    const pickup = formatDateServer(row.pickup_date);
    const delivery = formatDateServer(row.delivery_date);
    const rate = '$' + Number(row.rate || 0).toFixed(2);
    const weightStr = row.weight ? `${row.weight} ${row.weight_unit || 'lb'}` : 'N/A';

    await sendEmail(
      row.carrier_email,
      'Load assigned to you / Carga asignada a ti — CargaSur',
      `<p>You've been assigned the following load:</p>
       <ul>
         <li><strong>Route:</strong> ${escapeHtmlServer(row.origin)} &rarr; ${escapeHtmlServer(row.destination)}</li>
         <li><strong>Equipment:</strong> ${escapeHtmlServer(row.equipment_type)}</li>
         <li><strong>Miles:</strong> ${row.miles || 'N/A'}</li>
         <li><strong>Weight:</strong> ${weightStr}</li>
         <li><strong>Pickup date:</strong> ${pickup}</li>
         <li><strong>Delivery date:</strong> ${delivery}</li>
         <li><strong>Rate:</strong> ${rate}</li>
         <li><strong>Payment terms:</strong> ${escapeHtmlServer(row.payment_terms) || 'N/A'}</li>
         ${row.notes ? `<li><strong>Notes:</strong> ${escapeHtmlServer(row.notes)}</li>` : ''}
       </ul>
       <p><strong>Shipper contact:</strong></p>
       <ul>
         <li>Company: ${escapeHtmlServer(row.shipper_company_name) || 'N/A'}</li>
         <li>Phone: ${escapeHtmlServer(row.shipper_phone) || 'N/A'}</li>
         <li>Email: ${escapeHtmlServer(row.shipper_email)}</li>
         <li>Address: ${escapeHtmlServer(row.shipper_business_address) || 'N/A'}</li>
       </ul>
       <hr style="margin:24px 0;border:none;border-top:1px solid #ddd;">
       <p>Se te asigno la siguiente carga:</p>
       <ul>
         <li><strong>Ruta:</strong> ${escapeHtmlServer(row.origin)} &rarr; ${escapeHtmlServer(row.destination)}</li>
         <li><strong>Equipo:</strong> ${escapeHtmlServer(row.equipment_type)}</li>
         <li><strong>Millas:</strong> ${row.miles || 'N/A'}</li>
         <li><strong>Peso:</strong> ${weightStr}</li>
         <li><strong>Fecha de recoleccion:</strong> ${pickup}</li>
         <li><strong>Fecha de entrega:</strong> ${delivery}</li>
         <li><strong>Tarifa:</strong> ${rate}</li>
         <li><strong>Terminos de pago:</strong> ${escapeHtmlServer(row.payment_terms) || 'N/A'}</li>
         ${row.notes ? `<li><strong>Notas:</strong> ${escapeHtmlServer(row.notes)}</li>` : ''}
       </ul>
       <p><strong>Contacto del shipper:</strong></p>
       <ul>
         <li>Empresa: ${escapeHtmlServer(row.shipper_company_name) || 'N/A'}</li>
         <li>Telefono: ${escapeHtmlServer(row.shipper_phone) || 'N/A'}</li>
         <li>Correo: ${escapeHtmlServer(row.shipper_email)}</li>
         <li>Direccion: ${escapeHtmlServer(row.shipper_business_address) || 'N/A'}</li>
       </ul>`
    );
  } catch (err) {
    console.error('No se pudo enviar el correo de carga asignada:', err);
  }
}

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
    const kind = session.metadata && session.metadata.kind;
    const loadId = session.metadata && session.metadata.load_id;

    if (kind === 'shipper_post_fee') {
      // El shipper pago la tarifa de publicacion unica: la carga pasa de "pending_payment" a "open" (visible en el tablero).
      if (loadId) {
        await query(`UPDATE loads SET status = 'open' WHERE id = $1 AND status = 'pending_payment'`, [loadId]);
      }
      return;
    }

    const carrierId = session.metadata && session.metadata.carrier_id;
    if (loadId) {
      await query('UPDATE bookings SET payment_status = $1 WHERE stripe_checkout_session_id = $2', ['paid', session.id]);
      const loadResult = await query('UPDATE loads SET status = $1 WHERE id = $2 RETURNING shipper_id', ['booked', loadId]);
      if (carrierId) {
        sendLoadAssignedEmail(carrierId, loadId).catch((err) => console.error(err));
      }
      if (loadResult.rows[0]) {
        createNotification(loadResult.rows[0].shipper_id, loadId, 'load_assigned').catch((err) => console.error(err));
      }
    }
  }
}

async function handleSubscriptionChange(subscription) {
  const status = subscription.status === 'active' ? 'active' : 'inactive';
  await query('UPDATE users SET subscription_status = $1 WHERE stripe_customer_id = $2', [status, subscription.customer]);
}

// ============================================================
// NOTIFICACIONES
// ============================================================

app.get('/api/notifications', requireAuth, async (req, res) => {
  const result = await query(
    `SELECT notifications.*, loads.origin, loads.destination
     FROM notifications
     JOIN loads ON loads.id = notifications.load_id
     WHERE notifications.user_id = $1
     ORDER BY notifications.created_at DESC
     LIMIT 30`,
    [req.user.id]
  );
  res.json({ notifications: result.rows });
});

app.post('/api/notifications/:id/read', requireAuth, async (req, res) => {
  await query(
    'UPDATE notifications SET is_read = true WHERE id = $1 AND user_id = $2',
    [req.params.id, req.user.id]
  );
  res.json({ ok: true });
});

app.post('/api/notifications/read-all', requireAuth, async (req, res) => {
  await query('UPDATE notifications SET is_read = true WHERE user_id = $1', [req.user.id]);
  res.json({ ok: true });
});

// ============================================================
app.get('/api/health', (req, res) => res.json({ ok: true, service: 'cargasur-api' }));

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log('CargaSur API escuchando en el puerto ' + port);
});
