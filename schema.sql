-- Esquema de base de datos para CargaSur
-- Ejecuta este archivo una vez en tu base de datos Postgres antes de arrancar el servidor.

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('shipper','carrier')),
  company_name TEXT,
  phone TEXT,
  city TEXT,
  state TEXT,
  mc_number TEXT,
  stripe_customer_id TEXT,
  subscription_status TEXT NOT NULL DEFAULT 'none',   -- none | active | inactive
  subscription_plan TEXT,                              -- shipper_monthly | carrier_monthly
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS loads (
  id SERIAL PRIMARY KEY,
  shipper_id INTEGER NOT NULL REFERENCES users(id),
  origin TEXT NOT NULL,
  destination TEXT NOT NULL,
  equipment_type TEXT NOT NULL,
  rate NUMERIC(10,2) NOT NULL,
  miles INTEGER,
  pickup_date DATE,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','booked','cancelled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bookings (
  id SERIAL PRIMARY KEY,
  load_id INTEGER NOT NULL REFERENCES loads(id),
  carrier_id INTEGER NOT NULL REFERENCES users(id),
  payment_type TEXT NOT NULL CHECK (payment_type IN ('subscription','per_load')),
  payment_status TEXT NOT NULL DEFAULT 'pending' CHECK (payment_status IN ('pending','paid','failed')),
  stripe_checkout_session_id TEXT,
  amount NUMERIC(10,2),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_loads_status ON loads(status);
CREATE INDEX IF NOT EXISTS idx_loads_shipper ON loads(shipper_id);
CREATE INDEX IF NOT EXISTS idx_bookings_load ON bookings(load_id);
CREATE INDEX IF NOT EXISTS idx_bookings_carrier ON bookings(carrier_id);
