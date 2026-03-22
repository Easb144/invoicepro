-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  premium BOOLEAN DEFAULT FALSE,
  logo_base64 TEXT,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  reset_token TEXT,
  reset_expiry BIGINT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tabela de faturas
CREATE TABLE IF NOT EXISTS invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  invoice_number TEXT,
  company_name TEXT,
  company_email TEXT,
  company_vat TEXT,
  client_name TEXT,
  client_email TEXT,
  client_vat TEXT,
  client_address TEXT,
  due_date TEXT,
  po_number TEXT,
  tax_rate NUMERIC DEFAULT 23,
  currency TEXT DEFAULT 'USD',
  items JSONB DEFAULT '[]',
  subtotal NUMERIC DEFAULT 0,
  total_tax NUMERIC DEFAULT 0,
  total NUMERIC DEFAULT 0,
  symbol TEXT DEFAULT '$',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoices_user_id ON invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Habilita RLS (opcional, mas seguro)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;

-- Políticas (para simplificar, permitir tudo com service_role)
CREATE POLICY "service_role bypass" ON users FOR ALL USING (true);
CREATE POLICY "service_role bypass" ON invoices FOR ALL USING (true);