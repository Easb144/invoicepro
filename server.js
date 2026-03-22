require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const { createClient } = require('@supabase/supabase-js');
const paypal = require('@paypal/checkout-server-sdk');
const { Resend } = require('resend');
// Stripe removido — apenas PayPal

const app = express();
const PORT = process.env.PORT || 3002;
const SECRET = process.env.JWT_SECRET;

// ========== CLIENTES ==========
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);

// ========== PAYPAL ==========
function environment() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
  return process.env.PAYPAL_MODE === 'live'
    ? new paypal.core.LiveEnvironment(clientId, clientSecret)
    : new paypal.core.SandboxEnvironment(clientId, clientSecret);
}

function paypalClient() {
  return new paypal.core.PayPalHttpClient(environment());
}

// ========== MIDDLEWARE ==========
app.use(express.static('public'));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));

// LOG DE TODAS AS REQUISIÇÕES
app.use((req, res, next) => {
  console.log(`\n🌐 ${req.method} ${req.url}`);
  console.log('Headers:', req.headers);
  if (req.body && Object.keys(req.body).length) {
    console.log('Body:', JSON.stringify(req.body, null, 2).substring(0, 200));
  }
  next();
});

// ========== AUTH MIDDLEWARE ==========
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token não fornecido.' });
  try {
    req.user = jwt.verify(authHeader.replace('Bearer ', ''), SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, premium: user.premium },
    SECRET,
    { expiresIn: '30d' }
  );
}

// ========== ROTAS DE AUTENTICAÇÃO ==========
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha obrigatórios.' });
    if (password.length < 8) return res.status(400).json({ error: 'A senha deve ter no mínimo 8 caracteres.' });

    const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single();
    if (existing) return res.status(409).json({ error: 'Este e-mail já está registado.' });

    const hash = await bcrypt.hash(password, 12);
    const { data: user, error: insertError } = await supabase
      .from('users')
      .insert({ email: email.toLowerCase(), password_hash: hash, invoice_count: 0 })
      .select('id, email, premium')
      .single();

    if (insertError) {
      console.error('Erro ao inserir:', insertError);
      return res.status(500).json({ error: 'Erro ao criar conta.' });
    }

    res.json({
      token: makeToken(user),
      user: { id: user.id, email: user.email, premium: false, invoiceCount: 0 }
    });
  } catch (err) {
    console.error('Erro no registro:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha obrigatórios.' });

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) return res.status(401).json({ error: 'Credenciais inválidas.' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciais inválidas.' });

    const { count } = await supabase
      .from('invoices')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', user.id);

    res.json({
      token: makeToken(user),
      user: {
        id: user.id,
        email: user.email,
        premium: user.premium,
        invoiceCount: count || 0,
        logo: user.logo_base64
      }
    });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { data: user } = await supabase
      .from('users')
      .select('id, email, premium, logo_base64, invoice_count')
      .eq('id', req.user.id)
      .single();
    if (!user) return res.status(404).json({ error: 'Utilizador não encontrado.' });
    const { count } = await supabase
      .from('invoices')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', user.id);
    res.json({ ...user, invoiceCount: count || 0 });
  } catch (err) {
    console.error('Erro em /auth/me:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ========== ROTA DE RECUPERAÇÃO DE SENHA ==========
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'E-mail obrigatório.' });

    const { data: user } = await supabase
      .from('users')
      .select('id, email')
      .eq('email', email.toLowerCase())
      .single();

    if (!user) return res.json({ message: 'Se o e-mail estiver registado, receberá um link em breve.' });

    const token = uuid().replace(/-/g, '') + Date.now().toString(36);
    const expiry = Date.now() + 3_600_000;

    await supabase
      .from('users')
      .update({ reset_token: token, reset_expiry: expiry })
      .eq('id', user.id);

    const resetLink = `${process.env.FRONTEND_URL}?reset=${token}`;
    
    await resend.emails.send({
      from: process.env.EMAIL_FROM || 'InvoicePro <onboarding@resend.dev>',
      to: [user.email],
      subject: 'Recuperar palavra-passe - InvoicePro',
      html: `<p>Clique no link para redefinir sua senha: <a href="${resetLink}">${resetLink}</a></p>`
    });

    res.json({ message: 'Se o e-mail estiver registado, receberá um link em breve.' });
  } catch (err) {
    console.error('Erro:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token e senha obrigatórios.' });
    if (password.length < 8) return res.status(400).json({ error: 'A senha deve ter no mínimo 8 caracteres.' });

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('reset_token', token)
      .gt('reset_expiry', Date.now())
      .single();

    if (!user) return res.status(400).json({ error: 'Token inválido ou expirado.' });

    const hash = await bcrypt.hash(password, 12);
    await supabase
      .from('users')
      .update({ password_hash: hash, reset_token: null, reset_expiry: null })
      .eq('id', user.id);

    res.json({ message: 'Palavra-passe redefinida com sucesso.' });
  } catch (err) {
    console.error('Erro:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ========== ROTAS DE FATURAS ==========
app.get('/api/invoices', auth, async (req, res) => {
  try {
    const { data } = await supabase
      .from('invoices')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    res.json(data || []);
  } catch (err) {
    console.error('Erro:', err);
    res.status(500).json({ error: 'Erro ao carregar faturas.' });
  }
});

app.post('/api/invoices', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('premium').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'Utilizador não encontrado.' });

    if (!user.premium) {
      const { count } = await supabase
        .from('invoices')
        .select('*', { count: 'exact', head: true })
        .eq('user_id', req.user.id);
      if (count >= 2) return res.status(403).json({ error: 'Limite de 2 faturas grátis atingido.' });
    }

    const { data, error } = await supabase.from('invoices').insert({
      user_id: req.user.id,
      invoice_number: req.body.invoice_number,
      company_name: req.body.company_name,
      company_email: req.body.company_email,
      company_vat: req.body.company_vat,
      client_name: req.body.client_name,
      client_email: req.body.client_email,
      client_vat: req.body.client_vat,
      client_address: req.body.client_address,
      due_date: req.body.due_date,
      po_number: req.body.po_number,
      tax_rate: req.body.tax_rate,
      currency: req.body.currency,
      items: req.body.items,
      subtotal: req.body.subtotal,
      total_tax: req.body.total_tax,
      total: req.body.total,
      symbol: req.body.symbol,
    }).select().single();

    if (error) {
      console.error('Erro:', error);
      return res.status(500).json({ error: 'Erro ao guardar fatura.' });
    }

    res.json(data);
  } catch (err) {
    console.error('Erro:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

app.delete('/api/invoices/:id', auth, async (req, res) => {
  try {
    const { data: invoice } = await supabase.from('invoices').select('user_id').eq('id', req.params.id).single();
    if (!invoice || invoice.user_id !== req.user.id) return res.status(404).json({ error: 'Fatura não encontrada.' });
    await supabase.from('invoices').delete().eq('id', req.params.id);
    res.json({ message: 'Fatura eliminada.' });
  } catch (err) {
    console.error('Erro:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ========== ENVIO DE EMAIL ==========
app.post('/api/invoices/send', auth, async (req, res) => {
  console.log('\n📧 ROTA DE EMAIL ACESSADA');
  console.log('Usuário:', req.user?.email);
  
  try {
    const { to, subject, message, invoiceData } = req.body;

    console.log('Dados recebidos:', { to, subject, message, invoiceData });

    if (!to) {
      return res.status(400).json({ error: 'Email do destinatário é obrigatório' });
    }

    // HTML do email
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #0f2b5c; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .invoice-box { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; }
          h1 { margin: 0; }
          .total { color: #c79a3e; font-size: 24px; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>InvoicePro</h1>
          </div>
          <div class="content">
            <p>${message || 'Segue a sua fatura:'}</p>
            
            <div class="invoice-box">
              <h3>Detalhes da Fatura</h3>
              <p><strong>Número:</strong> ${invoiceData?.invoice_number || 'N/A'}</p>
              <p><strong>Cliente:</strong> ${invoiceData?.client_name || 'N/A'}</p>
              <p><strong>Total:</strong> <span class="total">${invoiceData?.symbol || '$'}${invoiceData?.total || 0}</span></p>
            </div>
            
            <p>Obrigado pela preferência!</p>
          </div>
          <div class="footer">
            <p>© 2025 InvoicePro - Faturação profissional para freelancers</p>
          </div>
        </div>
      </body>
      </html>
    `;

    console.log('📤 Enviando via Resend...');

    const { data, error } = await resend.emails.send({
      from: process.env.EMAIL_FROM || 'InvoicePro <onboarding@resend.dev>',
      to: [to],
      subject: subject || 'Sua fatura do InvoicePro',
      html: html
    });

    if (error) {
      console.error('❌ Erro Resend:', error);
      return res.status(500).json({ error: error.message });
    }

    console.log('✅ Email enviado! ID:', data.id);
    res.json({ success: true, id: data.id });

  } catch (error) {
    console.error('❌ Erro:', error);
    res.status(500).json({ error: error.message });
  }
});

// ========== LOGOTIPO ==========
app.put('/api/user/logo', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('premium').eq('id', req.user.id).single();
    if (!user?.premium) return res.status(403).json({ error: 'Logótipo exclusivo do plano Pro.' });
    await supabase.from('users').update({ logo_base64: req.body.logo }).eq('id', req.user.id);
    res.json({ message: 'Logótipo guardado.' });
  } catch (err) {
    console.error('Erro:', err);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ========== PAYPAL — pagamento mensal recorrente ==========
// Usamos Orders API com renovação manual via webhook ou verificação periódica
// Para subscrição real, o utilizador paga $10/mês e tu verificas manualmente ou por webhook

app.post('/api/paypal/create-payment', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'Utilizador não encontrado.' });
    if (user.premium) return res.status(400).json({ error: 'Já tem o plano Pro.' });

    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: 'CAPTURE',
      purchase_units: [{
        amount: { currency_code: 'USD', value: '10.00' },
        description: 'InvoicePro Pro — Acesso mensal',
        custom_id: user.id
      }],
      application_context: {
        brand_name: 'InvoicePro',
        landing_page: 'BILLING',
        user_action: 'PAY_NOW',
        return_url: `${process.env.FRONTEND_URL}/api/paypal/capture-payment`,
        cancel_url: `${process.env.FRONTEND_URL}?payment=cancelled`
      }
    });

    const order = await paypalClient().execute(request);
    await supabase.from('users').update({ paypal_order_id: order.result.id }).eq('id', user.id);
    const approvalLink = order.result.links.find(l => l.rel === 'approve').href;
    res.json({ url: approvalLink });
  } catch (err) {
    console.error('Erro PayPal:', err);
    res.status(500).json({ error: 'Erro ao criar pagamento PayPal.' });
  }
});

app.get('/api/paypal/capture-payment', async (req, res) => {
  const { token } = req.query;
  try {
    const request = new paypal.orders.OrdersCaptureRequest(token);
    const capture = await paypalClient().execute(request);

    // Encontra o utilizador pelo order_id
    const { data: user } = await supabase
      .from('users').select('id, email').eq('paypal_order_id', token).single();

    if (user && capture.result.status === 'COMPLETED') {
      // Calcula expiração — 31 dias a partir de hoje
      const expiry = new Date();
      expiry.setDate(expiry.getDate() + 31);

      await supabase.from('users').update({
        premium: true,
        paypal_payment_id: capture.result.id,
        premium_expires_at: expiry.toISOString()
      }).eq('id', user.id);

      // Envia email de confirmação
      try {
        await resend.emails.send({
          from: process.env.EMAIL_FROM || 'InvoicePro <onboarding@resend.dev>',
          to: [user.email],
          subject: '✅ Plano Pro activado — InvoicePro',
          html: `
            <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:32px">
              <h2 style="color:#0f2b5c">Bem-vindo ao InvoicePro Pro!</h2>
              <p>O teu plano Pro está activo. Tens acesso a:</p>
              <ul>
                <li>Facturas ilimitadas</li>
                <li>PDF sem marca de água</li>
                <li>Envio de email ao cliente</li>
                <li>Logo personalizado</li>
              </ul>
              <p style="color:#64748b;font-size:13px">Validade: ${expiry.toLocaleDateString('pt-PT')}</p>
              <p style="color:#64748b;font-size:12px">© 2025 InvoicePro</p>
            </div>
          `
        });
      } catch(emailErr) {
        console.error('Erro email confirmação:', emailErr);
      }

      console.log('✅ Pro activado para:', user.email);
    }

    res.redirect(`${process.env.FRONTEND_URL}?payment=success`);
  } catch (err) {
    console.error('Erro ao capturar:', err);
    res.redirect(`${process.env.FRONTEND_URL}?payment=failed`);
  }
});

// Verifica se o Pro expirou (middleware opcional para chamar antes de criar factura)
async function checkPremiumExpiry(userId) {
  const { data: user } = await supabase
    .from('users').select('premium, premium_expires_at').eq('id', userId).single();
  if (user?.premium && user?.premium_expires_at) {
    if (new Date(user.premium_expires_at) < new Date()) {
      await supabase.from('users').update({ premium: false }).eq('id', userId);
      return false;
    }
  }
  return user?.premium || false;
}

// ========== HEALTH CHECK ==========
// NOTA: Adiciona esta coluna ao Supabase se ainda não existir:
// ALTER TABLE users ADD COLUMN IF NOT EXISTS premium_expires_at TIMESTAMPTZ;
// ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_order_id TEXT;
// ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_payment_id TEXT;
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ========== INICIAR SERVIDOR ==========
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════╗
║  InvoicePro API rodando em http://localhost:${PORT}  ║
║  Supabase: ✅ Conectado                   ║
║  Email: ✅ Configurado                    ║
╚═══════════════════════════════════════════╝
  `);
});