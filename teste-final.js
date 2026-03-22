// teste-final.js
require('dotenv').config();
const { Resend } = require('resend');

async function testarResend() {
  console.log('\n🔍 TESTANDO RESEND - INVOICEPRO');
  console.log('================================');
  
  // Verificar variáveis de ambiente
  console.log('\n📋 VARIÁVEIS DE AMBIENTE:');
  console.log('RESEND_API_KEY:', process.env.RESEND_API_KEY ? '✅ Configurada (começa com ' + process.env.RESEND_API_KEY.substring(0, 10) + '...)' : '❌ Ausente');
  console.log('EMAIL_FROM:', process.env.EMAIL_FROM || '❌ Não configurado');
  console.log('PORT:', process.env.PORT || 3003);
  
  if (!process.env.RESEND_API_KEY) {
    console.log('\n❌ ERRO: RESEND_API_KEY não encontrada no arquivo .env');
    console.log('Por favor, verifique se o arquivo .env contém:');
    console.log('RESEND_API_KEY=re_hiaW1rsC_GE7KaHVxHv1vCiGUPfN43eiS');
    return;
  }

  console.log('\n📧 Inicializando Resend...');
  const resend = new Resend(process.env.RESEND_API_KEY);

  try {
    console.log('📤 Enviando email de teste para delivered@resend.dev...');
    
    const { data, error } = await resend.emails.send({
      from: process.env.EMAIL_FROM || 'InvoicePro <onboarding@resend.dev>',
      to: ['delivered@resend.dev'], // Email de teste do Resend
      subject: 'Teste InvoicePro - ' + new Date().toLocaleString(),
      html: `
        <h1>Teste do InvoicePro</h1>
        <p>Este é um email de teste enviado em ${new Date().toLocaleString()}</p>
        <p>Se você está vendo isso, o Resend está funcionando perfeitamente!</p>
      `
    });

    if (error) {
      console.log('\n❌ ERRO DA RESEND:');
      console.log(JSON.stringify(error, null, 2));
      
      // Mensagens de erro amigáveis
      if (error.message.includes('API key')) {
        console.log('\n🔑 PROBLEMA COM A CHAVE API:');
        console.log('A chave Resend parece ser inválida. Verifique:');
        console.log('1. Se a chave começa com "re_"');
        console.log('2. Se não há espaços ou caracteres extras');
        console.log('3. Se a chave está ativa no dashboard do Resend');
      } else if (error.message.includes('from')) {
        console.log('\n📧 PROBLEMA COM O REMETENTE:');
        console.log('O email de origem é inválido. Use onboarding@resend.dev para testes.');
      }
    } else {
      console.log('\n✅ SUCESSO! Email enviado com sucesso!');
      console.log('ID do email:', data.id);
      console.log('\n🎉 O Resend está funcionando corretamente!');
    }
  } catch (err) {
    console.log('\n❌ ERRO INESPERADO:');
    console.log(err);
  }
}

// Executar a função
testarResend();