/**
 * Serviço de Email — Controle de Portaria DSRH
 * 
 * Usa Nodemailer com SMTP (Gmail, Outlook, qualquer provedor).
 * Configuração por cliente no banco de dados.
 * Se não configurado, as notificações são silenciosamente ignoradas.
 */

const nodemailer = require('nodemailer');

// Cache de transporters por cliente
const transporterCache = new Map();
const TRANSPORTER_CACHE_TTL = 10 * 60 * 1000; // 10 minutos

/**
 * Cria transporter SMTP para um cliente (com cache)
 */
async function getTransporter(pool, clienteId) {
  const cached = transporterCache.get(clienteId);
  if (cached && (Date.now() - cached.t) < TRANSPORTER_CACHE_TTL) return cached.transporter;

  try {
    const result = await pool.query(
      'SELECT email_ativo, email_smtp_host, email_smtp_port, email_smtp_user, email_smtp_pass, email_remetente, email_destinatario FROM clientes WHERE id = $1',
      [clienteId]
    );
    const config = result.rows[0];
    if (!config || !config.email_ativo || !config.email_smtp_host) return null;

    const transporter = nodemailer.createTransport({
      host: config.email_smtp_host,
      port: parseInt(config.email_smtp_port) || 587,
      secure: parseInt(config.email_smtp_port) === 465,
      auth: {
        user: config.email_smtp_user,
        pass: config.email_smtp_pass
      },
      tls: { rejectUnauthorized: false }
    });

    // Testar conexão
    await transporter.verify();

    transporterCache.set(clienteId, { transporter, t: Date.now() });
    if (transporterCache.size > 100) {
      const first = transporterCache.keys().next().value;
      transporterCache.delete(first);
    }
    return transporter;
  } catch (err) {
    console.error('[EMAIL] Erro ao criar transporter:', err.message);
    return null;
  }
}

/**
 * Limpa cache de transporter
 */
function limparCache(clienteId) {
  if (clienteId) transporterCache.delete(clienteId);
  else transporterCache.clear();
}

/**
 * Busca config de email do cliente
 */
async function getConfig(pool, clienteId) {
  try {
    const result = await pool.query(
      'SELECT email_ativo, email_smtp_host, email_smtp_port, email_smtp_user, email_remetente, email_destinatario FROM clientes WHERE id = $1',
      [clienteId]
    );
    return result.rows[0] || null;
  } catch {
    return null;
  }
}

/**
 * Envia email
 */
async function enviar(pool, clienteId, assunto, html, destinatario) {
  const config = await getConfig(pool, clienteId);
  if (!config || !config.email_ativo) {
    return { ok: false, erro: 'Email não configurado para este cliente' };
  }

  const to = destinatario || config.email_destinatario;
  if (!to) return { ok: false, erro: 'Destinatário não informado' };

  try {
    const transporter = await getTransporter(pool, clienteId);
    if (!transporter) return { ok: false, erro: 'Falha ao conectar SMTP' };

    const info = await transporter.sendMail({
      from: `"Sistema Portaria" <${config.email_remetente || config.email_smtp_user}>`,
      to: to,
      subject: assunto,
      html: html
    });

    console.log('[EMAIL] Enviado:', assunto, '→', to);
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    console.error('[EMAIL] Erro ao enviar:', err.message);
    return { ok: false, erro: err.message };
  }
}

/**
 * Template HTML base para emails
 */
function templateHTML(titulo, conteudo) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0; padding:0; background:#f2f4f6; font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:600px; margin:20px auto; background:#fff; border-radius:12px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(135deg,#2a6f7e,#4FB0C6); padding:24px 32px;">
      <h2 style="margin:0; color:#fff; font-size:20px;">${titulo}</h2>
    </div>
    <div style="padding:24px 32px; color:#26313a; font-size:14px; line-height:1.6;">
      ${conteudo}
    </div>
    <div style="background:#f2f4f6; padding:16px 32px; text-align:center; font-size:11px; color:#8b93a1;">
      Sistema de Controle de Portaria DSRH &bull; ${new Date().toLocaleDateString('pt-BR')}
    </div>
  </div>
</body>
</html>`;
}

/**
 * Notifica entrada de veículo
 */
async function notificarEntrada(pool, clienteId, dados) {
  const config = await getConfig(pool, clienteId);
  if (!config || !config.email_ativo) return { ok: false, erro: 'Email não configurado' };

  const html = templateHTML('🚛 ENTRADA DE VEÍCULO', `
    <p><b>Empresa:</b> ${dados.empresa || '-'}</p>
    <p><b>Motorista:</b> ${dados.motorista || '-'}</p>
    <p><b>Placa:</b> ${dados.placa || '-'}</p>
    <p><b>Finalidade:</b> ${dados.finalidade || '-'}</p>
    <p><b>Horário:</b> ${dados.hora || '-'}</p>
    <hr style="border:none;border-top:1px solid #e3e7eb;margin:16px 0;">
    <p style="color:#8b93a1;">Este é um aviso automático do Sistema de Portaria DSRH.</p>
  `);

  return enviar(pool, clienteId, '[Portaria] Entrada de veículo — ' + (dados.placa || ''), html);
}

/**
 * Notifica saída de veículo
 */
async function notificarSaida(pool, clienteId, dados) {
  const config = await getConfig(pool, clienteId);
  if (!config || !config.email_ativo) return { ok: false, erro: 'Email não configurado' };

  const html = templateHTML('✅ SAÍDA DE VEÍCULO', `
    <p><b>Empresa:</b> ${dados.empresa || '-'}</p>
    <p><b>Motorista:</b> ${dados.motorista || '-'}</p>
    <p><b>Placa:</b> ${dados.placa || '-'}</p>
    <p><b>Finalidade:</b> ${dados.finalidade || '-'}</p>
    <p><b>Horário:</b> ${dados.hora || '-'}</p>
    <hr style="border:none;border-top:1px solid #e3e7eb;margin:16px 0;">
    <p style="color:#8b93a1;">Este é um aviso automático do Sistema de Portaria DSRH.</p>
  `);

  return enviar(pool, clienteId, '[Portaria] Saída de veículo — ' + (dados.placa || ''), html);
}

/**
 * Notifica check-in via QR Code recebido
 */
async function notificarCheckinQR(pool, clienteId, dados) {
  const config = await getConfig(pool, clienteId);
  if (!config || !config.email_ativo) return { ok: false, erro: 'Email não configurado' };

  const html = templateHTML('📱 NOVO CHECK-IN VIA QR CODE', `
    <p><b>Empresa:</b> ${dados.empresa || '-'}</p>
    <p><b>Motorista:</b> ${dados.motorista || '-'}</p>
    <p><b>Placa:</b> ${dados.placa || '-'}</p>
    <p><b>Finalidade:</b> ${dados.finalidade || '-'}</p>
    <hr style="border:none;border-top:1px solid #e3e7eb;margin:16px 0;">
    <p style="color:#e08a1e;font-weight:600;">⏳ Aguardando confirmação da portaria.</p>
    <p style="color:#8b93a1;">Este é um aviso automático do Sistema de Portaria DSRH.</p>
  `);

  return enviar(pool, clienteId, '[Portaria] Check-in QR recebido — ' + (dados.placa || ''), html);
}

module.exports = {
  enviar,
  notificarEntrada,
  notificarSaida,
  notificarCheckinQR,
  limparCache,
  getConfig
};
