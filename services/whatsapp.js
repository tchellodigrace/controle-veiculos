/**
 * Serviço de WhatsApp — Controle de Portaria DSRH
 * 
 * Suporta múltiplos provedores:
 * - Evolution API (brasileiro, gratuito, self-hosted)
 * - Z-API (brasileiro, pago)
 * - Twilio (internacional)
 * - Generic webhook
 * 
 * Configuração por cliente no banco de dados.
 * Se não configurado, as notificações são silenciosamente ignoradas (não quebra nada).
 */

const https = require('https');
const http = require('http');

// Cache de config por cliente (evita buscar no banco a cada notificação)
const configCache = new Map();
const CONFIG_CACHE_TTL = 5 * 60 * 1000; // 5 minutos

/**
 * Busca config do WhatsApp para um cliente (com cache)
 */
async function getConfig(pool, clienteId) {
  const cached = configCache.get(clienteId);
  if (cached && (Date.now() - cached.t) < CONFIG_CACHE_TTL) return cached.data;

  try {
    const result = await pool.query(
      'SELECT whatsapp_ativo, whatsapp_provedor, whatsapp_token, whatsapp_telefone, whatsapp_url, whatsapp_instancia FROM clientes WHERE id = $1',
      [clienteId]
    );
    const data = result.rows[0] || null;
    configCache.set(clienteId, { data, t: Date.now() });
    // Limitar cache
    if (configCache.size > 200) {
      const first = configCache.keys().next().value;
      configCache.delete(first);
    }
    return data;
  } catch (err) {
    console.error('[WHATSAPP] Erro ao buscar config:', err.message);
    return null;
  }
}

/**
 * Limpa cache de config (quando admin altera config)
 */
function limparCacheConfig(clienteId) {
  if (clienteId) configCache.delete(clienteId);
  else configCache.clear();
}

/**
 * Envia mensagem WhatsApp via Evolution API
 * Docs: https://docs.evolution-api.com/
 */
async function enviarEvolutionAPI(url, instancia, token, telefone, mensagem) {
  const baseUrl = url.replace(/\/+$/, '');
  const telefoneLimpo = telefone.replace(/[^0-9]/g, '');
  
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      number: telefoneLimpo,
      textMessage: { text: mensagem }
    });

    const options = {
      hostname: baseUrl.replace('https://', '').replace('http://', '').split('/')[0],
      port: baseUrl.startsWith('https') ? 443 : 80,
      path: `/instance/${instancia}/text`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': token,
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 15000
    };

    const transport = baseUrl.startsWith('https') ? https : http;
    const req = transport.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ ok: true, status: res.statusCode });
        } else {
          reject(new Error(`Evolution API ${res.statusCode}: ${body.substring(0, 200)}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout Evolution API')); });
    req.write(postData);
    req.end();
  });
}

/**
 * Envia mensagem WhatsApp via Z-API
 * Docs: https://z-api.io/
 */
async function enviarZAPI(token, telefone, mensagem) {
  const telefoneLimpo = telefone.replace(/[^0-9]/g, '');
  const telefoneZapi = '55' + telefoneLimpo;

  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      phone: telefoneZapi,
      message: mensagem
    });

    const options = {
      hostname: 'api.z-api.io',
      port: 443,
      path: '/' + token + '/send-text',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 15000
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ ok: true, status: res.statusCode });
        } else {
          reject(new Error(`Z-API ${res.statusCode}: ${body.substring(0, 200)}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout Z-API')); });
    req.write(postData);
    req.end();
  });
}

/**
 * Envia mensagem WhatsApp via Twilio
 * Docs: https://www.twilio.com/docs/whatsapp/api
 */
async function enviarTwilio(accountSid, authToken, from, telefone, mensagem) {
  const telefoneLimpo = telefone.replace(/[^0-9]/g, '');
  const to = 'whatsapp:+55' + telefoneLimpo;

  return new Promise((resolve, reject) => {
    const postData = 'From=' + encodeURIComponent(from) + '&To=' + encodeURIComponent(to) + '&Body=' + encodeURIComponent(mensagem);

    const options = {
      hostname: 'api.twilio.com',
      port: 443,
      path: '/2010-04-01/Accounts/' + accountSid + '/Messages.json',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(accountSid + ':' + authToken).toString('base64'),
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 15000
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ ok: true, status: res.statusCode });
        } else {
          reject(new Error(`Twilio ${res.statusCode}: ${body.substring(0, 200)}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout Twilio')); });
    req.write(postData);
    req.end();
  });
}

/**
 * Função principal de envio — roteia para o provedor correto
 */
async function enviar(pool, clienteId, telefone, mensagem) {
  if (!telefone || !mensagem) return { ok: false, erro: 'Telefone ou mensagem vazio' };

  const config = await getConfig(pool, clienteId);
  if (!config || !config.whatsapp_ativo) {
    return { ok: false, erro: 'WhatsApp não configurado para este cliente' };
  }

  try {
    switch (config.whatsapp_provedor) {
      case 'evolution':
        if (!config.whatsapp_url || !config.whatsapp_instancia || !config.whatsapp_token) {
          return { ok: false, erro: 'Evolution API: url, instancia e token são obrigatórios' };
        }
        return await enviarEvolutionAPI(config.whatsapp_url, config.whatsapp_instancia, config.whatsapp_token, telefone, mensagem);

      case 'zapi':
        if (!config.whatsapp_token) {
          return { ok: false, erro: 'Z-API: token é obrigatório' };
        }
        return await enviarZAPI(config.whatsapp_token, telefone, mensagem);

      case 'twilio':
        if (!config.whatsapp_token || !config.whatsapp_telefone) {
          return { ok: false, erro: 'Twilio: token e número remetente são obrigatórios' };
        }
        // Para Twilio, o token vem no formato "accountSid:authToken" e whatsapp_telefone é o from
        const parts = config.whatsapp_token.split(':');
        if (parts.length !== 2) return { ok: false, erro: 'Twilio: token deve ser accountSid:authToken' };
        return await enviarTwilio(parts[0], parts[1], config.whatsapp_telefone, telefone, mensagem);

      default:
        return { ok: false, erro: 'Provedor não suportado: ' + config.whatsapp_provedor };
    }
  } catch (err) {
    console.error('[WHATSAPP] Erro ao enviar:', err.message);
    return { ok: false, erro: err.message };
  }
}

/**
 * Notifica LOGÍSTICA quando motorista chega (entrada confirmada pela portaria)
 */
async function notificarEntrada(pool, clienteId, dados) {
  const empresa = dados.empresa || '';
  const motorista = dados.motorista || '';
  const placa = dados.placa || '';
  const finalidade = dados.finalidade || '';
  const hora = dados.hora || new Date().toLocaleTimeString('pt-BR');

  // Buscar telefone de notificação do cliente
  try {
    const result = await pool.query(
      'SELECT whatsapp_telefone_notif FROM clientes WHERE id = $1',
      [clienteId]
    );
    const telNotif = result.rows[0]?.whatsapp_telefone_notif;
    if (!telNotif) return { ok: false, erro: 'Telefone de notificação não configurado' };

    const msg = `🚛 *ENTRADA DE VEÍCULO*\n\n` +
      `📌 Empresa: ${empresa}\n` +
      `👤 Motorista: ${motorista}\n` +
      `🚗 Placa: ${placa}\n` +
      `📋 Finalidade: ${finalidade}\n` +
      `🕐 Horário: ${hora}\n\n` +
      `— Sistema Portaria DSRH`;

    const resultado = await enviar(pool, clienteId, telNotif, msg);
    console.log('[WHATSAPP] Notificação de entrada:', resultado.ok ? '✅' : '❌', resultado.erro || '');
    return resultado;
  } catch (err) {
    console.error('[WHATSAPP] Erro notificar entrada:', err.message);
    return { ok: false, erro: err.message };
  }
}

/**
 * Notifica LOGÍSTICA quando motorista sai (saída registrada pela portaria)
 */
async function notificarSaida(pool, clienteId, dados) {
  const empresa = dados.empresa || '';
  const motorista = dados.motorista || '';
  const placa = dados.placa || '';
  const finalidade = dados.finalidade || '';
  const hora = dados.hora || new Date().toLocaleTimeString('pt-BR');

  try {
    const result = await pool.query(
      'SELECT whatsapp_telefone_notif FROM clientes WHERE id = $1',
      [clienteId]
    );
    const telNotif = result.rows[0]?.whatsapp_telefone_notif;
    if (!telNotif) return { ok: false, erro: 'Telefone de notificação não configurado' };

    const msg = `✅ *SAÍDA DE VEÍCULO*\n\n` +
      `📌 Empresa: ${empresa}\n` +
      `👤 Motorista: ${motorista}\n` +
      `🚗 Placa: ${placa}\n` +
      `📋 Finalidade: ${finalidade}\n` +
      `🕐 Horário: ${hora}\n\n` +
      `— Sistema Portaria DSRH`;

    const resultado = await enviar(pool, clienteId, telNotif, msg);
    console.log('[WHATSAPP] Notificação de saída:', resultado.ok ? '✅' : '❌', resultado.erro || '');
    return resultado;
  } catch (err) {
    console.error('[WHATSAPP] Erro notificar saída:', err.message);
    return { ok: false, erro: err.message };
  }
}

/**
 * Envia comprovante digital para o motorista após check-in confirmado
 */
async function enviarComprovante(pool, clienteId, telefoneMotorista, dados) {
  if (!telefoneMotorista) return { ok: false, erro: 'Telefone do motorista não informado' };

  const empresa = dados.empresa || '';
  const motorista = dados.motorista || '';
  const placa = dados.placa || '';
  const finalidade = dados.finalidade || '';
  const hora = dados.hora || new Date().toLocaleTimeString('pt-BR');
  const data = new Date().toLocaleDateString('pt-BR');

  const msg = `🎫 *COMPROVANTE DE CHECK-IN*\n\n` +
    `🏢 ${empresa}\n` +
    `📅 ${data} às ${hora}\n` +
    `👤 ${motorista}\n` +
    `🚗 ${placa}\n` +
    `📋 ${finalidade}\n\n` +
    `Apresente este comprovante na portaria.\n\n` +
    `— Sistema Portaria DSRH`;

  const resultado = await enviar(pool, clienteId, telefoneMotorista, msg);
  console.log('[WHATSAPP] Comprovante:', resultado.ok ? '✅' : '❌', resultado.erro || '');
  return resultado;
}

/**
 * Notifica LOGÍSTICA sobre novo check-in via QR Code (pré-registro recebido)
 */
async function notificarCheckinQR(pool, clienteId, dados) {
  try {
    const result = await pool.query(
      'SELECT whatsapp_telefone_notif FROM clientes WHERE id = $1',
      [clienteId]
    );
    const telNotif = result.rows[0]?.whatsapp_telefone_notif;
    if (!telNotif) return { ok: false, erro: 'Telefone de notificação não configurado' };

    const msg = `📱 *NOVO CHECK-IN VIA QR CODE*\n\n` +
      `📌 Empresa: ${dados.empresa || ''}\n` +
      `👤 Motorista: ${dados.motorista || ''}\n` +
      `🚗 Placa: ${dados.placa || ''}\n` +
      `📋 Finalidade: ${dados.finalidade || ''}\n\n` +
      `⏳ Aguardando confirmação da portaria.\n\n` +
      `— Sistema Portaria DSRH`;

    const resultado = await enviar(pool, clienteId, telNotif, msg);
    console.log('[WHATSAPP] Notificação QR check-in:', resultado.ok ? '✅' : '❌', resultado.erro || '');
    return resultado;
  } catch (err) {
    console.error('[WHATSAPP] Erro notificar checkin QR:', err.message);
    return { ok: false, erro: err.message };
  }
}

module.exports = {
  enviar,
  notificarEntrada,
  notificarSaida,
  enviarComprovante,
  notificarCheckinQR,
  limparCacheConfig,
  getConfig
};
