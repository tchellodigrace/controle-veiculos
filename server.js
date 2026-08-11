// FIX: Garantir horario do Brasil (America/Sao_Paulo) no servidor (Render UTC)
process.env.TZ = process.env.TZ || 'America/Sao_Paulo';

require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const whatsapp = require('./services/whatsapp');
const email = require('./services/email');
const uuid = () => crypto.randomBytes(16).toString('hex');

// Cache de reverse geocoding para evitar chamadas excessivas ao Nominatim
const geoCache = new Map();
const GEO_CACHE_TTL = 5 * 60 * 1000; // 5 minutos

async function obterRua(lat, lng) {
  try {
    const key = Math.round(lat * 10000) + ',' + Math.round(lng * 10000);
    const cached = geoCache.get(key);
    if (cached && (Date.now() - cached.t) < GEO_CACHE_TTL) return cached.r;

    const res = await fetch('https://nominatim.openstreetmap.org/reverse?lat=' + lat + '&lon=' + lng + '&format=json&accept-language=pt-BR&zoom=18', {
      headers: { 'User-Agent': 'ControlePortariaDSRH/1.0' }
    });
    if (!res.ok) return '';
    const data = await res.json();
    const rua = data.address?.road || data.address?.street || data.address?.pedestrian || data.address?.residential || data.display_name?.split(',')[0] || '';
    const resultado = rua.substring(0, 200);
    geoCache.set(key, { r: resultado, t: Date.now() });
    if (geoCache.size > 500) {
      const first = geoCache.keys().next().value;
      geoCache.delete(first);
    }
    return resultado;
  } catch (e) {
    return '';
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = require('./package.json')?.version || '1.0.0';

// Validacao de variaveis de ambiente criticas
function validarEnv() {
  const avisos = [];
  if (!process.env.DATABASE_URL) avisos.push('DATABASE_URL nao definido - conexao com banco falhara');
  if (!process.env.JWT_SECRET) avisos.push('JWT_SECRET nao definido - usando fallback inseguro');
  if (avisos.length > 0) {
    console.warn('=== AVISOS DE CONFIGURACAO ===');
    avisos.forEach(a => console.warn(' - ' + a));
    console.warn('===============================');
  }
}
validarEnv();

const JWT_SECRET = process.env.JWT_SECRET || '';
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET nao definido no ambiente. Defina a variavel e reinicie.');
  process.exit(1);
}

// Remover header X-Powered-By do Express
app.disable('x-powered-by');

// Request ID para correlacao de logs
app.use((req, res, next) => {
  req.requestId = uuid();
  res.set('X-Request-Id', req.requestId);
  next();
});

// Validacao de complexidade de senha
function validarComplexidadeSenha(senha) {
  const erros = [];
  if (!/[a-z]/.test(senha)) erros.push('letra minuscula');
  if (!/[A-Z]/.test(senha)) erros.push('letra maiuscula');
  if (!/[0-9]/.test(senha)) erros.push('numero');
  if (senha.length >= 8 && erros.length >= 2) return null;
  if (senha.length < 8) return 'Senha deve ter pelo menos 8 caracteres';
  if (erros.length >= 3) return 'Senha deve conter: ' + erros.slice(0,2).join(', ') + ' e ' + erros[2];
  return null;
}

// Lockout de contas por tentativas falhadas
const loginAttempts = new Map();
function checkLockout(key) {
  const att = loginAttempts.get(key);
  if (!att) return false;
  if (att.count >= 5 && (Date.now() - att.lastAttempt) < 15 * 60 * 1000) return true;
  if ((Date.now() - att.lastAttempt) >= 15 * 60 * 1000) loginAttempts.delete(key);
  return false;
}
function recordFailedAttempt(key) {
  const att = loginAttempts.get(key) || { count: 0, lastAttempt: 0 };
  att.count++;
  att.lastAttempt = Date.now();
  loginAttempts.set(key, att);
}
function clearAttempts(key) { loginAttempts.delete(key); }
// Limpeza periodica do map de lockout (a cada 15 min) para evitar memory leak
setInterval(() => {
  const agora = Date.now();
  for (const [key, att] of loginAttempts) {
    if ((agora - att.lastAttempt) >= 15 * 60 * 1000) loginAttempts.delete(key);
  }
}, 15 * 60 * 1000);

const ALLOWED_ORIGINS = process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(s => s.trim()) : ['https://controle-veiculos-dsrh.onrender.com','http://localhost:3000'];
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.indexOf(origin) !== -1) callback(null, true);
    else callback(new Error('CORS bloqueado: ' + origin));
  },
  methods: ['GET','POST','PUT','DELETE'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true,
  maxAge: 600
}));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0,
  etag: true,
  lastModified: true
}));

// Security headers
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Cache-Control', 'no-store');
  res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: https: https://unpkg.com; font-src 'self' https://unpkg.com; connect-src 'self'"); // connect-src 'self' restringe fetch/XHR ao mesmo origem; ajustar se houver APIs externas necessarias
  res.set('Permissions-Policy', 'camera=(), microphone=(), payment=()');
  next();
});

// Configuracao de upload de arquivos
const uploadsDir = path.join(__dirname, 'public', 'uploads', 'arquivos');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storageArquivos = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, Date.now() + '_' + Math.random().toString(36).substring(2, 8) + ext);
  }
});
const uploadArquivo = multer({
  storage: storageArquivos,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const extensoes = ['.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.txt','.csv','.jpg','.jpeg','.png','.gif','.bmp','.zip','.rar','.mp4','.mp3','.avi','.mov','.dwg','.svg','.odt','.ods'];
    if (extensoes.includes(path.extname(file.originalname).toLowerCase())) cb(null, true);
    else cb(new Error('Tipo de arquivo nao permitido. Tipos aceitos: PDF, DOC, XLS, PPT, TXT, CSV, JPG, PNG, GIF, ZIP, RAR, DWG, MP4, MP3'));
  }
});

// HTTPS redirect (producao)
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https' && req.protocol !== 'https') {
      return res.redirect(301, 'https://' + req.headers.host + req.originalUrl);
    }
    next();
  });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  pool.query('SELECT 1 AS ok').then(() => {
    res.json({ status: 'ok', version: APP_VERSION, timestamp: new Date().toISOString(), uptime: process.uptime() });
  }).catch(() => {
    res.status(503).json({ status: 'error', version: APP_VERSION, timestamp: new Date().toISOString() });
  });
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { erro: 'Muitas tentativas. Tente novamente em 15 minutos.' },
  standardHeaders: true, legacyHeaders: false
});
const preRegistroLimiter = rateLimit({
  windowMs: 60 * 1000, max: 20,
  message: { erro: 'Muitas requisicoes. Tente novamente.' },
  standardHeaders: true, legacyHeaders: false
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 200,
  message: { erro: 'Muitas requisicoes. Tente novamente.' },
  standardHeaders: true, legacyHeaders: false
});

function gerarToken(usuario) {
  return jwt.sign(
    { id: usuario.id, usuario: usuario.usuario, nome: usuario.nome, cliente_id: usuario.cliente_id },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ erro: 'Token não fornecido' });
  }
  try {
    req.usuario = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

function adminMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ erro: 'Não autorizado' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.admin) return res.status(401).json({ erro: 'Não autorizado' });
    req.admin = decoded;
    next();
  } catch { return res.status(401).json({ erro: 'Token inválido' }); }
}

function logAuditoria(clienteId, usuario, acao, tipo, alvo, detalhes) {
  pool.query(
    'INSERT INTO logs_auditoria (cliente_id, usuario, acao, tipo, alvo, detalhes) VALUES ($1,$2,$3,$4,$5,$6)',
    [clienteId, usuario||'', acao, tipo||'', alvo||'', detalhes||'']
  ).catch(() => {});
}

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    if (!usuario || !senha) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios' });
    const lockKey = 'login:' + usuario.toLowerCase();
    if (checkLockout(lockKey)) return res.status(429).json({ erro: 'Conta temporariamente bloqueada por muitas tentativas. Tente novamente em 15 minutos.' });
    const result = await pool.query('SELECT id, nome, usuario, senha, cliente_id, trocar_senha FROM usuarios WHERE usuario = $1 AND ativo = TRUE', [usuario.toLowerCase()]);
    if (result.rows.length === 0) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    const user = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, user.senha);
    if (!senhaValida) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    clearAttempts(lockKey);
    const token = gerarToken(user);
    const cliente = user.cliente_id ? (await pool.query('SELECT id, empresa FROM clientes WHERE id = $1', [user.cliente_id])).rows[0] : null;
    res.json({ token, usuario: { nome: user.nome, usuario: user.usuario, cliente_id: user.cliente_id, trocar_senha: !!user.trocar_senha }, empresa: cliente ? cliente.empresa : '' });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.get('/api/verificar-token', authMiddleware, (req, res) => {
  res.json({ valido: true, usuario: req.usuario });
});

app.get('/api/registros', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, saida, nota, obs, posicao, data_registro, patio_liberado FROM registros WHERE cliente_id = $1 AND data_registro = CURRENT_DATE ORDER BY id ASC',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar registros:', err);
    res.status(500).json({ erro: 'Erro ao buscar registros' });
  }
});

app.get('/api/registros/todos', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const pagina = Math.max(parseInt(req.query.pagina) || 1, 1);
    const limite = Math.min(parseInt(req.query.limite) || 100, 500);
    const offset = (pagina - 1) * limite;
    const [result, countResult] = await Promise.all([
      pool.query(
        'SELECT id, cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, saida, nota, obs, posicao, data_registro FROM registros WHERE cliente_id = $1 ORDER BY data_registro DESC, id DESC LIMIT $2 OFFSET $3',
        [req.usuario.cliente_id, limite, offset]
      ),
      pool.query('SELECT COUNT(*)::int AS total FROM registros WHERE cliente_id = $1', [req.usuario.cliente_id])
    ]);
    res.json({ registros: result.rows, total: countResult.rows[0].total, pagina, limite, totalPaginas: Math.ceil(countResult.rows[0].total / limite) });
  } catch (err) {
    console.error('Erro ao buscar registros:', err);
    res.status(500).json({ erro: 'Erro ao buscar registros' });
  }
});

// Validacao auxiliar de entrada
function validarString(str, min, max, nome) {
  if (typeof str !== 'string') return 'Campo ' + nome + ' invalido';
  const trimmed = str.trim();
  if (min > 0 && trimmed.length < min) return nome + ' deve ter pelo menos ' + min + ' caracteres';
  if (max > 0 && trimmed.length > max) return nome + ' excede o limite de ' + max + ' caracteres';
  return null;
}
function validarCpf(cpf) {
  const digits = (cpf||'').replace(/[^0-9]/g, '');
  if (digits.length > 0 && digits.length !== 11) return 'CPF deve ter 11 digitos';
  return null;
}
function validarEmail(email) {
  if (!email) return null;
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!re.test(email)) return 'Email invalido';
  return null;
}
function sanitizarString(str) {
  return String(str||'').trim().replace(/[<>"'&]/g, '');
}

app.post('/api/registros', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { placa, modelo, finalidade, empresa, motorista, cnh, nota, obs } = req.body;
    if (!placa || !empresa) return res.status(400).json({ erro: 'Placa e Empresa são obrigatórios' });
    const placaClean = placa.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (placaClean.length < 6 || placaClean.length > 8) return res.status(400).json({ erro: 'Placa inválida (deve ter 6-8 caracteres alfanuméricos)' });
    // Tudo em maiusculas
    const empresaUp = (empresa || '').trim().toUpperCase();
    const modeloUp = (modelo || '').trim().toUpperCase();
    const finalidadeUp = (finalidade || '').trim().toUpperCase();
    const motoristaUp = (motorista || '').trim().toUpperCase();
    const cnhUp = (cnh || '').trim().toUpperCase();
    const notaUp = (nota || '').trim().toUpperCase();
    const obsUp = (obs || '').trim().toUpperCase();
    const errEmpresa = validarString(empresaUp, 2, 100, 'Empresa');
    if (errEmpresa) return res.status(400).json({ erro: errEmpresa });
    const errModelo = validarString(modeloUp, 0, 100, 'Modelo');
    if (errModelo) return res.status(400).json({ erro: errModelo });
    const errMotorista = validarString(motoristaUp, 0, 100, 'Motorista');
    if (errMotorista) return res.status(400).json({ erro: errMotorista });
    const errCnh = validarString(cnhUp, 0, 20, 'CNH');
    if (errCnh) return res.status(400).json({ erro: errCnh });
    const errNota = validarString(notaUp, 0, 50, 'Nota');
    if (errNota) return res.status(400).json({ erro: errNota });
    const errObs = validarString(obsUp, 0, 500, 'Observacao');
    if (errObs) return res.status(400).json({ erro: errObs });
    // Detecção de duplicado: mesma placa sem saída no mesmo dia
    const dup = await pool.query(
      `SELECT id FROM registros WHERE cliente_id = $1 AND placa = $2 AND data_registro = CURRENT_DATE AND saida = ''`,
      [req.usuario.cliente_id, placaClean]
    );
    if (dup.rows.length > 0) return res.status(409).json({ erro: 'Ja existe um registro com esta placa aguardando saida. Verifique a tabela.' });
    const hora = new Date().toLocaleTimeString('pt-BR'); // Sempre do servidor
    const cid = req.usuario.cliente_id;
    const pos = await pool.query(
      `SELECT COALESCE(MAX(posicao), 0) + 1 AS prox FROM registros WHERE cliente_id = $1 AND data_registro = CURRENT_DATE`,
      [cid]
    );
    const result = await pool.query(
      `INSERT INTO registros (cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, nota, obs, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, saida, nota, obs, posicao, data_registro`,
      [cid, hora, placaClean, sanitizarString(modeloUp).substring(0,100), sanitizarString(finalidadeUp).substring(0,50), sanitizarString(empresaUp).substring(0,100), sanitizarString(motoristaUp).substring(0,100), sanitizarString(cnhUp).substring(0,20), hora, sanitizarString(notaUp).substring(0,50), sanitizarString(obsUp).substring(0,500), pos.rows[0].prox]
    );
    // Atualizar ou inserir em localizacoes_motoristas para aparecer na logistica
    const updateResult = await pool.query(
      'UPDATE localizacoes_motoristas SET a_caminho = FALSE, chegou = TRUE, chegada_em = NOW(), cnh = $3, modelo = $4, finalidade = $5, nota = $6, obs = $7, empresa = $8, nome = $9, atualizado_em = NOW() WHERE cliente_id = $1 AND placa = $2 AND (a_caminho = TRUE OR chegou = FALSE)',
      [cid, placaClean, sanitizarString(cnhUp).substring(0,50), sanitizarString(modeloUp).substring(0,100), sanitizarString(finalidadeUp).substring(0,100), sanitizarString(notaUp).substring(0,100), sanitizarString(obsUp).substring(0,500), sanitizarString(empresaUp).substring(0,100), sanitizarString(motoristaUp).substring(0,100)]
    );
    // Se nao existia registro (chegou direto pela portaria sem app), criar um novo
    if(updateResult.rowCount === 0){
      await pool.query(
        'INSERT INTO localizacoes_motoristas (cliente_id, placa, empresa, nome, a_caminho, chegou, chegada_em, cnh, modelo, finalidade, nota, obs, atualizado_em) VALUES ($1,$2,$3,$4,FALSE,TRUE,NOW(),$5,$6,$7,$8,$9,NOW())',
        [cid, placaClean, sanitizarString(empresaUp).substring(0,100), sanitizarString(motoristaUp).substring(0,100), sanitizarString(cnhUp).substring(0,50), sanitizarString(modeloUp).substring(0,100), sanitizarString(finalidadeUp).substring(0,100), sanitizarString(notaUp).substring(0,100), sanitizarString(obsUp).substring(0,500)]
      ).catch(() => {});
    }
    // Criar conta de motorista se ainda nao existe (registro direto pela portaria)
    if(motoristaUp){
      var usuarioGen = placaClean.toLowerCase();
      var existeMotorista = await pool.query('SELECT id FROM contas_motoristas WHERE cliente_id = $1 AND (usuario = $2 OR nome = $3)', [cid, usuarioGen, motoristaUp]);
      if(!existeMotorista.rows.length){
        var senhaTemp = placaClean.toLowerCase() + '@Portaria';
        var senhaHash = await bcrypt.hash(senhaTemp, 10);
        await pool.query(
          'INSERT INTO contas_motoristas (cliente_id, usuario, senha, senha_exibicao, nome, empresa, ativo) VALUES ($1,$2,$3,$4,$5,$6,FALSE)',
          [cid, usuarioGen, senhaHash, senhaTemp.substring(0,20), motoristaUp, empresaUp]
        ).catch(() => {});
      }
    }
    res.status(201).json(result.rows[0]);
    logAuditoria(cid, req.usuario?.nome || '', 'Entrada', 'veiculo', placa.toUpperCase(), 'Motorista: ' + motoristaUp + ' | Empresa: ' + empresaUp);
  } catch (err) {
    console.error('Erro ao criar registro:', err);
    res.status(500).json({ erro: 'Erro ao criar registro' });
  }
});

app.put('/api/registros/:id/saida', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const hora = new Date().toLocaleTimeString('pt-BR'); // Sempre do servidor
    // Primeiro buscar o registro completo para pegar placa, finalidade, etc.
    const regInfo = await pool.query(
      'SELECT id, cliente_id, placa, motorista, finalidade, patio_liberado FROM registros WHERE id = $1 AND saida = $2 AND cliente_id = $3',
      [req.params.id, '', req.usuario.cliente_id]
    );
    if (regInfo.rows.length === 0) return res.status(404).json({ erro: 'Registro não encontrado ou já possui saída' });
    const reg = regInfo.rows[0];
    // Verificar se o patio foi liberado pela logistica antes de permitir a saida
    if (!reg.patio_liberado) {
      return res.status(403).json({ erro: 'Aguardando liberação do pátio pela Logística. O botão "Marcar Saída" será habilitado quando a Logística liberar o pátio.' });
    }
    const result = await pool.query(
      'UPDATE registros SET saida = $1 WHERE id = $2 RETURNING id, cliente_id, placa, modelo, saida',
      [hora, req.params.id]
    );
    // Marcar saida_logistica na localizacao do motorista (para logistica mostrar como concluido)
    // Busca pela placa no mesmo cliente, onde ainda não marcou saida
    await pool.query(
      'UPDATE localizacoes_motoristas SET saida_logistica = TRUE, finalidade_tipo = $1, saida_em = NOW(), atualizado_em = NOW() WHERE cliente_id = $2 AND placa = $3 AND saida_logistica = FALSE',
      [reg.finalidade || '', req.usuario.cliente_id, reg.placa]
    );
    res.json(result.rows[0]);
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Saida', 'veiculo', result.rows[0].placa, 'Saida registrada as ' + hora);
    // Notificar logística via WhatsApp (saída registrada)
    whatsapp.notificarSaida(pool, req.usuario.cliente_id, { empresa: '', motorista: reg.motorista, placa: reg.placa, finalidade: reg.finalidade, hora }).catch(() => {});
    // Notificar via Email (saída registrada)
    email.notificarSaida(pool, req.usuario.cliente_id, { empresa: '', motorista: reg.motorista, placa: reg.placa, finalidade: reg.finalidade, hora }).catch(() => {});
    // Criar notificação no sistema
    pool.query('INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)', [req.usuario.cliente_id, 'saida', 'Saída de veículo', 'Motorista: ' + (reg.motorista||'') + ' | Placa: ' + reg.placa]).catch(() => {});
  } catch (err) {
    console.error('Erro ao marcar saída:', err);
    res.status(500).json({ erro: 'Erro ao marcar saída' });
  }
});

app.delete('/api/registros/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const result = await pool.query('DELETE FROM registros WHERE id = $1 AND cliente_id = $2 RETURNING id, cliente_id, placa, motorista', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Registro não encontrado' });
    res.json({ mensagem: 'Registro excluído com sucesso' });
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Exclusao', 'veiculo', result.rows[0].placa, 'Motorista: ' + (result.rows[0].motorista||''));
  } catch (err) {
    console.error('Erro ao excluir registro:', err);
    res.status(500).json({ erro: 'Erro ao excluir registro' });
  }
});

app.get('/api/auto-preenchimento', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { motorista, placa, empresa, cnh } = req.query;
    const cid = req.usuario.cliente_id;
    const params = [cid];
    const conds = [];
    if (motorista) { params.push(`%${motorista}%`); conds.push(`motorista ILIKE $${params.length}`); }
    if (placa) { params.push(`%${placa}%`); conds.push(`placa ILIKE $${params.length}`); }
    if (empresa) { params.push(`%${empresa}%`); conds.push(`empresa ILIKE $${params.length}`); }
    if (cnh) { const digits = cnh.replace(/[^0-9]/g, ''); if(digits) { params.push(`%${digits}%`); conds.push(`regexp_replace(cnh, '[^0-9]', '', 'g') ILIKE $${params.length}`); } }
    if (conds.length === 0) return res.json(null);
    const sql = `SELECT DISTINCT ON (COALESCE(NULLIF(motorista,''),placa)) motorista, placa, modelo, empresa, cnh, finalidade, entrada
                 FROM registros WHERE cliente_id = $1 AND (${conds.join(' OR ')}) AND motorista != ''
                 ORDER BY COALESCE(NULLIF(motorista,''),placa), id DESC`;
    const result = await pool.query(sql, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Erro no auto-preenchimento:', err);
    res.status(500).json({ erro: 'Erro ao buscar dados' });
  }
});

app.get('/api/motoristas-lista', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT motorista, placa, empresa, cnh FROM registros
       WHERE cliente_id = $1 AND motorista != '' ORDER BY motorista ASC`,
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar motoristas:', err);
    res.status(500).json({ erro: 'Erro ao listar motoristas' });
  }
});

app.get('/api/empresas-lista', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const campo = req.query.campo;
    const q = (req.query.q || '').trim();
    if (!campo) {
      const filtro = q ? ` AND empresa ILIKE '%' || $2 || '%'` : '';
      const params = q ? [req.usuario.cliente_id, q] : [req.usuario.cliente_id];
      const result = await pool.query(
        `SELECT DISTINCT empresa FROM registros WHERE cliente_id = $1 AND empresa != ''${filtro} ORDER BY empresa ASC LIMIT 50`, params
      );
      return res.json(result.rows);
    }
    const camposPermitidos = ['empresa', 'placa', 'cnh', 'motorista', 'modelo'];
    if (!camposPermitidos.includes(campo)) return res.json([]);
    const filtro = q ? ` AND ${campo} ILIKE '%' || $2 || '%'` : '';
    const params = q ? [req.usuario.cliente_id, q] : [req.usuario.cliente_id];
    const result = await pool.query(
      `SELECT DISTINCT ${campo} FROM registros WHERE cliente_id = $1 AND ${campo} != '' AND ${campo} IS NOT NULL${filtro} ORDER BY ${campo} ASC LIMIT 50`, params
    );
    const preParams = q ? [req.usuario.cliente_id, q] : [req.usuario.cliente_id];
    const preResult = await pool.query(
      `SELECT DISTINCT ${campo} FROM pre_registros WHERE cliente_id = $1 AND ${campo} != '' AND ${campo} IS NOT NULL${filtro} ORDER BY ${campo} ASC LIMIT 50`, preParams
    );
    const todos = new Set();
    result.rows.forEach(r => { if(r[campo]) todos.add(r[campo]); });
    preResult.rows.forEach(r => { if(r[campo]) todos.add(r[campo]); });
    res.json(Array.from(todos).sort().slice(0, 50).map(v => ({ [campo]: v })));
  } catch (err) {
    console.error('Erro ao listar sugestoes:', err);
    res.status(500).json({ erro: 'Erro ao listar' });
  }
});

app.get('/api/empresas-lista-pre', apiLimiter, async (req, res) => {
  try {
    const cid = req.query.cliente_id;
    if (!cid || !/^\d+$/.test(String(cid))) return res.json([]);
    const campo = req.query.campo;
    const q = (req.query.q || '').trim();
    if (!campo) return res.json([]);
    const camposPermitidos = ['empresa', 'placa', 'cnh', 'motorista', 'modelo'];
    if (!camposPermitidos.includes(campo)) return res.json([]);
    const filtro = q ? ` AND ${campo} ILIKE '%' || $2 || '%'` : '';
    const params = q ? [cid, q] : [cid];
    const result = await pool.query(
      `SELECT DISTINCT ${campo} FROM registros WHERE cliente_id = $1 AND ${campo} != '' AND ${campo} IS NOT NULL${filtro} ORDER BY ${campo} ASC LIMIT 50`, params
    );
    const preResult = await pool.query(
      `SELECT DISTINCT ${campo} FROM pre_registros WHERE cliente_id = $1 AND ${campo} != '' AND ${campo} IS NOT NULL${filtro} ORDER BY ${campo} ASC LIMIT 50`, params
    );
    const todos = new Set();
    result.rows.forEach(r => { if(r[campo]) todos.add(r[campo]); });
    preResult.rows.forEach(r => { if(r[campo]) todos.add(r[campo]); });
    res.json(Array.from(todos).sort().slice(0, 50).map(v => ({ [campo]: v })));
  } catch (err) {
    console.error('Erro ao listar sugestoes:', err);
    res.status(500).json({ erro: 'Erro ao buscar sugestoes' });
  }
});

app.get('/api/visitantes-lista', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const campo = req.query.campo;
    const q = (req.query.q || '').trim();
    if (campo && campo === 'cpf') {
      const filtro = q ? ` AND cpf ILIKE '%' || $2 || '%'` : '';
      const params = q ? [req.usuario.cliente_id, q] : [req.usuario.cliente_id];
      const result = await pool.query(
        `SELECT DISTINCT cpf FROM visitantes WHERE cliente_id = $1 AND cpf != '' AND cpf IS NOT NULL${filtro} ORDER BY cpf ASC LIMIT 50`, params
      );
      const preResult = await pool.query(
        `SELECT DISTINCT cpf FROM pre_registros_visitantes WHERE cliente_id = $1 AND cpf != '' AND cpf IS NOT NULL${filtro} ORDER BY cpf ASC LIMIT 50`, params
      );
      const todos = new Set();
      result.rows.forEach(r => { if(r.cpf) todos.add(r.cpf); });
      preResult.rows.forEach(r => { if(r.cpf) todos.add(r.cpf); });
      return res.json(Array.from(todos).sort().slice(0, 50).map(v => ({ cpf: v })));
    }
    const filtro = q ? ` AND nome ILIKE '%' || $2 || '%'` : '';
    const params = q ? [req.usuario.cliente_id, q] : [req.usuario.cliente_id];
    const result = await pool.query(
      `SELECT DISTINCT nome, cpf, empresa FROM visitantes
       WHERE cliente_id = $1 AND nome != ''${filtro} ORDER BY nome ASC LIMIT 50`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar visitantes:', err);
    res.status(500).json({ erro: 'Erro ao listar visitantes' });
  }
});

app.get('/api/auto-preenchimento-visitante', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { nome, cpf, empresa } = req.query;
    const cid = req.usuario.cliente_id;
    const params = [cid];
    const conds = [];
    if (nome) { params.push(`%${nome}%`); conds.push(`nome ILIKE $${params.length}`); }
    if (cpf) { const digits = cpf.replace(/[^0-9]/g, ''); if(digits) { params.push(`%${digits}%`); conds.push(`regexp_replace(cpf, '[^0-9]', '', 'g') ILIKE $${params.length}`); } }
    if (empresa) { params.push(`%${empresa}%`); conds.push(`empresa ILIKE $${params.length}`); }
    if (conds.length === 0) return res.json(null);
    const sql = `SELECT DISTINCT ON (COALESCE(NULLIF(nome,''),cpf)) nome, cpf, empresa
                 FROM visitantes WHERE cliente_id = $1 AND (${conds.join(' OR ')}) AND nome != ''
                 ORDER BY COALESCE(NULLIF(nome,''),cpf), id DESC`;
    const result = await pool.query(sql, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Erro no auto-preenchimento visitante:', err);
    res.status(500).json({ erro: 'Erro ao buscar dados' });
  }
});

app.get('/api/resumo', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const [result, visitResult, motoristasResult] = await Promise.all([
      pool.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE saida = '')::int AS aguardando,
          COUNT(*) FILTER (WHERE saida != '')::int AS saidas
        FROM registros WHERE cliente_id = $1 AND data_registro = CURRENT_DATE
      `, [req.usuario.cliente_id]),
      pool.query(`
        SELECT
          COUNT(*)::int AS visitantes_total,
          COUNT(*) FILTER (WHERE saida = '')::int AS visitantes_aguardando,
          COUNT(*) FILTER (WHERE saida != '')::int AS visitantes_saidas
        FROM visitantes WHERE cliente_id = $1 AND data_registro = CURRENT_DATE
      `, [req.usuario.cliente_id]),
      pool.query(
        'SELECT COUNT(*)::int AS total_motoristas FROM contas_motoristas WHERE cliente_id = $1 AND ativo = TRUE',
        [req.usuario.cliente_id]
      )
    ]);
    const dados = result.rows[0];
    const vis = visitResult.rows[0];
    const mot = motoristasResult.rows[0];
    res.json({
      total: dados.total,
      aguardando: dados.aguardando,
      saidas: dados.saidas,
      visitantes_total: vis.visitantes_total,
      visitantes_aguardando: vis.visitantes_aguardando,
      visitantes_saidas: vis.visitantes_saidas,
      total_motoristas: mot.total_motoristas
    });
  } catch (err) {
    console.error('Erro ao buscar resumo:', err);
    res.status(500).json({ erro: 'Erro ao buscar resumo' });
  }
});

app.get('/api/usuarios', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nome, usuario, ativo, criado_em FROM usuarios WHERE cliente_id = $1 ORDER BY nome',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar usuários:', err);
    res.status(500).json({ erro: 'Erro ao buscar usuários' });
  }
});

app.post('/api/usuarios', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { nome, usuario, senha } = req.body;
    if (!nome || !usuario || !senha) return res.status(400).json({ erro: 'Nome, usuário e senha são obrigatórios' });
    if (senha.length < 8) return res.status(400).json({ erro: 'Senha deve ter pelo menos 8 caracteres' });
    if (senha.length > 100) return res.status(400).json({ erro: 'Senha muito longa' });
    const errComplexidade1 = validarComplexidadeSenha(senha);
    if (errComplexidade1) return res.status(400).json({ erro: errComplexidade1 });
    if (usuario.length < 3) return res.status(400).json({ erro: 'Usuário deve ter pelo menos 3 caracteres' });
    const senhaHash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (cliente_id, nome, usuario, senha) VALUES ($1, $2, $3, $4) RETURNING id, nome, usuario',
      [req.usuario.cliente_id, sanitizarString(nome).toUpperCase(), usuario.toLowerCase(), senhaHash]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    console.error('Erro ao criar usuário:', err);
    res.status(500).json({ erro: 'Erro ao criar usuário' });
  }
});

app.put('/api/config', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { nome, senha } = req.body;
    if (senha && (senha.length < 8 || senha.length > 100)) return res.status(400).json({ erro: 'Senha deve ter entre 8 e 100 caracteres' });
    if (senha) { const errC = validarComplexidadeSenha(senha); if (errC) return res.status(400).json({ erro: errC }); }
    if (senha) {
      const senhaHash = await bcrypt.hash(senha, 10);
      await pool.query('UPDATE usuarios SET nome=$1, senha=$2, trocar_senha=FALSE WHERE id=$3', [nome, senhaHash, req.usuario.id]);
    } else {
      await pool.query('UPDATE usuarios SET nome=$1 WHERE id=$2', [nome, req.usuario.id]);
    }
    const result = await pool.query('SELECT id, nome, usuario FROM usuarios WHERE id=$1', [req.usuario.id]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao atualizar config:', err);
    res.status(500).json({ erro: 'Erro ao salvar configurações' });
  }
});

app.get('/api/visitantes', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, cliente_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs, entrada, saida, posicao, data_registro FROM visitantes WHERE cliente_id = $1 AND data_registro = CURRENT_DATE ORDER BY id ASC',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar visitantes:', err);
    res.status(500).json({ erro: 'Erro ao buscar visitantes' });
  }
});

app.post('/api/visitantes', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs } = req.body;
    if (!nome) return res.status(400).json({ erro: 'Nome é obrigatório' });
    const errNome = validarString(nome, 2, 100, 'Nome');
    if (errNome) return res.status(400).json({ erro: errNome });
    const errCpf = validarCpf(cpf);
    if (errCpf) return res.status(400).json({ erro: errCpf });
    const errEmpresaV = validarString(empresa, 0, 100, 'Empresa');
    if (errEmpresaV) return res.status(400).json({ erro: errEmpresaV });
    // Detecção de duplicado: mesmo CPF sem saída no mesmo dia
    const cpfDigits = (cpf||'').replace(/[^0-9]/g, '');
    if (cpfDigits.length === 11) {
      const dupV = await pool.query(
        `SELECT id FROM visitantes WHERE cliente_id = $1 AND cpf = $2 AND data_registro = CURRENT_DATE AND saida = ''`,
        [req.usuario.cliente_id, cpfDigits]
      );
      if (dupV.rows.length > 0) return res.status(409).json({ erro: 'Ja existe um visitante com este CPF aguardando saida.' });
    }
    const hora = new Date().toLocaleTimeString('pt-BR'); // Sempre do servidor
    const cid = req.usuario.cliente_id;
    const pos = await pool.query(
      `SELECT COALESCE(MAX(posicao), 0) + 1 AS prox FROM visitantes WHERE cliente_id = $1 AND data_registro = CURRENT_DATE`,
      [cid]
    );
    const result = await pool.query(
      `INSERT INTO visitantes (cliente_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs, entrada, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id, cliente_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs, entrada, saida, posicao, data_registro`,
      [cid, sanitizarString(nome).toUpperCase(), (cpf||'').replace(/[^0-9]/g, ''), (rg||'').replace(/[^0-9A-Za-z]/g, ''), sanitizarString(empresa), sanitizarString(tipo), sanitizarString(cracha).substring(0,50), (telefone||'').replace(/[^0-9()+\-\s]/g, '').substring(0,30), sanitizarString(setor_visitado).substring(0,100), sanitizarString(autorizado_por).substring(0,100), sanitizarString(nota).substring(0,50), sanitizarString(obs).substring(0,500), hora, pos.rows[0].prox]
    );
    res.status(201).json(result.rows[0]);
    logAuditoria(cid, req.usuario?.nome || '', 'Entrada', 'visitante', nome.toUpperCase(), 'Empresa: ' + (empresa||'') + ' | Tipo: ' + (tipo||''));
  } catch (err) {
    console.error('Erro ao criar visitante:', err);
    res.status(500).json({ erro: 'Erro ao criar visitante' });
  }
});

app.put('/api/visitantes/:id/saida', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const hora = new Date().toLocaleTimeString('pt-BR'); // Sempre do servidor
    const result = await pool.query(
      'UPDATE visitantes SET saida = $1 WHERE id = $2 AND saida = $3 AND cliente_id = $4 RETURNING id, cliente_id, nome, cpf, saida',
      [hora, req.params.id, '', req.usuario.cliente_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Visitante não encontrado ou já possui saída' });
    res.json(result.rows[0]);
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Saida', 'visitante', result.rows[0].nome, 'Saida registrada as ' + hora);
  } catch (err) {
    console.error('Erro ao marcar saída:', err);
    res.status(500).json({ erro: 'Erro ao marcar saída' });
  }
});

app.delete('/api/visitantes/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const result = await pool.query('DELETE FROM visitantes WHERE id = $1 AND cliente_id = $2 RETURNING id, cliente_id, nome, cpf', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Visitante não encontrado' });
    res.json({ mensagem: 'Visitante excluído com sucesso' });
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Exclusao', 'visitante', result.rows[0].nome, 'CPF: ' + (result.rows[0].cpf||''));
  } catch (err) {
    console.error('Erro ao excluir visitante:', err);
    res.status(500).json({ erro: 'Erro ao excluir visitante' });
  }
});

app.post('/api/pre-registro', preRegistroLimiter, async (req, res) => {
  try {
    const { cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs } = req.body;
    const finalEmpresa = empresa || '';
    const finalMotorista = motorista || '';
    if (!cliente_id || !finalMotorista || !placa) return res.status(400).json({ erro: 'Empresa, motorista e placa são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    const placaPre = placa.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (placaPre.length < 6 || placaPre.length > 8) return res.status(400).json({ erro: 'Placa invalida' });
    const result = await pool.query(
      `INSERT INTO pre_registros (cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs, criado_em`,
      [cliente_id, sanitizarString(finalEmpresa).toUpperCase(), sanitizarString(finalMotorista).toUpperCase(), sanitizarString(cnh).substring(0,20), placaPre, sanitizarString(modelo).substring(0,100), sanitizarString(finalidade).substring(0,50), sanitizarString(nota).substring(0,50), sanitizarString(obs).substring(0,500)]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro no pre-registro:', err);
    res.status(500).json({ erro: 'Erro ao realizar pré-registro' });
  }
});

app.post('/api/cadastro-motorista', preRegistroLimiter, async (req, res) => {
  try {
    const { cliente_id, nome, usuario, senha, empresa } = req.body;
    if (!cliente_id || !nome || !usuario || !senha) return res.status(400).json({ erro: 'Nome, usuário e senha são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    if (senha.length < 8) return res.status(400).json({ erro: 'Senha deve ter pelo menos 8 caracteres' });
    if (senha.length > 100) return res.status(400).json({ erro: 'Senha muito longa' });
    const errComp2 = validarComplexidadeSenha(senha);
    if (errComp2) return res.status(400).json({ erro: errComp2 });
    const errUsuario = validarString(usuario, 3, 50, 'Usuario');
    if (errUsuario) return res.status(400).json({ erro: errUsuario });
    const existe = await pool.query('SELECT id FROM contas_motoristas WHERE cliente_id = $1 AND usuario = $2', [cliente_id, usuario.toLowerCase()]);
    if (existe.rows.length > 0) return res.status(400).json({ erro: 'Usuário já existe' });
    const senhaHash = await bcrypt.hash(senha, 10);
    const senhaExibicao = senha.substring(0, 20);
    const result = await pool.query(
      'INSERT INTO contas_motoristas (cliente_id, usuario, senha, senha_exibicao, nome, empresa, ativo) VALUES ($1, $2, $3, $4, $5, $6, FALSE) RETURNING id, usuario, nome',
      [cliente_id, usuario.toLowerCase(), senhaHash, senhaExibicao, nome.toUpperCase(), empresa||'']
    );
    // Notificar portaria sobre novo cadastro de motorista
    await pool.query('INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)', [
      cliente_id, 'novo_cadastro', 'Novo cadastro de motorista', 'Motorista: ' + (nome||'').toUpperCase() + (empresa ? ' | Empresa: ' + empresa : '') + ' | Aguardando ativacao'
    ]);
    res.status(201).json({ mensagem: 'Conta criada com sucesso. Aguarde a ativação da portaria.', motorista: result.rows[0] });
  } catch (err) {
    console.error('Erro ao cadastrar motorista:', err);
    res.status(500).json({ erro: 'Erro ao criar conta' });
  }
});

// Verificar se conta de motorista esta ativa (usado pelo app para auto-check)
app.get('/api/verificar-ativacao', apiLimiter, async (req, res) => {
  try {
    const { cliente_id, usuario } = req.query;
    if (!cliente_id || !usuario) return res.status(400).json({ erro: 'cliente_id e usuario obrigatorios' });
    const result = await pool.query('SELECT ativo FROM contas_motoristas WHERE cliente_id = $1 AND usuario = $2', [parseInt(cliente_id), usuario.toLowerCase()]);
    console.log('[VERIFICAR_ATIVACAO] cliente_id:', cliente_id, 'usuario:', usuario, 'resultado:', result.rows.length > 0 ? 'ativo=' + result.rows[0].ativo : 'nao encontrado');
    if (!result.rows.length) return res.json({ ativo: false });
    res.json({ ativo: result.rows[0].ativo });
  } catch (err) {
    console.error('Erro ao verificar ativacao:', err);
    res.status(500).json({ erro: 'Erro ao verificar' });
  }
});

app.post('/api/login-motorista', loginLimiter, async (req, res) => {
  try {
    const { usuario, senha, cliente_id } = req.body;
    if (!usuario || !senha || !cliente_id) return res.status(400).json({ erro: 'Usuário, senha e empresa são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    const lockKey = 'motorista:' + cliente_id + ':' + usuario.toLowerCase();
    if (checkLockout(lockKey)) return res.status(429).json({ erro: 'Conta temporariamente bloqueada. Tente novamente em 15 minutos.' });
    const result = await pool.query('SELECT id, nome, usuario, senha, cliente_id FROM contas_motoristas WHERE cliente_id = $1 AND usuario = $2 AND ativo = TRUE', [cliente_id, usuario.toLowerCase()]);
    if (result.rows.length === 0) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    const conta = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, conta.senha);
    if (!senhaValida) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    clearAttempts(lockKey);
    const token = jwt.sign({ id: conta.id, nome: conta.nome, cliente_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, motorista: { id: conta.id, nome: conta.nome } });
  } catch (err) {
    console.error('Erro no login motorista:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

// === MOTORISTA AUTH MIDDLEWARE ===
function motoristaAuthMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ erro: 'Token não fornecido' });
  }
  try {
    const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
    if (decoded.admin) return res.status(401).json({ erro: 'Token inválido' });
    req.motorista = decoded;
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

// === MOTORISTA LOCALIZACAO (GPS) ===
app.post('/api/motorista/localizacao', motoristaAuthMiddleware, apiLimiter, async (req, res) => {
  try {
    const { lat, lng, placa, empresa, modelo, finalidade, cnh, nota, obs } = req.body;
    if (lat === undefined || lng === undefined) return res.status(400).json({ erro: 'Coordenadas obrigatórias' });
    const latNum = parseFloat(lat);
    const lngNum = parseFloat(lng);
    if (isNaN(latNum) || isNaN(lngNum)) return res.status(400).json({ erro: 'Coordenadas inválidas' });
    // Verificar última posição para só fazer geocoding se mudou > 100m
    const ultima = await pool.query('SELECT lat, lng, rua FROM localizacoes_motoristas WHERE motorista_id = $1', [req.motorista.id]);
    var rua = '';
    if (ultima.rows.length > 0) {
      const dlat = latNum - ultima.rows[0].lat;
      const dlng = lngNum - ultima.rows[0].lng;
      const dist = Math.sqrt(dlat * dlat + dlng * dlng) * 111000;
      if (dist > 100) {
        rua = await obterRua(latNum, lngNum);
      } else {
        rua = ultima.rows[0].rua || '';
      }
    } else {
      rua = await obterRua(latNum, lngNum);
    }
    await pool.query('DELETE FROM localizacoes_motoristas WHERE motorista_id = $1', [req.motorista.id]);
    await pool.query(
      `INSERT INTO localizacoes_motoristas (motorista_id, cliente_id, nome, placa, empresa, lat, lng, rua, a_caminho, cnh, modelo, finalidade, nota, obs, atualizado_em)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9, $10, $11, $12, $13, NOW())`,
      [
      req.motorista.id,
      req.motorista.cliente_id,
      sanitizarString(req.motorista.nome || '').substring(0, 200),
      sanitizarString(placa || '').substring(0, 20),
      sanitizarString(empresa || '').substring(0, 200),
      latNum,
      lngNum,
      sanitizarString(rua).substring(0, 200),
      sanitizarString(cnh || '').substring(0, 50),
      sanitizarString(modelo || '').substring(0, 100),
      sanitizarString(finalidade || '').substring(0, 100),
      sanitizarString(nota || '').substring(0, 100),
      sanitizarString(obs || '').substring(0, 500)
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Erro ao salvar localizacao:', err);
    res.status(500).json({ erro: 'Erro ao salvar localização' });
  }
});

app.post('/api/motorista/cheguei', motoristaAuthMiddleware, apiLimiter, async (req, res) => {
  try {
    await pool.query('UPDATE localizacoes_motoristas SET a_caminho = FALSE, chegou = TRUE, chegada_em = NOW(), atualizado_em = NOW() WHERE motorista_id = $1 AND cliente_id = $2', [
      req.motorista.id,
      req.motorista.cliente_id
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Erro ao marcar chegada:', err);
    res.status(500).json({ erro: 'Erro ao marcar chegada' });
  }
});

app.get('/api/localizacoes', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        l.motorista_id, l.nome, l.placa, l.empresa, l.lat, l.lng, l.rua,
        l.a_caminho, l.chegou, l.chegada_em, l.saida_logistica, l.saida_em,
        l.finalidade_tipo, l.atualizado_em,
        CASE WHEN r.id IS NOT NULL THEN TRUE ELSE FALSE END AS atendido_portaria
      FROM localizacoes_motoristas l
      LEFT JOIN registros r ON r.cliente_id = l.cliente_id
        AND r.placa = l.placa
        AND r.motorista = l.nome
        AND r.data_registro = CURRENT_DATE
      WHERE l.cliente_id = $1 AND (l.a_caminho = TRUE OR l.chegou = TRUE OR l.saida_logistica = TRUE) AND l.atualizado_em > NOW() - INTERVAL '24 hours'
      ORDER BY l.saida_logistica ASC, l.chegou ASC, l.atualizado_em DESC
    `, [req.usuario.cliente_id]);
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar localizacoes:', err);
    res.status(500).json({ erro: 'Erro ao buscar localizações' });
  }
});

// ENDPOINT TEMPORARIO - Limpar rastreamento (remover apos uso)
app.post('/api/localizacoes/limpar', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM localizacoes_motoristas WHERE cliente_id = $1', [req.usuario.cliente_id]);
    res.json({ ok: true, mensagem: 'Rastreamento limpo' });
  } catch (err) {
    console.error('Erro ao limpar localizacoes:', err);
    res.status(500).json({ erro: 'Erro ao limpar' });
  }
});

// Endpoint para o motorista verificar seu proprio status de rastreamento
app.get('/api/motorista/status', motoristaAuthMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT a_caminho, chegou, saida_logistica, chegada_em, saida_em FROM localizacoes_motoristas WHERE motorista_id = $1 AND cliente_id = $2 ORDER BY atualizado_em DESC LIMIT 1',
      [req.motorista.id, req.motorista.cliente_id]
    );
    if (!result.rows.length) return res.json({ ativo: false });
    const d = result.rows[0];
    res.json({
      ativo: true,
      a_caminho: d.a_caminho,
      chegou: d.chegou,
      saida_logistica: d.saida_logistica,
      chegada_em: d.chegada_em,
      saida_em: d.saida_em
    });
  } catch (err) {
    console.error('Erro ao buscar status motorista:', err);
    res.status(500).json({ erro: 'Erro ao buscar status' });
  }
});

app.get('/api/pre-registros', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT pr.id, pr.cliente_id, pr.empresa, pr.motorista, pr.cnh, pr.placa, pr.modelo, pr.finalidade, pr.nota, pr.obs, pr.criado_em,
              COALESCE(lm.a_caminho, FALSE) AS gps_a_caminho, COALESCE(lm.chegou, FALSE) AS gps_chegou, lm.chegada_em AS gps_chegada_em
       FROM pre_registros pr
       LEFT JOIN LATERAL (
         SELECT a_caminho, chegou, chegada_em
         FROM localizacoes_motoristas
         WHERE cliente_id = pr.cliente_id AND placa = pr.placa
         ORDER BY atualizado_em DESC LIMIT 1
       ) lm ON true
       WHERE pr.cliente_id = $1
       ORDER BY pr.id ASC`,
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar pre-registros:', err);
    res.status(500).json({ erro: 'Erro ao buscar pré-registros' });
  }
});

app.post('/api/pre-registros/:id/confirmar', authMiddleware, apiLimiter, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
    const cid = req.usuario.cliente_id;
    const pre = await pool.query('SELECT id, cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs, criado_em FROM pre_registros WHERE id = $1 AND cliente_id = $2', [req.params.id, cid]);
    if (pre.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    const d = pre.rows[0];
    const hora = new Date().toLocaleTimeString('pt-BR'); // Sempre do servidor
    const hoje = new Date().toLocaleDateString('en-CA'); // Sempre do servidor
    const pos = await pool.query(
      `SELECT COALESCE(MAX(posicao), 0) + 1 AS prox FROM registros WHERE cliente_id = $1 AND data_registro = $2`,
      [cid, hoje]
    );
    const posicao = pos.rows[0].prox;
    const registro = await pool.query(
      `INSERT INTO registros (cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, nota, obs, data_registro, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id, cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, saida, nota, obs, posicao, data_registro`,
      [cid, hora, d.placa, d.modelo, d.finalidade, d.empresa, d.motorista, d.cnh, hora, d.nota || '', d.obs, hoje, posicao]
    );
    await pool.query('DELETE FROM pre_registros WHERE id = $1', [req.params.id]);
    // Atualizar localizacoes_motoristas: marcar motorista como "chegou" no rastreamento/logistica
    await pool.query(
      'UPDATE localizacoes_motoristas SET a_caminho = FALSE, chegou = TRUE, chegada_em = NOW(), cnh = $3, modelo = $4, finalidade = $5, nota = $6, obs = $7, atualizado_em = NOW() WHERE cliente_id = $1 AND placa = $2 AND a_caminho = TRUE AND chegou = FALSE',
      [cid, d.placa, sanitizarString(d.cnh||'').substring(0,50), sanitizarString(d.modelo||'').substring(0,100), sanitizarString(d.finalidade||'').substring(0,100), sanitizarString(d.nota||'').substring(0,100), sanitizarString(d.obs||'').substring(0,500)]
    ).catch(() => {});
    res.status(201).json(registro.rows[0]);
    logAuditoria(cid, req.usuario?.nome || '', 'Confirmacao pre-registro', 'veiculo', d.placa, 'Motorista: ' + (d.motorista||'') + ' | Empresa: ' + d.empresa);
    // Notificar logística via WhatsApp (entrada confirmada)
    whatsapp.notificarEntrada(pool, cid, { empresa: d.empresa, motorista: d.motorista, placa: d.placa, finalidade: d.finalidade, hora }).catch(() => {});
    // Notificar via Email (entrada confirmada)
    email.notificarEntrada(pool, cid, { empresa: d.empresa, motorista: d.motorista, placa: d.placa, finalidade: d.finalidade, hora }).catch(() => {});
    // Criar notificacao no sistema (portaria + logistica)
    pool.query('INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)', [cid, 'entrada', 'Veículo aguardando liberação do pátio', 'Motorista: ' + (d.motorista||'') + ' | Placa: ' + d.placa + ' | Empresa: ' + d.empresa]).catch(() => {});
  } catch (err) {
    console.error('Erro ao confirmar pre-registro:', err);
    res.status(500).json({ erro: 'Erro ao confirmar pré-registro' });
  }
});

app.delete('/api/pre-registros/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const result = await pool.query('DELETE FROM pre_registros WHERE id = $1 AND cliente_id = $2 RETURNING id, cliente_id, placa, motorista, empresa', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    res.json({ mensagem: 'Pré-registro excluído' });
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Exclusao pre-registro', 'veiculo', result.rows[0].placa, 'Motorista: ' + (result.rows[0].motorista||''));
  } catch (err) {
    console.error('Erro ao excluir pre-registro:', err);
    res.status(500).json({ erro: 'Erro ao excluir pré-registro' });
  }
});

app.get('/api/contas-motoristas', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, usuario, nome, empresa, ativo, senha_exibicao, criado_em FROM contas_motoristas WHERE cliente_id = $1 ORDER BY nome',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar contas:', err);
    res.status(500).json({ erro: 'Erro ao buscar contas' });
  }
});

app.post('/api/contas-motoristas', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { usuario, senha, nome, empresa } = req.body;
    if (!usuario || !senha || !nome) return res.status(400).json({ erro: 'Usuário, senha e nome são obrigatórios' });
    if (senha.length < 8 || senha.length > 100) return res.status(400).json({ erro: 'Senha deve ter entre 8 e 100 caracteres' });
    const errComp3 = validarComplexidadeSenha(senha);
    if (errComp3) return res.status(400).json({ erro: errComp3 });
    const senhaHash = await bcrypt.hash(senha, 10);
    const senhaExibicao = senha.substring(0, 20);
    const cid = req.usuario.cliente_id;
    const result = await pool.query(
      'INSERT INTO contas_motoristas (cliente_id, usuario, senha, senha_exibicao, nome, empresa, ativo) VALUES ($1, $2, $3, $4, $5, $6, FALSE) RETURNING id, usuario, nome, empresa',
      [cid, usuario.toLowerCase(), senhaHash, senhaExibicao, nome.toUpperCase(), empresa||'']
    );
    res.status(201).json(result.rows[0]);
    // Notificar portaria sobre novo cadastro de motorista
    pool.query('INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)', [
      cid, 'novo_cadastro', 'Novo cadastro de motorista', 'Motorista: ' + (nome||'').toUpperCase() + (empresa ? ' | Empresa: ' + empresa : '')
    ]).catch(() => {});
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    console.error('Erro ao criar conta motorista:', err);
    res.status(500).json({ erro: 'Erro ao criar conta' });
  }
});

app.put('/api/contas-motoristas/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { nome, ativo, empresa } = req.body;
    const updates = []; const params = [];
    if (nome) { params.push(sanitizarString(nome).toUpperCase()); updates.push(`nome = $${params.length}`); }
    if (empresa !== undefined) { params.push(sanitizarString(empresa)); updates.push(`empresa = $${params.length}`); }
    if (ativo !== undefined) { params.push(ativo); updates.push(`ativo = $${params.length}`); }
    if (updates.length === 0) return res.status(400).json({ erro: 'Nada para atualizar' });
    params.push(req.params.id);
    params.push(req.usuario.cliente_id);
    await pool.query(`UPDATE contas_motoristas SET ${updates.join(', ')} WHERE id = $${params.length - 1} AND cliente_id = $${params.length}`, params);
    res.json({ mensagem: 'Conta atualizada' });
  } catch (err) {
    console.error('Erro ao atualizar conta:', err);
    res.status(500).json({ erro: 'Erro ao atualizar conta' });
  }
});

app.delete('/api/contas-motoristas/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const result = await pool.query('DELETE FROM contas_motoristas WHERE id = $1 AND cliente_id = $2 RETURNING id, nome', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Conta nao encontrada' });
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Exclusao conta motorista', 'motorista', '', 'Nome: ' + result.rows[0].nome);
    res.json({ mensagem: 'Conta excluida com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir conta motorista:', err);
    res.status(500).json({ erro: 'Erro ao excluir conta' });
  }
});

app.post('/api/cadastro-visitante', preRegistroLimiter, async (req, res) => {
  try {
    const { cliente_id, nome, usuario, senha, cpf, rg, empresa } = req.body;
    if (!cliente_id || !nome || !usuario || !senha) return res.status(400).json({ erro: 'Nome, usuário e senha são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    if (senha.length < 8) return res.status(400).json({ erro: 'Senha deve ter pelo menos 8 caracteres' });
    if (senha.length > 100) return res.status(400).json({ erro: 'Senha muito longa' });
    const errComp4 = validarComplexidadeSenha(senha);
    if (errComp4) return res.status(400).json({ erro: errComp4 });
    const errCpfV = validarCpf(cpf);
    if (errCpfV) return res.status(400).json({ erro: errCpfV });
    const existe = await pool.query('SELECT id FROM contas_visitantes WHERE cliente_id = $1 AND usuario = $2', [cliente_id, usuario.toLowerCase()]);
    if (existe.rows.length > 0) return res.status(400).json({ erro: 'Usuário já existe' });
    const senhaHash = await bcrypt.hash(senha, 10);
    const senhaExibicao = senha.substring(0, 20);
    const result = await pool.query(
      'INSERT INTO contas_visitantes (cliente_id, usuario, senha, senha_exibicao, nome, cpf, rg, empresa, ativo) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE) RETURNING id, usuario, nome',
      [cliente_id, usuario.toLowerCase(), senhaHash, senhaExibicao, nome.toUpperCase(), cpf||'', rg||'', empresa||'']
    );
    // Notificar portaria sobre novo cadastro de visitante
    await pool.query('INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)', [
      cliente_id, 'novo_cadastro', 'Novo cadastro de visitante', 'Visitante: ' + (nome||'').toUpperCase() + (empresa ? ' | Empresa: ' + empresa : '') + ' | Aguardando ativacao'
    ]);
    res.status(201).json({ mensagem: 'Conta criada. Aguarde ativação da portaria.', visitante: result.rows[0] });
  } catch (err) {
    console.error('Erro ao cadastrar visitante:', err);
    res.status(500).json({ erro: 'Erro ao criar conta' });
  }
});

app.post('/api/login-visitante', loginLimiter, async (req, res) => {
  try {
    const { usuario, senha, cliente_id } = req.body;
    if (!usuario || !senha || !cliente_id) return res.status(400).json({ erro: 'Usuário, senha e empresa são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    const lockKey = 'visitante:' + cliente_id + ':' + usuario.toLowerCase();
    if (checkLockout(lockKey)) return res.status(429).json({ erro: 'Conta temporariamente bloqueada. Tente novamente em 15 minutos.' });
    const result = await pool.query('SELECT id, nome, usuario, senha, cpf, empresa, cliente_id FROM contas_visitantes WHERE cliente_id = $1 AND usuario = $2 AND ativo = TRUE', [cliente_id, usuario.toLowerCase()]);
    if (result.rows.length === 0) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    const conta = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, conta.senha);
    if (!senhaValida) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    clearAttempts(lockKey);
    const token = jwt.sign({ id: conta.id, nome: conta.nome, cliente_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, visitante: { id: conta.id, nome: conta.nome, cpf: conta.cpf, empresa: conta.empresa } });
  } catch (err) {
    console.error('Erro no login visitante:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

app.post('/api/pre-registro-visitante', preRegistroLimiter, async (req, res) => {
  try {
    const { cliente_id, visitante_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs } = req.body;
    const finalNome = nome || '';
    if (!cliente_id || !finalNome) return res.status(400).json({ erro: 'Nome e empresa são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    const errCpfPreV = validarCpf(cpf);
    if (errCpfPreV) return res.status(400).json({ erro: errCpfPreV });
    const result = await pool.query(
      `INSERT INTO pre_registros_visitantes (cliente_id, visitante_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id, cliente_id, visitante_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs, criado_em`,
      [cliente_id, visitante_id || null, sanitizarString(finalNome).toUpperCase(), (cpf||'').replace(/[^0-9]/g, ''), (rg||'').replace(/[^0-9A-Za-z]/g, ''), sanitizarString(empresa), sanitizarString(tipo), sanitizarString(cracha).substring(0,50), (telefone||'').replace(/[^0-9()+\-\s]/g, '').substring(0,30), sanitizarString(setor_visitado).substring(0,100), sanitizarString(autorizado_por).substring(0,100), sanitizarString(nota).substring(0,50), sanitizarString(obs).substring(0,500)]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro no pre-registro visitante:', err);
    res.status(500).json({ erro: 'Erro ao realizar pré-registro' });
  }
});

app.get('/api/pre-registros-visitantes', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, cliente_id, visitante_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs, criado_em FROM pre_registros_visitantes WHERE cliente_id = $1 ORDER BY id ASC',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar pre-registros visitantes:', err);
    res.status(500).json({ erro: 'Erro ao buscar pré-registros de visitantes' });
  }
});

app.post('/api/pre-registros-visitantes/:id/confirmar', authMiddleware, apiLimiter, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
    const cid = req.usuario.cliente_id;
    const pre = await pool.query('SELECT id, cliente_id, visitante_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs, criado_em FROM pre_registros_visitantes WHERE id = $1 AND cliente_id = $2', [req.params.id, cid]);
    if (pre.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    const d = pre.rows[0];
    const hora = new Date().toLocaleTimeString('pt-BR'); // Sempre do servidor
    const hoje = new Date().toLocaleDateString('en-CA'); // Sempre do servidor
    const pos = await pool.query(
      `SELECT COALESCE(MAX(posicao), 0) + 1 AS prox FROM visitantes WHERE cliente_id = $1 AND data_registro = $2`,
      [cid, hoje]
    );
    const visitante = await pool.query(
      `INSERT INTO visitantes (cliente_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs, entrada, data_registro, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING id, cliente_id, nome, cpf, rg, empresa, tipo, cracha, telefone, setor_visitado, autorizado_por, nota, obs, entrada, saida, data_registro, posicao`,
      [cid, d.nome, d.cpf, d.rg||'', d.empresa, d.tipo||'', d.cracha||'', d.telefone||'', d.setor_visitado||'', d.autorizado_por||'', d.nota||'', d.obs||'', hora, hoje, pos.rows[0].prox]
    );
    await pool.query('DELETE FROM pre_registros_visitantes WHERE id = $1', [req.params.id]);
    res.status(201).json(visitante.rows[0]);
    logAuditoria(cid, req.usuario?.nome || '', 'Confirmacao pre-registro', 'visitante', d.nome, 'CPF: ' + (d.cpf||'') + ' | Empresa: ' + (d.empresa||''));
  } catch (err) {
    console.error('Erro ao confirmar pre-registro visitante:', err);
    res.status(500).json({ erro: 'Erro ao confirmar pre-registro de visitante' });
  }
});

app.delete('/api/pre-registros-visitantes/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const result = await pool.query('DELETE FROM pre_registros_visitantes WHERE id = $1 AND cliente_id = $2 RETURNING id, cliente_id, nome, cpf, empresa, rg, cracha, telefone', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    res.json({ mensagem: 'Pré-registro excluído' });
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Exclusao pre-registro', 'visitante', result.rows[0].nome, 'CPF: ' + (result.rows[0].cpf||''));
  } catch (err) {
    console.error('Erro ao excluir pre-registro visitante:', err);
    res.status(500).json({ erro: 'Erro ao excluir pré-registro' });
  }
});

app.post('/api/contas-visitantes', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { usuario, senha, nome, cpf, rg, empresa, telefone, setor_visitado } = req.body;
    if (!usuario || !senha || !nome) return res.status(400).json({ erro: 'Usuário, senha e nome são obrigatórios' });
    if (senha.length < 8 || senha.length > 100) return res.status(400).json({ erro: 'Senha deve ter entre 8 e 100 caracteres' });
    const errComp5 = validarComplexidadeSenha(senha);
    if (errComp5) return res.status(400).json({ erro: errComp5 });
    const errCpfCV = validarCpf(cpf);
    if (errCpfCV) return res.status(400).json({ erro: errCpfCV });
    const senhaHash = await bcrypt.hash(senha, 10);
    const senhaExibicao = senha.substring(0, 20);
    const cid = req.usuario.cliente_id;
    const result = await pool.query(
      'INSERT INTO contas_visitantes (cliente_id, usuario, senha, senha_exibicao, nome, cpf, rg, empresa, telefone, setor_visitado, ativo) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, FALSE) RETURNING id, usuario, nome',
      [cid, usuario.toLowerCase(), senhaHash, senhaExibicao, nome.toUpperCase(), cpf||'', rg||'', empresa||'', telefone||'', setor_visitado||'']
    );
    res.status(201).json(result.rows[0]);
    // Notificar portaria sobre novo cadastro de visitante
    pool.query('INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)', [
      cid, 'novo_cadastro', 'Novo cadastro de visitante', 'Visitante: ' + (nome||'').toUpperCase() + (empresa ? ' | Empresa: ' + empresa : '') + ' | Aguardando ativacao'
    ]).catch(() => {});
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    console.error('Erro ao criar conta visitante:', err);
    res.status(500).json({ erro: 'Erro ao criar conta' });
  }
});

app.get('/api/contas-visitantes', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, usuario, nome, cpf, rg, empresa, ativo, senha_exibicao, criado_em FROM contas_visitantes WHERE cliente_id = $1 ORDER BY nome',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar contas visitantes:', err);
    res.status(500).json({ erro: 'Erro ao buscar contas' });
  }
});

// Redefinir senha de motorista
app.put('/api/contas-motoristas/:id/redefinir-senha', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const cid = req.usuario.cliente_id;
    const conta = await pool.query('SELECT id FROM contas_motoristas WHERE id = $1 AND cliente_id = $2', [req.params.id, cid]);
    if (!conta.rows.length) return res.status(404).json({ erro: 'Conta nao encontrada' });
    const novaSenha = 'Mt' + crypto.randomBytes(4).toString('hex') + '!@';
    const senhaHash = await bcrypt.hash(novaSenha, 10);
    await pool.query('UPDATE contas_motoristas SET senha = $1, senha_exibicao = $2, trocar_senha = TRUE WHERE id = $3 AND cliente_id = $4', [senhaHash, novaSenha, req.params.id, cid]);
    res.json({ senha_exibicao: novaSenha });
  } catch (err) {
    console.error('Erro ao redefinir senha:', err);
    res.status(500).json({ erro: 'Erro ao redefinir senha' });
  }
});

app.put('/api/contas-visitantes/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { nome, ativo } = req.body;
    const updates = []; const params = [];
    if (nome) { params.push(sanitizarString(nome).toUpperCase()); updates.push(`nome = $${params.length}`); }
    if (ativo !== undefined) { params.push(ativo); updates.push(`ativo = $${params.length}`); }
    if (updates.length === 0) return res.status(400).json({ erro: 'Nada para atualizar' });
    params.push(req.params.id);
    params.push(req.usuario.cliente_id);
    await pool.query(`UPDATE contas_visitantes SET ${updates.join(', ')} WHERE id = $${params.length - 1} AND cliente_id = $${params.length}`, params);
    res.json({ mensagem: 'Conta atualizada' });
  } catch (err) {
    console.error('Erro ao atualizar conta visitante:', err);
    res.status(500).json({ erro: 'Erro ao atualizar conta' });
  }
});

app.delete('/api/contas-visitantes/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const result = await pool.query('DELETE FROM contas_visitantes WHERE id = $1 AND cliente_id = $2 RETURNING id, nome', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Conta nao encontrada' });
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Exclusao conta visitante', 'visitante', '', 'Nome: ' + result.rows[0].nome);
    res.json({ mensagem: 'Conta excluida com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir conta visitante:', err);
    res.status(500).json({ erro: 'Erro ao excluir conta' });
  }
});

// Redefinir senha de visitante
app.put('/api/contas-visitantes/:id/redefinir-senha', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const cid = req.usuario.cliente_id;
    const conta = await pool.query('SELECT id FROM contas_visitantes WHERE id = $1 AND cliente_id = $2', [req.params.id, cid]);
    if (!conta.rows.length) return res.status(404).json({ erro: 'Conta nao encontrada' });
    const novaSenha = 'Vi' + crypto.randomBytes(4).toString('hex') + '!@';
    const senhaHash = await bcrypt.hash(novaSenha, 10);
    await pool.query('UPDATE contas_visitantes SET senha = $1, senha_exibicao = $2, trocar_senha = TRUE WHERE id = $3 AND cliente_id = $4', [senhaHash, novaSenha, req.params.id, cid]);
    res.json({ senha_exibicao: novaSenha });
  } catch (err) {
    console.error('Erro ao redefinir senha visitante:', err);
    res.status(500).json({ erro: 'Erro ao redefinir senha' });
  }
});

app.get('/api/nome-empresa', authMiddleware, apiLimiter, async (req, res) => {
  try {
    if (!req.usuario.cliente_id) return res.json({ empresa: '' });
    const result = await pool.query('SELECT empresa FROM clientes WHERE id = $1', [req.usuario.cliente_id]);
    res.json({ empresa: result.rows[0] ? result.rows[0].empresa : '' });
  } catch (err) {
    res.json({ empresa: '' });
  }
});

app.get('/api/auditoria', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const result = await pool.query(
      'SELECT id, cliente_id, usuario, acao, tipo, alvo, detalhes, criado_em FROM logs_auditoria WHERE cliente_id = $1 ORDER BY criado_em DESC LIMIT $2',
      [req.usuario.cliente_id, limit]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar auditoria' });
  }
});

app.get('/api/mural', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, cliente_id, titulo, texto, prioridade, criado_em, atualizado_em FROM mural WHERE cliente_id = $1 ORDER BY prioridade DESC, criado_em DESC',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar mural' });
  }
});

app.post('/api/mural', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { titulo, texto, prioridade } = req.body;
    if (!titulo) return res.status(400).json({ erro: 'Titulo e obrigatorio' });
    const errMuralPost = validarString(titulo, 2, 200, 'Titulo');
    if (errMuralPost) return res.status(400).json({ erro: errMuralPost });
    const result = await pool.query(
      'INSERT INTO mural (cliente_id, titulo, texto, prioridade) VALUES ($1,$2,$3,$4) RETURNING id, cliente_id, titulo, texto, prioridade, criado_em',
      [req.usuario.cliente_id, sanitizarString(titulo), sanitizarString(texto).substring(0,2000), sanitizarString(prioridade) || 'normal']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao criar post' });
  }
});

app.put('/api/mural/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { titulo, texto, prioridade } = req.body;
    const errMural = titulo ? validarString(titulo, 2, 200, 'Titulo') : null;
    if (errMural) return res.status(400).json({ erro: errMural });
    const result = await pool.query(
      'UPDATE mural SET titulo = COALESCE($1, titulo), texto = COALESCE($2, texto), prioridade = COALESCE($3, prioridade), atualizado_em = NOW() WHERE id = $4 AND cliente_id = $5 RETURNING id, cliente_id, titulo, texto, prioridade, atualizado_em',
      [titulo !== undefined ? sanitizarString(titulo) : null, texto !== undefined ? sanitizarString(texto) : null, prioridade !== undefined ? sanitizarString(prioridade) : null, req.params.id, req.usuario.cliente_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Post nao encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao atualizar post' });
  }
});

app.delete('/api/mural/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const result = await pool.query('DELETE FROM mural WHERE id = $1 AND cliente_id = $2 RETURNING id', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Post nao encontrado' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao excluir post' });
  }
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/admin-login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    if (!usuario || !senha) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios' });
    const lockKey = 'admin:' + usuario.toLowerCase();
    if (checkLockout(lockKey)) return res.status(429).json({ erro: 'Conta temporariamente bloqueada. Tente novamente em 15 minutos.' });
    const result = await pool.query('SELECT id, nome, usuario, senha, trocar_senha FROM admin_users WHERE usuario = $1', [usuario.toLowerCase()]);
    if (result.rows.length === 0) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    const admin = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, admin.senha);
    if (!senhaValida) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    clearAttempts(lockKey);
    const token = jwt.sign({ id: admin.id, nome: admin.nome, usuario: admin.usuario, admin: true, trocar_senha: !!admin.trocar_senha }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, admin: { id: admin.id, nome: admin.nome, trocar_senha: !!admin.trocar_senha } });
  } catch (err) {
    console.error('Erro no login admin:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

app.put('/api/admin/config', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const { senha_atual, nova_senha, novo_usuario } = req.body;
    if (!senha_atual) return res.status(400).json({ erro: 'Senha atual e obrigatoria' });
    const result = await pool.query('SELECT senha FROM admin_users WHERE id = $1', [req.admin.id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Admin nao encontrado' });
    const senhaValida = await bcrypt.compare(senha_atual, result.rows[0].senha);
    if (!senhaValida) return res.status(401).json({ erro: 'Senha atual incorreta' });
    if (novo_usuario) {
      if (novo_usuario.length < 3) return res.status(400).json({ erro: 'Usuario deve ter pelo menos 3 caracteres' });
      if (!/^[a-z0-9_]+$/.test(novo_usuario)) return res.status(400).json({ erro: 'Usuario deve conter apenas letras minusculas, numeros e underline' });
      const dup = await pool.query('SELECT id FROM admin_users WHERE usuario = $1 AND id != $2', [novo_usuario.toLowerCase(), req.admin.id]);
      if (dup.rows.length > 0) return res.status(400).json({ erro: 'Este usuario ja esta em uso' });
    }
    if (nova_senha) {
      if (nova_senha.length < 8) return res.status(400).json({ erro: 'Nova senha deve ter pelo menos 8 caracteres' });
      const errC = validarComplexidadeSenha(nova_senha);
      if (errC) return res.status(400).json({ erro: errC });
    }
    if (novo_usuario && nova_senha) {
      const senhaHash = await bcrypt.hash(nova_senha, 10);
      await pool.query('UPDATE admin_users SET usuario = $1, senha = $2, trocar_senha = FALSE WHERE id = $3', [novo_usuario.toLowerCase(), senhaHash, req.admin.id]);
    } else if (novo_usuario) {
      await pool.query('UPDATE admin_users SET usuario = $1 WHERE id = $2', [novo_usuario.toLowerCase(), req.admin.id]);
    } else if (nova_senha) {
      const senhaHash = await bcrypt.hash(nova_senha, 10);
      await pool.query('UPDATE admin_users SET senha = $1, trocar_senha = FALSE WHERE id = $2', [senhaHash, req.admin.id]);
    }
    res.json({ sucesso: true, mensagem: 'Configuracoes alteradas com sucesso' });
  } catch (err) {
    console.error('Erro ao alterar config admin:', err);
    res.status(500).json({ erro: 'Erro ao alterar configuracoes' });
  }
});

app.get('/api/admin/clientes', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, empresa, cnpj, responsavel, email, telefone, telefone_fixo, plano, valor_mensal, data_expiracao, dominio, ativo, logistica_ativo, logistica_token, criado_em, whatsapp_ativo, whatsapp_provedor, whatsapp_telefone, whatsapp_telefone_notif, whatsapp_url, whatsapp_instancia, email_ativo, email_smtp_host, email_smtp_port, email_smtp_user, email_remetente, email_destinatario FROM clientes ORDER BY criado_em DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar clientes:', err);
    res.status(500).json({ erro: 'Erro ao buscar clientes' });
  }
});

app.post('/api/admin/clientes', adminMiddleware, apiLimiter, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { empresa, cnpj, responsavel, email, telefone, telefone_fixo, plano, valor_mensal, data_expiracao, dominio } = req.body;
    if (!empresa) return res.status(400).json({ erro: 'Empresa é obrigatória' });
    const errEmpresaAdmin = validarString(empresa, 2, 200, 'Empresa');
    if (errEmpresaAdmin) return res.status(400).json({ erro: errEmpresaAdmin });
    const errCnpj = validarString(cnpj, 0, 20, 'CNPJ');
    if (errCnpj) return res.status(400).json({ erro: errCnpj });
    const errResp = validarString(responsavel, 0, 100, 'Responsavel');
    if (errResp) return res.status(400).json({ erro: errResp });
    const errEmailAdmin = validarEmail(email);
    if (errEmailAdmin) return res.status(400).json({ erro: errEmailAdmin });
    const errTel = validarString(telefone, 0, 20, 'Telefone');
    if (errTel) return res.status(400).json({ erro: errTel });
    const errTelFixo = validarString(telefone_fixo, 0, 20, 'Telefone Fixo');
    if (errTelFixo) return res.status(400).json({ erro: errTelFixo });
    const cliResult = await client.query(
      `INSERT INTO clientes (empresa, cnpj, responsavel, email, telefone, telefone_fixo, plano, valor_mensal, data_expiracao, dominio)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, cliente_id, empresa, cnpj, responsavel, email, telefone, telefone_fixo, plano, valor_mensal, data_expiracao, dominio, ativo, criado_em`,
      [empresa.toUpperCase(), cnpj||'', responsavel||'', email||'', telefone||'', telefone_fixo||'', plano||'basico', valor_mensal||0, data_expiracao||null, dominio||'']
    );
    const cliente = cliResult.rows[0];
    const userLogin = empresa.toUpperCase().replace(/[^A-Z0-9]/g, '').substring(0, 20) + '_portaria';
    const defaultSenha = 'portaria123';
    const senhaHash = await bcrypt.hash(defaultSenha, 10);
    try {
      await client.query(
        'INSERT INTO usuarios (cliente_id, nome, usuario, senha, trocar_senha) VALUES ($1, $2, $3, $4, TRUE)',
        [cliente.id, 'PORTARIA ' + empresa.toUpperCase(), userLogin.toLowerCase(), senhaHash]
      );
    } catch (e) {
      console.log('Aviso: não criou usuário portaria:', e.message);
    }
    await client.query('COMMIT');
    pool.query('INSERT INTO historico_clientes (cliente_id, admin_usuario, acao, detalhes) VALUES ($1,$2,$3,$4)', [cliente.id, req.admin?.usuario || '', 'Cliente criado', 'Empresa: ' + empresa.toUpperCase()]).catch(()=>{});
    res.status(201).json({ ...cliente, portaria_usuario: userLogin.toLowerCase(), portaria_senha: defaultSenha });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Erro ao criar cliente:', err);
    res.status(500).json({ erro: 'Erro ao criar cliente' });
  } finally {
    client.release();
  }
});

app.put('/api/admin/clientes/:id', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
    const { empresa, cnpj, responsavel, email, telefone, telefone_fixo, plano, valor_mensal, data_expiracao, dominio, ativo } = req.body;
    const updates = []; const params = [];
    if (empresa !== undefined) { params.push(empresa.toUpperCase()); updates.push(`empresa = $${params.length}`); }
    if (cnpj !== undefined) { params.push(cnpj); updates.push(`cnpj = $${params.length}`); }
    if (responsavel !== undefined) { params.push(responsavel); updates.push(`responsavel = $${params.length}`); }
    if (email !== undefined) { params.push(email); updates.push(`email = $${params.length}`); }
    if (telefone !== undefined) { params.push(telefone); updates.push(`telefone = $${params.length}`); }
    if (telefone_fixo !== undefined) { params.push(telefone_fixo); updates.push(`telefone_fixo = $${params.length}`); }
    if (plano !== undefined) { params.push(plano); updates.push(`plano = $${params.length}`); }
    if (valor_mensal !== undefined) { params.push(valor_mensal); updates.push(`valor_mensal = $${params.length}`); }
    if (data_expiracao !== undefined) { params.push(data_expiracao); updates.push(`data_expiracao = $${params.length}`); }
    if (dominio !== undefined) { params.push(dominio); updates.push(`dominio = $${params.length}`); }
    if (ativo !== undefined) { params.push(ativo === true || ativo === 'true'); updates.push(`ativo = $${params.length}`); }
    if (updates.length === 0) return res.status(400).json({ erro: 'Nada para atualizar' });
    params.push(req.params.id);
    await pool.query(`UPDATE clientes SET ${updates.join(', ')} WHERE id = $${params.length}`, params);
    pool.query('INSERT INTO historico_clientes (cliente_id, admin_usuario, acao, detalhes) VALUES ($1,$2,$3,$4)', [req.params.id, req.admin?.usuario || '', 'Cliente atualizado', updates.join(', ')]).catch(()=>{});
    res.json({ mensagem: 'Cliente atualizado' });
  } catch (err) {
    console.error('Erro ao atualizar cliente:', err);
    res.status(500).json({ erro: 'Erro ao atualizar cliente' });
  }
});

app.delete('/api/admin/clientes/:id', adminMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cli = await client.query('SELECT id, empresa FROM clientes WHERE id = $1', [req.params.id]);
    if (cli.rows.length === 0) { await client.query('ROLLBACK'); client.release(); return res.status(404).json({ erro: 'Cliente não encontrado' }); }
    const clienteId = req.params.id;
    const clienteNome = cli.rows[0].empresa;
    await client.query('DELETE FROM faturamento WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM chamados WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM historico_clientes WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM logs_auditoria WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM mural WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM visitantes WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM registros WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM pre_registros WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM pre_registros_visitantes WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM usuarios WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM contas_motoristas WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM contas_visitantes WHERE cliente_id = $1', [clienteId]);
    await client.query('DELETE FROM clientes WHERE id = $1', [clienteId]);
    await client.query('COMMIT');
    client.release();
    pool.query('INSERT INTO historico_clientes (admin_usuario, acao, detalhes) VALUES ($1,$2,$3)', [req.admin?.usuario || '', 'Cliente excluido manualmente', 'Empresa: ' + clienteNome]).catch(()=>{});
    res.json({ mensagem: 'Cliente excluído com sucesso' });
  } catch (err) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Erro ao excluir cliente:', err);
    res.status(500).json({ erro: 'Erro ao excluir cliente' });
  }
});

app.get('/api/admin/clientes/:id/usuarios', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nome, usuario, senha_exibicao, ativo FROM usuarios WHERE cliente_id = $1 ORDER BY nome', [req.params.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar usuários' });
  }
});

app.post('/api/admin/clientes/:id/usuarios', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const { usuario, senha, nome } = req.body;
    const cliente_id = req.params.id;
    if (!/^\d+$/.test(cliente_id)) return res.status(400).json({ erro: 'ID de cliente invalido' });
    const cliRes = await pool.query('SELECT empresa FROM clientes WHERE id = $1', [cliente_id]);
    if (cliRes.rows.length === 0) return res.status(404).json({ erro: 'Cliente não encontrado' });
    const u = usuario || (cliRes.rows[0].empresa.toUpperCase().replace(/[^A-Z0-9]/g, '').substring(0, 20) + '_portaria');
    const s = senha || 'portaria123';
    const n = nome || 'PORTARIA ' + cliRes.rows[0].empresa.toUpperCase();
    const senhaHash = await bcrypt.hash(s, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (cliente_id, nome, usuario, senha, senha_exibicao, trocar_senha) VALUES ($1, $2, $3, $4, $5, TRUE) RETURNING id, nome, usuario, senha_exibicao',
      [cliente_id, n, u.toLowerCase(), senhaHash, s]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    res.status(500).json({ erro: 'Erro ao criar usuário' });
  }
});

app.get('/api/admin/dashboard', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const clientes = await pool.query('SELECT COUNT(*)::int AS total FROM clientes');
    const ativos = await pool.query("SELECT COUNT(*)::int AS total FROM clientes WHERE ativo = TRUE");
    const expirados = await pool.query("SELECT COUNT(*)::int AS total FROM clientes WHERE data_expiracao < CURRENT_DATE AND ativo = TRUE");
    const receita = await pool.query("SELECT COALESCE(SUM(valor_mensal), 0)::float AS total FROM clientes WHERE ativo = TRUE");
    const faturamento = await pool.query("SELECT COALESCE(SUM(valor), 0)::float AS total FROM faturamento");
    const recentes = await pool.query("SELECT id, valor, descricao, data_pagamento FROM faturamento ORDER BY data_pagamento DESC LIMIT 10");
    const planos = await pool.query("SELECT plano, COUNT(*)::int AS total FROM clientes GROUP BY plano");
    res.json({
      total_clientes: clientes.rows[0].total,
      clientes_ativos: ativos.rows[0].total,
      clientes_expirados: expirados.rows[0].total,
      receita_mensal: receita.rows[0].total,
      faturamento_total: faturamento.rows[0].total,
      faturamento_recente: recentes.rows,
      distribuicao_planos: planos.rows
    });
  } catch (err) {
    console.error('Erro no dashboard:', err);
    res.status(500).json({ erro: 'Erro ao carregar dashboard' });
  }
});

app.post('/api/admin/faturamento', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const { cliente_id, valor, descricao, data_pagamento } = req.body;
    if (!cliente_id || !valor) return res.status(400).json({ erro: 'Cliente e valor são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    const valorNum = parseFloat(valor);
    if (isNaN(valorNum) || valorNum < 0 || valorNum > 999999999) return res.status(400).json({ erro: 'Valor invalido' });
    const result = await pool.query(
      'INSERT INTO faturamento (cliente_id, valor, descricao, data_pagamento) VALUES ($1, $2, $3, $4) RETURNING id, cliente_id, valor, descricao, data_pagamento, criado_em',
      [cliente_id, valor, descricao||'', data_pagamento||new Date().toISOString().substring(0,10)]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao registrar faturamento:', err);
    res.status(500).json({ erro: 'Erro ao registrar faturamento' });
  }
});

app.get('/api/admin/faturamento', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT f.id, f.cliente_id, f.valor, f.descricao, f.data_pagamento, f.criado_em, c.empresa FROM faturamento f 
       LEFT JOIN clientes c ON f.cliente_id = c.id 
       ORDER BY f.data_pagamento DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar faturamento:', err);
    res.status(500).json({ erro: 'Erro ao buscar faturamento' });
  }
});

// === LOGS DE ACESSO ===
function logAcessoMiddleware(req, res, next) {
  if (req.admin) {
    const ip = req.headers['x-forwarded-for'] || req.connection?.remoteAddress || '';
    const ua = req.headers['user-agent'] || '';
    pool.query(
      'INSERT INTO logs_acesso (admin_id, admin_usuario, acao, detalhes, ip, user_agent) VALUES ($1,$2,$3,$4,$5,$6)',
      [req.admin.id || null, req.admin.usuario || '', req.method + ' ' + req.originalUrl, '[body omitted]', ip, ua]
    ).catch(() => {});
  }
  next();
}
app.use('/api/admin', logAcessoMiddleware);

app.get('/api/admin/logs', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const result = await pool.query('SELECT id, admin_id, admin_usuario, acao, ip, criado_em FROM logs_acesso ORDER BY criado_em DESC LIMIT $1', [limit]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar logs' });
  }
});

// === CONFIGURACOES GERAIS ===
app.get('/api/admin/config', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT chave, valor, descricao FROM config_geral ORDER BY chave');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar config' });
  }
});

app.put('/api/admin/config', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const { configs } = req.body;
    if (!configs || !Array.isArray(configs)) return res.status(400).json({ erro: 'Formato invalido' });
    if (configs.length > 50) return res.status(400).json({ erro: 'Limite de 50 configuracoes por requisicao' });
    for (const c of configs) {
      if (!c.chave) continue;
      await pool.query(
        `INSERT INTO config_geral (chave, valor, descricao) VALUES ($1, $2, $3)
         ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor`,
        [sanitizarString(c.chave).substring(0,100), sanitizarString(c.valor).substring(0,1000), sanitizarString(c.descricao).substring(0,200)]
      );
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao salvar config' });
  }
});

// === NOTIFICACOES DO SISTEMA ===
app.get('/api/notificacoes', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, tipo, titulo, descricao, lida, criado_em FROM notificacoes WHERE cliente_id = $1 ORDER BY lida ASC, criado_em DESC LIMIT 50',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar notificacoes:', err);
    res.status(500).json({ erro: 'Erro ao buscar notificações' });
  }
});

app.get('/api/notificacoes/nao-lidas', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT COUNT(*)::int AS total FROM notificacoes WHERE cliente_id = $1 AND lida = FALSE',
      [req.usuario.cliente_id]
    );
    res.json({ total: result.rows[0].total });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao contar notificações' });
  }
});

app.put('/api/notificacoes/:id/ler', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    await pool.query('UPDATE notificacoes SET lida = TRUE WHERE id = $1 AND cliente_id = $2', [req.params.id, req.usuario.cliente_id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao marcar notificação' });
  }
});

app.put('/api/notificacoes/ler-todas', authMiddleware, apiLimiter, async (req, res) => {
  try {
    await pool.query('UPDATE notificacoes SET lida = TRUE WHERE cliente_id = $1 AND lida = FALSE', [req.usuario.cliente_id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao marcar notificações' });
  }
});

// === EMAIL CONFIG (ADMIN) ===
app.put('/api/admin/clientes/:id/email', adminMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { ativo, smtp_host, smtp_port, smtp_user, smtp_pass, remetente, destinatario } = req.body;
    const id = parseInt(req.params.id);
    await pool.query(
      `UPDATE clientes SET 
        email_ativo = $1,
        email_smtp_host = $2,
        email_smtp_port = $3,
        email_smtp_user = $4,
        email_smtp_pass = $5,
        email_remetente = $6,
        email_destinatario = $7
      WHERE id = $8`,
      [!!ativo, sanitizarString(smtp_host||'').substring(0,200), sanitizarString(smtp_port||'587').substring(0,10), sanitizarString(smtp_user||'').substring(0,200), sanitizarString(smtp_pass||'').substring(0,500), sanitizarString(remetente||'').substring(0,200), sanitizarString(destinatario||'').substring(0,200), id]
    );
    email.limparCache(id);
    res.json({ ok: true });
    logAuditoria(id, 'Admin', 'Config Email atualizada', 'email', 'Ativo: ' + !!ativo);
  } catch (err) {
    console.error('Erro ao salvar config Email:', err);
    res.status(500).json({ erro: 'Erro ao salvar configuração' });
  }
});

app.post('/api/admin/clientes/:id/email-teste', adminMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { destinatario } = req.body;
    if (!destinatario) return res.status(400).json({ erro: 'Email de destino é obrigatório' });
    const id = parseInt(req.params.id);
    email.limparCache(id);
    const resultado = await email.enviar(pool, id, '🧪 Teste de Conexão — Sistema Portaria DSRH', '<p>Este é um <b>teste de conexão</b> do Sistema de Controle de Portaria DSRH.</p><p>Se você recebeu este email, a integração está funcionando!</p>', destinatario);
    res.json(resultado);
  } catch (err) {
    console.error('Erro no teste Email:', err);
    res.status(500).json({ ok: false, erro: 'Erro ao enviar email. Verifique as configuracoes SMTP.' });
  }
});

// === WHATSAPP CONFIG (ADMIN) ===
app.put('/api/admin/clientes/:id/whatsapp', adminMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { ativo, provedor, token, telefone, telefone_notif, url, instancia } = req.body;
    const id = parseInt(req.params.id);
    await pool.query(
      `UPDATE clientes SET 
        whatsapp_ativo = $1,
        whatsapp_provedor = $2,
        whatsapp_token = $3,
        whatsapp_telefone = $4,
        whatsapp_telefone_notif = $5,
        whatsapp_url = $6,
        whatsapp_instancia = $7
      WHERE id = $8`,
      [!!ativo, sanitizarString(provedor||'').substring(0,20), sanitizarString(token||'').substring(0,500), sanitizarString(telefone||'').substring(0,30), sanitizarString(telefone_notif||'').substring(0,30), sanitizarString(url||'').substring(0,300), sanitizarString(instancia||'').substring(0,200), id]
    );
    whatsapp.limparCacheConfig(id);
    res.json({ ok: true });
    logAuditoria(id, 'Admin', 'Config WhatsApp atualizada', 'whatsapp', 'Provedor: ' + (provedor||'') + ' | Ativo: ' + !!ativo);
  } catch (err) {
    console.error('Erro ao salvar config WhatsApp:', err);
    res.status(500).json({ erro: 'Erro ao salvar configuração' });
  }
});

app.post('/api/admin/clientes/:id/whatsapp-teste', adminMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { telefone } = req.body;
    if (!telefone) return res.status(400).json({ erro: 'Telefone de destino é obrigatório' });
    const id = parseInt(req.params.id);
    whatsapp.limparCacheConfig(id);
    const resultado = await whatsapp.enviar(pool, id, telefone, '🧪 *TESTE DE CONEXÃO*\n\nMensagem de teste do Sistema de Portaria DSRH.\nSe você recebeu esta mensagem, a integração está funcionando!\n\n— Sistema Portaria DSRH');
    res.json(resultado);
  } catch (err) {
    console.error('Erro no teste WhatsApp:', err);
    res.status(500).json({ ok: false, erro: 'Erro ao conectar com WhatsApp. Verifique as configuracoes.' });
  }
});

// === WHATSAPP CONFIG (CLIENTE) ===
app.get('/api/whatsapp-config', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT whatsapp_ativo, whatsapp_provedor, whatsapp_telefone_notif FROM clientes WHERE id = $1',
      [req.usuario.cliente_id]
    );
    if (result.rows.length === 0) return res.json({ ativo: false });
    const c = result.rows[0];
    res.json({ ativo: !!c.whatsapp_ativo, provedor: c.whatsapp_provedor, telefone_notif: c.whatsapp_telefone_notif });
  } catch (err) {
    console.error('Erro ao buscar config WhatsApp:', err);
    res.status(500).json({ erro: 'Erro ao buscar configuração' });
  }
});

// === CHAMADOS (SUPORTE) ===
app.get('/api/admin/chamados', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ch.id, ch.cliente_id, ch.titulo, ch.descricao, ch.status, ch.prioridade, ch.resposta, ch.criado_em, ch.atualizado_em, c.empresa FROM chamados ch LEFT JOIN clientes c ON ch.cliente_id = c.id ORDER BY ch.criado_em DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar chamados' });
  }
});

app.post('/api/admin/chamados', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const { cliente_id, titulo, descricao, prioridade } = req.body;
    if (!titulo) return res.status(400).json({ erro: 'Titulo e obrigatorio' });
    const errChamado = validarString(titulo, 2, 200, 'Titulo');
    if (errChamado) return res.status(400).json({ erro: errChamado });
    const result = await pool.query(
      'INSERT INTO chamados (cliente_id, titulo, descricao, prioridade) VALUES ($1,$2,$3,$4) RETURNING id, cliente_id, titulo, descricao, status, prioridade, criado_em',
      [cliente_id || null, sanitizarString(titulo), sanitizarString(descricao).substring(0,2000), sanitizarString(prioridade) || 'media']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao criar chamado' });
  }
});

app.put('/api/admin/chamados/:id', adminMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { status, resposta } = req.body;
    const result = await pool.query(
      `UPDATE chamados SET status = COALESCE($1, status), resposta = COALESCE($2, resposta), atualizado_em = NOW() WHERE id = $3 RETURNING id, cliente_id, titulo, status, resposta, atualizado_em`,
      [status || null, sanitizarString(resposta).substring(0,2000) || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Chamado nao encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao atualizar chamado' });
  }
});

app.delete('/api/admin/chamados/:id', adminMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    await pool.query('DELETE FROM chamados WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao excluir chamado' });
  }
});

// === HISTORICO DE CLIENTES ===
app.get('/api/admin/historico', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const result = await pool.query(
      `SELECT h.id, h.cliente_id, h.admin_usuario, h.acao, h.detalhes, h.criado_em, c.empresa FROM historico_clientes h LEFT JOIN clientes c ON h.cliente_id = c.id ORDER BY h.criado_em DESC LIMIT $1`,
      [limit]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar historico' });
  }
});

// === ALERTAS ===
app.get('/api/admin/alertas', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const alertas = [];
    const expirados = await pool.query(
      `SELECT id, empresa, data_expiracao FROM clientes WHERE ativo = TRUE AND data_expiracao IS NOT NULL AND data_expiracao < CURRENT_DATE`
    );
    expirados.rows.forEach(c => {
      alertas.push({ tipo: 'expirado', titulo: 'Plano expirado', descricao: c.empresa + ' - expirou em ' + new Date(c.data_expiracao).toLocaleDateString('pt-BR'), cliente_id: c.id, empresa: c.empresa });
    });
    const vencendo = await pool.query(
      `SELECT id, empresa, data_expiracao FROM clientes WHERE ativo = TRUE AND data_expiracao IS NOT NULL AND data_expiracao >= CURRENT_DATE AND data_expiracao <= CURRENT_DATE + INTERVAL '7 days'`
    );
    vencendo.rows.forEach(c => {
      alertas.push({ tipo: 'vencendo', titulo: 'Plano vencendo em 7 dias', descricao: c.empresa + ' - vence em ' + new Date(c.data_expiracao).toLocaleDateString('pt-BR'), cliente_id: c.id, empresa: c.empresa });
    });
    const semUsuario = await pool.query(
      `SELECT cl.id, cl.empresa FROM clientes cl LEFT JOIN usuarios u ON cl.id = u.cliente_id WHERE cl.ativo = TRUE AND u.id IS NULL`
    );
    semUsuario.rows.forEach(c => {
      alertas.push({ tipo: 'atencao', titulo: 'Sem usuario portaria', descricao: c.empresa + ' - nenhum usuario de portaria criado', cliente_id: c.id, empresa: c.empresa });
    });
    const chamadosAbertos = await pool.query(
      `SELECT ch.id, ch.titulo, c.empresa FROM chamados ch LEFT JOIN clientes c ON ch.cliente_id = c.id WHERE ch.status = 'aberto'`
    );
    chamadosAbertos.rows.forEach(ch => {
      alertas.push({ tipo: 'chamado', titulo: 'Chamado aberto', descricao: (ch.empresa || 'Geral') + ' - ' + ch.titulo, cliente_id: ch.id });
    });
    res.json(alertas);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar alertas' });
  }
});

// === EXPORT / BACKUP ===
app.get('/api/admin/export/:tabela', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const tabela = req.params.tabela;
    const allowed = ['clientes', 'usuarios', 'registros', 'visitantes', 'pre_registros', 'pre_registros_visitantes', 'faturamento', 'chamados'];
    if (!allowed.includes(tabela)) return res.status(400).json({ erro: 'Tabela nao permitida' });
    const colunasExcluidas = { 'usuarios': ['senha','senha_exibicao'], 'admin_users': ['senha'], 'contas_motoristas': ['senha','senha_exibicao'], 'contas_visitantes': ['senha','senha_exibicao'] };
    const excluidas = colunasExcluidas[tabela] || [];
    const result = await pool.query(`SELECT * FROM ${tabela} ORDER BY id`, []);
    if (result.rows.length === 0) return res.json({ csv: '', rows: 0 });
    const allHeaders = Object.keys(result.rows[0]);
    const headers = allHeaders.filter(h => !excluidas.includes(h));
    // Sanitizar dados do CSV
    const csvLines = [headers.map(h => sanitizarString(h)).join(';')];
    result.rows.forEach(row => {
      csvLines.push(headers.map(h => {
        let v = row[h];
        if (v === null || v === undefined) return '';
        if (typeof v === 'string') return '"' + v.replace(/"/g, '""').replace(/[<>]/g, '') + '"';
        return String(v);
      }).join(';'));
    });
    res.json({ csv: csvLines.join('\n'), rows: result.rows.length, headers });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao exportar dados' });
  }
});

// === ROTA LOGISTICA (PUBLICA VIA TOKEN) ===
app.get('/l/:token', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, empresa, logistica_token, logistica_ativo FROM clientes WHERE logistica_token = $1', [req.params.token]);
    if (!result.rows.length) return res.status(404).send('Link invalido ou desativado');
    const c = result.rows[0];
    if (!c.logistica_ativo) return res.status(404).send('Logistica desativada para esta empresa');
    res.redirect(302, '/logistica.html?token=' + encodeURIComponent(c.logistica_token) + '&cliente_id=' + c.id + '&empresa=' + encodeURIComponent(c.empresa) + '&_t=' + Date.now());
  } catch { res.status(500).send('Erro'); }
});

app.get('/api/logistica/:token', apiLimiter, async (req, res) => {
  try {
    const cliente = await pool.query('SELECT id, empresa, logistica_ativo FROM clientes WHERE logistica_token = $1', [req.params.token]);
    if (!cliente.rows.length) {
      console.log('[LOGISTICA] Token nao encontrado para o cliente informado');
      return res.status(404).json({ erro: 'Link invalido' });
    }
    if (!cliente.rows[0].logistica_ativo) {
      console.log('[LOGISTICA] Token encontrado mas logistica INATIVA para cliente:', cliente.rows[0].id, cliente.rows[0].empresa);
      return res.status(403).json({ erro: 'Logistica desativada para esta empresa' });
    }
    const cid = cliente.rows[0].id;
    console.log('[LOGISTICA] Buscando dados para cliente:', cid, cliente.rows[0].empresa);
    const [localizacoes, preRegistros, checkinsQR] = await Promise.all([
      pool.query("SELECT l.motorista_id, l.nome, l.placa, l.empresa, l.lat, l.lng, l.rua, l.a_caminho, l.chegou, l.chegada_em, l.saida_logistica, l.finalidade_tipo, l.saida_em, l.cnh, l.modelo, l.finalidade, l.nota, l.obs, l.atualizado_em, COALESCE(r.patio_liberado, FALSE) AS patio_liberado, COALESCE(r.veiculo_no_patio, FALSE) AS veiculo_no_patio, r.id AS registro_id FROM localizacoes_motoristas l LEFT JOIN registros r ON r.cliente_id = l.cliente_id AND r.placa = l.placa AND r.saida = '' AND r.data_registro = CURRENT_DATE WHERE l.cliente_id = $1 AND (l.a_caminho = TRUE OR l.chegou = TRUE OR l.saida_logistica = TRUE) AND l.atualizado_em > NOW() - INTERVAL '24 hours' ORDER BY l.saida_logistica ASC, l.chegou ASC, l.atualizado_em DESC", [cid]),
      pool.query('SELECT id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs, criado_em FROM pre_registros WHERE cliente_id = $1 ORDER BY id DESC LIMIT 50', [cid]),
      pool.query('SELECT id, cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs, telefone_motorista, descricao_material, quantidade_peso, nome_recebedor, data_previsao, tipo_checkin, status_checkin, criado_em FROM pre_registros WHERE cliente_id = $1 AND origem = \'checkin_qr\' ORDER BY criado_em DESC LIMIT 200', [cid])
    ]);
    console.log('[LOGISTICA] Resultado:', localizacoes.rows.length, 'motoristas,', preRegistros.rows.length, 'pre-registros,', checkinsQR.rows.length, 'checkins QR');
    res.json({ empresa: cliente.rows[0].empresa, motoristas: localizacoes.rows, preRegistros: preRegistros.rows, checkinsQR: checkinsQR.rows });
  } catch (err) {
    console.error('Erro API logistica:', err);
    res.status(500).json({ erro: 'Erro ao buscar dados' });
  }
});

// === LOGISTICA: Notificacoes (para toast no painel) ===
app.get('/api/logistica/:token/notificacoes', apiLimiter, async (req, res) => {
  try {
    const cliente = await pool.query('SELECT id, logistica_ativo FROM clientes WHERE logistica_token = $1', [req.params.token]);
    if (!cliente.rows.length || !cliente.rows[0].logistica_ativo) return res.status(403).json({ erro: 'Link invalido ou desativado' });
    const cid = cliente.rows[0].id;
    const result = await pool.query(
      'SELECT id, tipo, titulo, descricao, lida, criado_em FROM notificacoes WHERE cliente_id = $1 AND lida = FALSE AND tipo NOT IN (\'veiculo_no_patio\', \'patio_liberado\') ORDER BY criado_em DESC LIMIT 10',
      [cid]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar notificacoes logistica:', err);
    res.status(500).json({ erro: 'Erro ao buscar notificacoes' });
  }
});

app.put('/api/logistica/:token/notificacoes/ler-todas', apiLimiter, async (req, res) => {
  try {
    const cliente = await pool.query('SELECT id, logistica_ativo FROM clientes WHERE logistica_token = $1', [req.params.token]);
    if (!cliente.rows.length || !cliente.rows[0].logistica_ativo) return res.status(403).json({ erro: 'Link invalido ou desativado' });
    const cid = cliente.rows[0].id;
    await pool.query('UPDATE notificacoes SET lida = TRUE WHERE cliente_id = $1 AND lida = FALSE', [cid]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Erro ao marcar notificacoes lidas logistica:', err);
    res.status(500).json({ erro: 'Erro ao marcar notificacoes' });
  }
});

// === LOGISTICA: Entrega Concluida (marcar saida do motorista) ===
app.post('/api/logistica/:token/entrega-concluida', apiLimiter, async (req, res) => {
  try {
    const { motorista_id, placa } = req.body;
    if (!motorista_id && !placa) return res.status(400).json({ erro: 'motorista_id ou placa obrigatorio' });
    const cliente = await pool.query('SELECT id, empresa, logistica_ativo FROM clientes WHERE logistica_token = $1', [req.params.token]);
    if (!cliente.rows.length || !cliente.rows[0].logistica_ativo) return res.status(403).json({ erro: 'Link invalido ou desativado' });
    const cid = cliente.rows[0].id;

    // Buscar dados do motorista na localizacao
    var matchQuery, matchParams;
    if (motorista_id) {
      matchQuery = 'SELECT * FROM localizacoes_motoristas WHERE motorista_id = $1 AND cliente_id = $2 AND chegou = TRUE AND saida_logistica = FALSE';
      matchParams = [motorista_id, cid];
    } else {
      matchQuery = 'SELECT * FROM localizacoes_motoristas WHERE placa = $1 AND cliente_id = $2 AND chegou = TRUE AND saida_logistica = FALSE';
      matchParams = [placa, cid];
    }
    const mot = await pool.query(matchQuery, matchParams);
    if (!mot.rows.length) return res.status(404).json({ erro: 'Motorista nao encontrado ou ja concluido' });
    const m = mot.rows[0];

    // Marcar saida_logistica
    await pool.query(
      'UPDATE localizacoes_motoristas SET saida_logistica = TRUE, finalidade_tipo = $1, saida_em = NOW(), atualizado_em = NOW() WHERE motorista_id = $2 AND cliente_id = $3',
      ['Entrega', m.motorista_id, cid]
    );

    // NOTA: Nao marca saida automaticamente no registro da portaria.
    // A saida so sera marcada pela portaria APOS o patio ser liberado.

    // Notificar portaria via notificacao no sistema
    await pool.query(
      'INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)',
      [cid, 'entrega_concluida', 'Entrega Concluida', 'Motorista: ' + (m.nome||'') + ' | Placa: ' + (m.placa||'') + ' | Empresa: ' + (m.empresa||'')]
    ).catch(() => {});

    // WhatsApp/Email notificacao de saida
    whatsapp.notificarSaida(pool, cid, { empresa: m.empresa, motorista: m.nome, placa: m.placa, finalidade: 'Entrega', hora: new Date().toLocaleTimeString('pt-BR') }).catch(() => {});
    email.notificarSaida(pool, cid, { empresa: m.empresa, motorista: m.nome, placa: m.placa, finalidade: 'Entrega', hora: new Date().toLocaleTimeString('pt-BR') }).catch(() => {});

    logAuditoria(cid, 'Logistica', 'Entrega concluida', 'veiculo', m.placa, 'Motorista: ' + (m.nome||'') + ' | Empresa: ' + (m.empresa||''));
    res.json({ ok: true, mensagem: 'Entrega concluida com sucesso' });
  } catch (err) {
    console.error('Erro ao marcar entrega concluida:', err);
    res.status(500).json({ erro: 'Erro ao marcar entrega concluida' });
  }
});

// === LOGISTICA: Patio Liberado (operador confirma veiculo no patio, avisa portaria) ===
app.post('/api/logistica/:token/patio-liberado', apiLimiter, async (req, res) => {
  try {
    const { placa } = req.body;
    if (!placa) return res.status(400).json({ erro: 'Placa obrigatoria' });
    const cliente = await pool.query('SELECT id, empresa, logistica_ativo FROM clientes WHERE logistica_token = $1', [req.params.token]);
    if (!cliente.rows.length || !cliente.rows[0].logistica_ativo) return res.status(403).json({ erro: 'Link invalido ou desativado' });
    const cid = cliente.rows[0].id;

    // Marcar veiculo_no_patio no registro da portaria
    const resReg = await pool.query(
      'UPDATE registros SET veiculo_no_patio = TRUE WHERE cliente_id = $1 AND placa = $2 AND saida = $3 AND data_registro = CURRENT_DATE',
      [cid, placa, '']
    );

    // Criar notificacao para a portaria: veiculo liberado para o patio
    const descricaoNotif = 'Logistica liberou o veiculo placa ' + placa + ' para o patio. Veiculo a caminho do patio.';
    await pool.query(
      'INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)',
      [cid, 'veiculo_no_patio', 'Veiculo liberado para o patio', descricaoNotif]
    );

    logAuditoria(cid, 'Logistica', 'Patio Liberado', 'veiculo', placa, 'Veiculo liberado para o patio - placa ' + placa);
    res.json({ ok: true, mensagem: 'Portaria notificada: veiculo liberado para o patio' });
  } catch (err) {
    console.error('Erro ao liberar patio:', err);
    res.status(500).json({ erro: 'Erro ao liberar patio' });
  }
});

// === LOGISTICA: Finalizar veiculo (descarga concluida, pátio finalizado) ===
app.post('/api/logistica/:token/finalizar-veiculo', apiLimiter, async (req, res) => {
  try {
    const { placa } = req.body;
    if (!placa) return res.status(400).json({ erro: 'Placa obrigatoria' });
    const cliente = await pool.query('SELECT id, empresa, logistica_ativo FROM clientes WHERE logistica_token = $1', [req.params.token]);
    if (!cliente.rows.length || !cliente.rows[0].logistica_ativo) return res.status(403).json({ erro: 'Link invalido ou desativado' });
    const cid = cliente.rows[0].id;

    // Marcar patio_liberado no registro da portaria para habilitar o botao Marcar Saida
    await pool.query(
      'UPDATE registros SET patio_liberado = TRUE WHERE cliente_id = $1 AND placa = $2 AND saida = $3 AND data_registro = CURRENT_DATE',
      [cid, placa, '']
    );

    // Criar notificacao para a portaria: Patio Finalizado
    const descricaoNotif = 'Logistica finalizou a descarga do veiculo placa: ' + placa;
    await pool.query(
      'INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)',
      [cid, 'patio_liberado', 'Patio Finalizado', descricaoNotif]
    );

    logAuditoria(cid, 'Logistica', 'Veiculo finalizado', 'veiculo', placa, 'Patio finalizado para portaria - placa ' + placa);
    res.json({ ok: true, mensagem: 'Portaria notificada: patio finalizado' });
  } catch (err) {
    console.error('Erro ao finalizar veiculo:', err);
    res.status(500).json({ erro: 'Erro ao finalizar veiculo' });
  }
});

// === ADMIN: TOGGLE LOGISTICA ===
app.put('/api/admin/clientes/:id/logistica', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const { ativo } = req.body;
    const id = parseInt(req.params.id);
    if (typeof ativo !== 'boolean') return res.status(400).json({ erro: 'Parametro ativo obrigatorio (boolean)' });
    if (ativo) {
      const existing = await pool.query('SELECT logistica_token FROM clientes WHERE id = $1', [id]);
      var token = existing.rows[0]?.logistica_token || '';
      if (!token) {
        token = crypto.randomBytes(16).toString('hex');
      }
      await pool.query('UPDATE clientes SET logistica_ativo = TRUE, logistica_token = $1 WHERE id = $2', [token, id]);
      res.json({ ativo: true, token: token });
    } else {
      await pool.query('UPDATE clientes SET logistica_ativo = FALSE WHERE id = $1', [id]);
      res.json({ ativo: false });
    }
  } catch (err) {
    console.error('Erro ao toggle logistica:', err);
    res.status(500).json({ erro: 'Erro ao atualizar' });
  }
});


// === ARQUIVOS (UPLOAD / DOWNLOAD / GERENCIAR) ===
app.post('/api/arquivos/upload', authMiddleware, apiLimiter, uploadArquivo.single('arquivo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ erro: 'Nenhum arquivo enviado' });
    const { descricao } = req.body;
    const result = await pool.query(
      'INSERT INTO arquivos (cliente_id, nome, nome_original, tipo, tamanho, caminho, descricao, criado_por) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, nome_original, tipo, tamanho, descricao, criado_por, criado_em',
      [req.usuario.cliente_id, req.file.filename, sanitizarString(req.file.originalname).substring(0,255), req.file.mimetype, req.file.size, req.file.path, sanitizarString(descricao||'').substring(0,500), req.usuario.usuario||'portaria']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao fazer upload:', err);
    res.status(500).json({ erro: 'Erro ao fazer upload' });
  }
});

app.get('/api/arquivos', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nome_original, tipo, tamanho, descricao, criado_por, criado_em FROM arquivos WHERE cliente_id = $1 ORDER BY criado_em DESC',
      [req.usuario.cliente_id]
    );
    // Adicionar hash de visualizacao publica a cada arquivo
    const arquivos = result.rows.map(a => ({
      ...a,
      public_hash: gerarHashPublicView(String(a.id))
    }));
    res.json(arquivos);
  } catch (err) {
    console.error('Erro ao buscar arquivos:', err);
    res.status(500).json({ erro: 'Erro ao buscar arquivos' });
  }
});

app.get('/api/arquivos/:id/download', authMiddleware, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
    const result = await pool.query('SELECT id, nome, nome_original, tipo, caminho, cliente_id FROM arquivos WHERE id = $1 AND cliente_id = $2', [req.params.id, req.usuario.cliente_id]);
    if (!result.rows.length) return res.status(404).json({ erro: 'Arquivo nao encontrado' });
    const arq = result.rows[0];
    if (!fs.existsSync(arq.caminho)) return res.status(404).json({ erro: 'Arquivo nao encontrado no servidor' });
    res.setHeader('Content-Disposition', 'attachment; filename="' + encodeURIComponent(arq.nome_original) + '"');
    res.setHeader('Content-Type', arq.tipo || 'application/octet-stream');
    res.sendFile(path.resolve(arq.caminho));
  } catch (err) {
    console.error('Erro ao baixar arquivo:', err);
    res.status(500).json({ erro: 'Erro ao baixar arquivo' });
  }
});

// Gerar hash de visualizacao publica (valido por 24h)
function gerarHashPublicView(id) {
  const secret = process.env.JWT_SECRET || 'dsrh-portaria-2024';
  const hoje = new Date().toISOString().slice(0, 10); // dia atual, valida por 24h
  return crypto.createHash('sha256').update(id + secret + hoje).digest('hex').substring(0, 16);
}

app.get('/api/arquivos/:id/view', authMiddleware, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
    const result = await pool.query('SELECT id, nome, nome_original, tipo, caminho, cliente_id FROM arquivos WHERE id = $1 AND cliente_id = $2', [req.params.id, req.usuario.cliente_id]);
    if (!result.rows.length) return res.status(404).json({ erro: 'Arquivo nao encontrado' });
    const arq = result.rows[0];
    if (!fs.existsSync(arq.caminho)) return res.status(404).json({ erro: 'Arquivo nao encontrado no servidor' });
    res.setHeader('Content-Type', arq.tipo || 'application/octet-stream');
    res.setHeader('Content-Disposition', 'inline; filename="' + encodeURIComponent(arq.nome_original) + '"');
    res.sendFile(path.resolve(arq.caminho));
  } catch (err) {
    console.error('Erro ao visualizar arquivo:', err);
    res.status(500).json({ erro: 'Erro ao visualizar' });
  }
});

// Visualizacao publica via hash temporario (para Google Docs Viewer e Office Online)
// Valido por 24h (usa data do dia)
app.get('/api/arquivos/:id/public-view/:hash/:nome?', async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
    const secret = process.env.JWT_SECRET || 'dsrh-portaria-2024';
    // Verifica hash do dia atual E do dia anterior (cobrir virada de meia-noite)
    const hoje = new Date().toISOString().slice(0, 10);
    const ontem = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const hashHoje = crypto.createHash('sha256').update(req.params.id + secret + hoje).digest('hex').substring(0, 16);
    const hashOntem = crypto.createHash('sha256').update(req.params.id + secret + ontem).digest('hex').substring(0, 16);
    if (req.params.hash !== hashHoje && req.params.hash !== hashOntem) {
      return res.status(403).json({ erro: 'Link expirado ou invalido' });
    }
    const result = await pool.query('SELECT id, nome, nome_original, tipo, caminho, cliente_id FROM arquivos WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ erro: 'Arquivo nao encontrado' });
    const arq = result.rows[0];
    if (!fs.existsSync(arq.caminho)) return res.status(404).json({ erro: 'Arquivo nao encontrado no servidor' });
    res.setHeader('Content-Type', arq.tipo || 'application/octet-stream');
    res.setHeader('Content-Disposition', 'inline; filename="' + encodeURIComponent(arq.nome_original) + '"');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.sendFile(path.resolve(arq.caminho));
  } catch (err) {
    console.error('Erro ao visualizar arquivo publico:', err);
    res.status(500).json({ erro: 'Erro ao visualizar' });
  }
});

app.delete('/api/arquivos/:id', authMiddleware, apiLimiter, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
    const result = await pool.query('SELECT id, caminho, cliente_id FROM arquivos WHERE id = $1 AND cliente_id = $2', [req.params.id, req.usuario.cliente_id]);
    if (!result.rows.length) return res.status(404).json({ erro: 'Arquivo nao encontrado' });
    try { if (fs.existsSync(result.rows[0].caminho)) fs.unlinkSync(result.rows[0].caminho); } catch {}
    await pool.query('DELETE FROM arquivos WHERE id = $1 AND cliente_id = $2', [req.params.id, req.usuario.cliente_id]);
    res.json({ mensagem: 'Arquivo excluido' });
  } catch (err) {
    console.error('Erro ao excluir arquivo:', err);
    res.status(500).json({ erro: 'Erro ao excluir arquivo' });
  }
});

// === MOTORISTA DESPACHO (PAINEL DO MOTORISTA) ===
// GET: buscar dados do check-in pelo token do motorista
app.get('/api/motorista-despacho/:token', apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT pr.id, pr.cliente_id, pr.empresa, pr.motorista, pr.cnh, pr.placa, pr.modelo, pr.finalidade,
              pr.nota, pr.obs, pr.telefone_motorista, pr.descricao_material, pr.quantidade_peso,
              pr.nome_recebedor, pr.data_previsao, pr.tipo_checkin, pr.status_checkin, pr.motorista_token,
              pr.transito_inicio, pr.criado_em,
              c.empresa AS empresa_destino
       FROM pre_registros pr
       JOIN clientes c ON c.id = pr.cliente_id
       WHERE pr.motorista_token = $1 AND pr.origem = 'checkin_qr'`,
      [req.params.token]
    );
    if (!result.rows.length) {
      return res.status(404).json({ erro: 'Despacho nao encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao buscar despacho motorista:', err);
    res.status(500).json({ erro: 'Erro ao buscar dados' });
  }
});

// POST: motorista inicia transito (muda status para em_transito + salva GPS inicial)
app.post('/api/motorista-despacho/:token/iniciar-transito', apiLimiter, async (req, res) => {
  try {
    // Verificar se e partida - apenas partida pode iniciar transito
    const checkTipo = await pool.query(
      `SELECT id, tipo_checkin, status_checkin FROM pre_registros WHERE motorista_token = $1 AND origem = 'checkin_qr'`,
      [req.params.token]
    );
    if (!checkTipo.rows.length) {
      return res.status(404).json({ erro: 'Despacho nao encontrado' });
    }
    if (checkTipo.rows[0].tipo_checkin !== 'partida') {
      return res.status(400).json({ erro: 'Este check-in e de chegada. Inicio de transito nao se aplica.' });
    }
    if (checkTipo.rows[0].status_checkin === 'em_transito') {
      return res.status(200).json({ id: checkTipo.rows[0].id, status_checkin: 'em_transito', ja_iniciado: true });
    }

    const { lat, lng } = req.body;
    const result = await pool.query(
      `UPDATE pre_registros
       SET status_checkin = 'em_transito',
           transito_inicio = COALESCE(transito_inicio, NOW()),
           transito_lat = COALESCE(transito_lat, $2),
           transito_lng = COALESCE(transito_lng, $3)
       WHERE motorista_token = $1 AND origem = 'checkin_qr' AND tipo_checkin = 'partida'
       RETURNING id, status_checkin, transito_inicio`,
      [req.params.token, lat || null, lng || null]
    );
    if (!result.rows.length) {
      return res.status(404).json({ erro: 'Despacho nao encontrado' });
    }

    // Criar localizacao ativa para o motorista aparecer no mapa da logistica
    const despacho = await pool.query(
      `SELECT cliente_id, motorista, placa, empresa, finalidade FROM pre_registros WHERE id = $1`,
      [result.rows[0].id]
    );
    if (despacho.rows.length && lat && lng) {
      const d = despacho.rows[0];
      const motoristaId = result.rows[0].id;
      await pool.query(
        `DELETE FROM localizacoes_motoristas WHERE cliente_id = $1 AND motorista_id = $2`,
        [d.cliente_id, motoristaId]
      ).catch(() => {});
      await pool.query(
        `INSERT INTO localizacoes_motoristas (cliente_id, motorista_id, nome, placa, empresa, lat, lng, rua, a_caminho, chegou, finalidade_tipo, atualizado_em)
         VALUES ($1, $2, $3, $4, $5, $6, $7, '', TRUE, FALSE, $8, NOW())`,
        [d.cliente_id, motoristaId, d.motorista, d.placa, d.empresa, lat, lng, d.finalidade || 'Entrega']
      ).catch(() => {});
    }

    // Notificar
    const d2 = despacho.rows[0];
    whatsapp.notificarCheckinQR(pool, d2.cliente_id, { empresa: d2.empresa, motorista: d2.motorista, placa: d2.placa, finalidade: d2.finalidade }).catch(() => {});
    email.notificarCheckinQR(pool, d2.cliente_id, { empresa: d2.empresa, motorista: d2.motorista, placa: d2.placa, finalidade: d2.finalidade }).catch(() => {});
    pool.query('INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)',
      [d2.cliente_id, 'checkin_qr', '🚛 Motorista em transito', 'Motorista: ' + d2.motorista + ' | Placa: ' + d2.placa + ' | Empresa: ' + d2.empresa]).catch(() => {});

    res.json({ id: result.rows[0].id, status_checkin: 'em_transito', hora_inicio: result.rows[0].transito_inicio });
  } catch (err) {
    console.error('Erro ao iniciar transito:', err);
    res.status(500).json({ erro: 'Erro ao iniciar transito' });
  }
});

// POST: atualizar GPS do motorista
app.post('/api/motorista-despacho/:token/gps', apiLimiter, async (req, res) => {
  try {
    const { lat, lng } = req.body;
    if (lat == null || lng == null) return res.status(400).json({ erro: 'Coordenadas obrigatorias' });
    const latNum = parseFloat(lat);
    const lngNum = parseFloat(lng);
    if (isNaN(latNum) || isNaN(lngNum)) return res.status(400).json({ erro: 'Coordenadas invalidas' });
    if (latNum < -90 || latNum > 90 || lngNum < -180 || lngNum > 180) return res.status(400).json({ erro: 'Coordenadas fora do range' });

    // Atualizar pre_registros
    await pool.query(
      `UPDATE pre_registros SET transito_lat = $1, transito_lng = $2 WHERE motorista_token = $3 AND origem = 'checkin_qr'`,
      [lat, lng, req.params.token]
    );

    // Atualizar localizacoes_motoristas
    await pool.query(
      `UPDATE localizacoes_motoristas SET lat = $1, lng = $2, atualizado_em = NOW()
       WHERE motorista_id = (
         SELECT id FROM pre_registros WHERE motorista_token = $3 AND origem = 'checkin_qr' LIMIT 1
       )`,
      [lat, lng, req.params.token]
    ).catch(() => {});

    res.json({ ok: true });
  } catch (err) {
    console.error('Erro GPS motorista:', err);
    res.status(500).json({ erro: 'Erro ao atualizar GPS' });
  }
});

// === CHECK-IN VIA QR CODE (MOTORISTA NA PORTARIA) ===
app.get('/checkin/:cliente_id', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, empresa, checkin_ativo FROM clientes WHERE id = $1', [req.params.cliente_id]);
    if (!result.rows.length) return res.status(404).send('Cliente não encontrado');
    const c = result.rows[0];
    if (!c.checkin_ativo) return res.status(404).send('Check-in desativado para esta empresa');
    res.redirect('/motorista-checkin.html?cliente_id=' + c.id + '&empresa=' + encodeURIComponent(c.empresa));
  } catch { res.status(500).send('Erro'); }
});

app.post('/api/checkin-portaria', preRegistroLimiter, async (req, res) => {
  try {
    const { cliente_id, motorista, cnh, placa, modelo, empresa, finalidade, nota, obs } = req.body;
    if (!cliente_id || !motorista || !placa || !empresa) return res.status(400).json({ erro: 'Motorista, placa e empresa são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    const placaClean = placa.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (placaClean.length < 6 || placaClean.length > 8) return res.status(400).json({ erro: 'Placa invalida' });
    const tipoCheckin = (req.body.tipo_checkin === 'partida') ? 'partida' : 'chegada';
    const statusCheckin = tipoCheckin === 'partida' ? 'em_transito' : 'aguardando';
    const motoristaToken = 'mtk_' + Date.now().toString(36) + Math.random().toString(36).substring(2, 10);
    const result = await pool.query(
      `INSERT INTO pre_registros (cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs, origem, telefone_motorista, descricao_material, quantidade_peso, nome_recebedor, data_previsao, tipo_checkin, status_checkin, motorista_token)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'checkin_qr', $10, $11, $12, $13, $14, $15, $16, $17) RETURNING id, cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs, telefone_motorista, descricao_material, quantidade_peso, nome_recebedor, data_previsao, tipo_checkin, status_checkin, motorista_token, criado_em`,
      [cliente_id, sanitizarString(empresa).toUpperCase(), sanitizarString(motorista).toUpperCase(), sanitizarString(cnh).substring(0,20), placaClean, sanitizarString(modelo).substring(0,100), sanitizarString(finalidade).substring(0,100), sanitizarString(nota).substring(0,50), sanitizarString(obs).substring(0,500), sanitizarString(req.body.telefone_motorista||'').substring(0,30), sanitizarString(req.body.descricao_material||'').substring(0,1000), sanitizarString(req.body.quantidade_peso||'').substring(0,100), sanitizarString(req.body.nome_recebedor||'').substring(0,200), req.body.data_previsao || null, tipoCheckin, statusCheckin, motoristaToken]
    );
    logAuditoria(cliente_id, 'Motorista (Check-in QR)', 'Pré-registro via QR Code', 'veiculo', placa.toUpperCase(), 'Motorista: ' + motorista + ' | Empresa: ' + empresa);
    res.status(201).json(result.rows[0]);
    // Notificar logística via WhatsApp (novo check-in QR recebido)
    whatsapp.notificarCheckinQR(pool, cliente_id, { empresa, motorista, placa, finalidade }).catch(() => {});
    // Notificar via Email (check-in QR)
    email.notificarCheckinQR(pool, cliente_id, { empresa, motorista, placa, finalidade }).catch(() => {});
    // Criar notificação no sistema
    const tipoLabel = tipoCheckin === 'partida' ? '🚛 Em trânsito' : '📱 Chegando na portaria';
    pool.query('INSERT INTO notificacoes (cliente_id, tipo, titulo, descricao) VALUES ($1,$2,$3,$4)', [cliente_id, 'checkin_qr', tipoLabel, 'Motorista: ' + motorista + ' | Placa: ' + placa + ' | Empresa: ' + empresa]).catch(() => {});
  } catch (err) {
    console.error('Erro no checkin-portaria:', err);
    res.status(500).json({ erro: 'Erro ao realizar check-in' });
  }
});

// Listar check-ins com filtro de status
app.get('/api/checkins', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const status = req.query.status || '';
    let query = 'SELECT id, cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs, origem, telefone_motorista, descricao_material, quantidade_peso, nome_recebedor, data_previsao, tipo_checkin, status_checkin, criado_em FROM pre_registros WHERE cliente_id = $1 AND origem = \'checkin_qr\'';
    const params = [req.usuario.cliente_id];
    if (status) {
      query += ' AND status_checkin = $2';
      params.push(status);
    }
    query += ' ORDER BY criado_em DESC LIMIT 200';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar checkins:', err);
    res.status(500).json({ erro: 'Erro ao buscar check-ins' });
  }
});

// Atualizar status de check-in
app.put('/api/checkins/:id/status', authMiddleware, apiLimiter, async (req, res) => {
  try {
    if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
    const { status_checkin } = req.body;
    if (!['em_transito', 'aguardando', 'confirmado'].includes(status_checkin)) {
      return res.status(400).json({ erro: 'Status invalido' });
    }
    const result = await pool.query(
      'UPDATE pre_registros SET status_checkin = $1 WHERE id = $2 AND cliente_id = $3 RETURNING *',
      [status_checkin, req.params.id, req.usuario.cliente_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Check-in não encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao atualizar status checkin:', err);
    res.status(500).json({ erro: 'Erro ao atualizar status' });
  }
});

// === AGENDAMENTOS ===
app.get('/api/agendamentos', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const data = req.query.data || new Date().toLocaleDateString('en-CA');
    const result = await pool.query(
      'SELECT id, cliente_id, motorista, placa, empresa, finalidade, data_agendada, horario, doca, nota, status, criado_em FROM agendamentos WHERE cliente_id = $1 AND data_agendada = $2 ORDER BY horario ASC, id ASC',
      [req.usuario.cliente_id, data]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar agendamentos:', err);
    res.status(500).json({ erro: 'Erro ao buscar agendamentos' });
  }
});

app.post('/api/agendamentos', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { motorista, placa, empresa, finalidade, data_agendada, horario, doca, nota } = req.body;
    if (!data_agendada || !horario) return res.status(400).json({ erro: 'Data e horário são obrigatórios' });
    const result = await pool.query(
      `INSERT INTO agendamentos (cliente_id, motorista, placa, empresa, finalidade, data_agendada, horario, doca, nota)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, motorista, placa, empresa, finalidade, data_agendada, horario, doca, nota, status`,
      [req.usuario.cliente_id, sanitizarString(motorista||'').substring(0,200), sanitizarString(placa||'').substring(0,20), sanitizarString(empresa||'').substring(0,200), sanitizarString(finalidade||'').substring(0,50), data_agendada, sanitizarString(horario).substring(0,10), sanitizarString(doca||'').substring(0,50), sanitizarString(nota||'').substring(0,500)]
    );
    res.status(201).json(result.rows[0]);
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Agendamento criado', 'agendamento', placa || '', 'Motorista: ' + (motorista||'') + ' | Data: ' + data_agendada + ' ' + horario);
  } catch (err) {
    console.error('Erro ao criar agendamento:', err);
    res.status(500).json({ erro: 'Erro ao criar agendamento' });
  }
});

app.put('/api/agendamentos/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const { status, horario, doca, motorista, placa, empresa, finalidade, nota } = req.body;
    const updates = [];
    const values = [];
    let idx = 1;
    if (status !== undefined) { updates.push(`status = $${idx++}`); values.push(status); }
    if (horario !== undefined) { updates.push(`horario = $${idx++}`); values.push(horario); }
    if (doca !== undefined) { updates.push(`doca = $${idx++}`); values.push(doca); }
    if (motorista !== undefined) { updates.push(`motorista = $${idx++}`); values.push(sanitizarString(motorista).substring(0,200)); }
    if (placa !== undefined) { updates.push(`placa = $${idx++}`); values.push(sanitizarString(placa).substring(0,20)); }
    if (empresa !== undefined) { updates.push(`empresa = $${idx++}`); values.push(sanitizarString(empresa).substring(0,200)); }
    if (finalidade !== undefined) { updates.push(`finalidade = $${idx++}`); values.push(sanitizarString(finalidade).substring(0,50)); }
    if (nota !== undefined) { updates.push(`nota = $${idx++}`); values.push(sanitizarString(nota).substring(0,500)); }
    if (updates.length === 0) return res.status(400).json({ erro: 'Nada para atualizar' });
    updates.push(`atualizado_em = NOW()`);
    values.push(req.params.id);
    values.push(req.usuario.cliente_id);
    const result = await pool.query(
      `UPDATE agendamentos SET ${updates.join(', ')} WHERE id = $${idx} AND cliente_id = $${idx+1} RETURNING *`,
      values
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Agendamento não encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao atualizar agendamento:', err);
    res.status(500).json({ erro: 'Erro ao atualizar agendamento' });
  }
});

app.delete('/api/agendamentos/:id', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const result = await pool.query('DELETE FROM agendamentos WHERE id = $1 AND cliente_id = $2 RETURNING id', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Agendamento não encontrado' });
    res.json({ mensagem: 'Agendamento excluído' });
  } catch (err) {
    console.error('Erro ao excluir agendamento:', err);
    res.status(500).json({ erro: 'Erro ao excluir agendamento' });
  }
});

app.get('/p/:cliente_id', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, empresa FROM clientes WHERE id = $1', [req.params.cliente_id]);
    if (!result.rows.length) return res.status(404).send('Cliente não encontrado');
    const c = result.rows[0];
    res.redirect('/pre-registro.html?cliente_id=' + c.id + '&empresa=' + encodeURIComponent(c.empresa));
  } catch { res.status(500).send('Erro'); }
});

app.get('/v/:cliente_id', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, empresa FROM clientes WHERE id = $1', [req.params.cliente_id]);
    if (!result.rows.length) return res.status(404).send('Cliente não encontrado');
    const c = result.rows[0];
    res.redirect('/pre-registro-visitante.html?cliente_id=' + c.id + '&empresa=' + encodeURIComponent(c.empresa));
  } catch { res.status(500).send('Erro'); }
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ erro: 'Rota não encontrada' });
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

async function conectarDB(retries = 5, delay = 3000) {
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query('SELECT 1');
      console.log('Conectado ao PostgreSQL');
      return true;
    } catch (err) {
      console.error(`Tentativa ${i + 1}/${retries} de conexao com DB falhou: ${err.message}`);
      if (i < retries - 1) await new Promise(r => setTimeout(r, delay));
    }
  }
  return false;
}

async function iniciar() {
  try {
    const conectado = await conectarDB();
    if (!conectado) {
      console.error('Falha ao conectar ao PostgreSQL apos todas as tentativas.');
      process.exit(1);
    }
    try {
      const fs = require('fs');
      const sql = fs.readFileSync('./schema.sql', 'utf8');
      const statements = sql.split(';').map(s => s.trim()).filter(s => s.length > 0);
      for (const stmt of statements) {
        try { await pool.query(stmt); } catch(e) { console.log('Aviso schema:', e.message); }
      }
      console.log('Schema verificado/criado');
    } catch (err) {
      console.log('Aviso: schema.sql não encontrado ou erro ao executar:', err.message);
    }
    const migrateCols = [
      "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE",
      "ALTER TABLE registros ADD COLUMN IF NOT EXISTS cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE",
      "ALTER TABLE contas_motoristas ADD COLUMN IF NOT EXISTS cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE",
      "ALTER TABLE contas_visitantes ADD COLUMN IF NOT EXISTS cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE",
      "ALTER TABLE pre_registros_visitantes ADD COLUMN IF NOT EXISTS cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE",
      "ALTER TABLE pre_registros_visitantes ADD COLUMN IF NOT EXISTS rg VARCHAR(30) DEFAULT ''",
      "ALTER TABLE pre_registros_visitantes ADD COLUMN IF NOT EXISTS cracha VARCHAR(50) DEFAULT ''",
      "ALTER TABLE pre_registros_visitantes ADD COLUMN IF NOT EXISTS telefone VARCHAR(30) DEFAULT ''",
      "ALTER TABLE pre_registros_visitantes ADD COLUMN IF NOT EXISTS setor_visitado VARCHAR(100) DEFAULT ''",
      "ALTER TABLE pre_registros_visitantes ADD COLUMN IF NOT EXISTS autorizado_por VARCHAR(100) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS telefone_fixo VARCHAR(20) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS obs VARCHAR(500) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS posicao INTEGER DEFAULT 0",
      "CREATE TABLE IF NOT EXISTS faturamento (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, valor DECIMAL(10,2) NOT NULL, descricao VARCHAR(200) DEFAULT '', data_pagamento DATE DEFAULT CURRENT_DATE, criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS logs_acesso (id SERIAL PRIMARY KEY, admin_id INTEGER, admin_usuario VARCHAR(100) DEFAULT '', acao VARCHAR(200) NOT NULL, detalhes TEXT DEFAULT '', ip VARCHAR(100) DEFAULT '', user_agent TEXT DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS chamados (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, titulo VARCHAR(200) NOT NULL, descricao TEXT DEFAULT '', status VARCHAR(20) DEFAULT 'aberto', prioridade VARCHAR(20) DEFAULT 'media', resposta TEXT DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP, atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS arquivos (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, nome VARCHAR(255) NOT NULL, nome_original VARCHAR(255) NOT NULL, tipo VARCHAR(100), tamanho BIGINT DEFAULT 0, caminho VARCHAR(500), descricao TEXT DEFAULT '', criado_por VARCHAR(100) DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS historico_clientes (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE SET NULL, admin_usuario VARCHAR(100) DEFAULT '', acao VARCHAR(200) NOT NULL, detalhes TEXT DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS config_geral (chave VARCHAR(100) PRIMARY KEY, valor TEXT DEFAULT '', descricao VARCHAR(200) DEFAULT '')",
      "CREATE TABLE IF NOT EXISTS logs_auditoria (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, usuario VARCHAR(100) DEFAULT '', acao VARCHAR(100) NOT NULL, tipo VARCHAR(50) DEFAULT '', alvo VARCHAR(200) DEFAULT '', detalhes TEXT DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS mural (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, titulo VARCHAR(200) NOT NULL, texto TEXT DEFAULT '', prioridade VARCHAR(20) DEFAULT 'normal', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP, atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS localizacoes_motoristas (id SERIAL PRIMARY KEY, motorista_id INTEGER, cliente_id INTEGER, nome VARCHAR(200) DEFAULT '', placa VARCHAR(20) DEFAULT '', empresa VARCHAR(200) DEFAULT '', lat DOUBLE PRECISION, lng DOUBLE PRECISION, rua VARCHAR(200) DEFAULT '', a_caminho BOOLEAN DEFAULT TRUE, atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE INDEX IF NOT EXISTS idx_localizacoes_cliente ON localizacoes_motoristas(cliente_id, a_caminho)",
      "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS rua VARCHAR(200) DEFAULT ''",
      "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS chegou BOOLEAN DEFAULT FALSE",
      "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS chegada_em TIMESTAMP DEFAULT NULL",
      "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS saida_logistica BOOLEAN DEFAULT FALSE",
      "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS finalidade_tipo VARCHAR(50) DEFAULT ''",
      "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS saida_em TIMESTAMP DEFAULT NULL",
    "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS cnh VARCHAR(50) DEFAULT ''",
    "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS modelo VARCHAR(100) DEFAULT ''",
    "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS finalidade VARCHAR(100) DEFAULT ''",
    "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS nota VARCHAR(100) DEFAULT ''",
    "ALTER TABLE localizacoes_motoristas ADD COLUMN IF NOT EXISTS obs TEXT DEFAULT ''",
      "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS trocar_senha BOOLEAN DEFAULT FALSE",
      "ALTER TABLE contas_motoristas ADD COLUMN IF NOT EXISTS trocar_senha BOOLEAN DEFAULT FALSE",
      "ALTER TABLE contas_visitantes ADD COLUMN IF NOT EXISTS trocar_senha BOOLEAN DEFAULT FALSE",
      "ALTER TABLE contas_visitantes ADD COLUMN IF NOT EXISTS rg VARCHAR(30) DEFAULT ''",
      "ALTER TABLE contas_visitantes ADD COLUMN IF NOT EXISTS telefone VARCHAR(30) DEFAULT ''",
      "ALTER TABLE contas_visitantes ADD COLUMN IF NOT EXISTS setor_visitado VARCHAR(100) DEFAULT ''",
      "ALTER TABLE contas_visitantes ADD COLUMN IF NOT EXISTS autorizado_por VARCHAR(100) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS rg VARCHAR(30) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS cracha VARCHAR(50) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS telefone VARCHAR(30) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS setor_visitado VARCHAR(100) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS autorizado_por VARCHAR(100) DEFAULT ''",
      "ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS trocar_senha BOOLEAN DEFAULT FALSE",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS logistica_ativo BOOLEAN DEFAULT FALSE",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS logistica_token VARCHAR(100) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS checkin_ativo BOOLEAN DEFAULT TRUE",
      "ALTER TABLE registros ADD COLUMN IF NOT EXISTS origem VARCHAR(20) DEFAULT 'portaria'",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS origem VARCHAR(20) DEFAULT 'portaria'",
      "ALTER TABLE registros ADD COLUMN IF NOT EXISTS patio_liberado BOOLEAN DEFAULT FALSE",
      "ALTER TABLE registros ADD COLUMN IF NOT EXISTS veiculo_no_patio BOOLEAN DEFAULT FALSE",
      "CREATE TABLE IF NOT EXISTS agendamentos (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, motorista VARCHAR(200) DEFAULT '', placa VARCHAR(20) DEFAULT '', empresa VARCHAR(200) DEFAULT '', finalidade VARCHAR(50) DEFAULT '', data_agendada DATE NOT NULL, horario VARCHAR(10) DEFAULT '', doca VARCHAR(50) DEFAULT '', nota VARCHAR(500) DEFAULT '', status VARCHAR(20) DEFAULT 'agendado', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP, atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE INDEX IF NOT EXISTS idx_agendamentos_cliente ON agendamentos(cliente_id, data_agendada)",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS whatsapp_ativo BOOLEAN DEFAULT FALSE",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS whatsapp_provedor VARCHAR(20) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS whatsapp_token VARCHAR(500) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS whatsapp_telefone VARCHAR(30) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS whatsapp_telefone_notif VARCHAR(30) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS whatsapp_url VARCHAR(300) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS whatsapp_instancia VARCHAR(200) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS email_ativo BOOLEAN DEFAULT FALSE",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS email_smtp_host VARCHAR(200) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS email_smtp_port VARCHAR(10) DEFAULT '587'",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS email_smtp_user VARCHAR(200) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS email_smtp_pass VARCHAR(500) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS email_remetente VARCHAR(200) DEFAULT ''",
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS email_destinatario VARCHAR(200) DEFAULT ''",
      "CREATE TABLE IF NOT EXISTS notificacoes (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, tipo VARCHAR(30) NOT NULL, titulo VARCHAR(200) NOT NULL, descricao TEXT DEFAULT '', lida BOOLEAN DEFAULT FALSE, criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE INDEX IF NOT EXISTS idx_notificacoes_cliente ON notificacoes(cliente_id, lida, criado_em DESC)",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS telefone_motorista VARCHAR(30) DEFAULT ''",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS descricao_material TEXT DEFAULT ''",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS quantidade_peso VARCHAR(100) DEFAULT ''",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS nome_recebedor VARCHAR(200) DEFAULT ''",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS data_previsao DATE DEFAULT NULL",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS tipo_checkin VARCHAR(20) DEFAULT 'chegada'",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS status_checkin VARCHAR(20) DEFAULT 'aguardando'",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS motorista_token VARCHAR(100) DEFAULT ''",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS transito_inicio TIMESTAMP DEFAULT NULL",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS transito_lat DECIMAL(10,7) DEFAULT NULL",
      "ALTER TABLE pre_registros ADD COLUMN IF NOT EXISTS transito_lng DECIMAL(10,7) DEFAULT NULL",
      "ALTER TABLE contas_motoristas ALTER COLUMN ativo SET DEFAULT FALSE",
      "UPDATE contas_motoristas SET ativo = FALSE WHERE ativo IS NULL"
    ];
    for (const col of migrateCols) {
      try { await pool.query(col); } catch(e) {}
    }
    const clienteCheck = await pool.query("SELECT id FROM clientes WHERE empresa ILIKE '%OCEANICA%' OR empresa ILIKE '%OCEÂNICA%'");
    if (clienteCheck.rows.length === 0) {
      const cli = await pool.query("INSERT INTO clientes (empresa, responsavel, plano, ativo) VALUES ('OCEANICA ENGENHARIA', 'ADMIN', 'premium', TRUE) RETURNING id");
      const cid = cli.rows[0].id;
      console.log('Cliente Oceânica criado com id:', cid);
      await pool.query("UPDATE usuarios SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE registros SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE visitantes SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE pre_registros SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE contas_motoristas SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE contas_visitantes SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE pre_registros_visitantes SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE faturamento SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
    } else {
      const cid = clienteCheck.rows[0].id;
      await pool.query("UPDATE usuarios SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE registros SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE visitantes SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE pre_registros SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE contas_motoristas SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE contas_visitantes SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
      await pool.query("UPDATE pre_registros_visitantes SET cliente_id = $1 WHERE cliente_id IS NULL", [cid]);
    }
    const adminCount = await pool.query('SELECT COUNT(*)::int AS total FROM admin_users');
    if (adminCount.rows[0].total === 0) {
      const senhaSuper = await bcrypt.hash('admin123', 10);
      await pool.query(
        'INSERT INTO admin_users (nome, usuario, senha, trocar_senha) VALUES ($1, $2, $3, TRUE)',
        ['SUPER ADMIN', 'superadmin', senhaSuper]
      );
      console.warn('AVISO: Senha padrao do admin e "admin123". ALTERE IMEDIATAMENTE apos o primeiro login!');
      // TODO: trocar_senha = TRUE nao e forcado no fluxo de login admin. Implementar verificacao obrigatoria de troca de senha apos primeiro login.
    }
  } catch (err) {
    console.error('Erro ao conectar ao PostgreSQL:', err.message);
    process.exit(1);
  }
  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
    // Graceful shutdown
    const shutdown = (signal) => {
      console.log(`Recebido ${signal}. Encerrando graciosamente...`);
      let settled = false;
      const forceExit = setTimeout(() => {
        if (!settled) { console.error('Forçando encerramento apos timeout'); process.exit(1); }
      }, 10000);
      server.close(() => {
        settled = true;
        clearTimeout(forceExit);
        console.log('Servidor encerrado.');
        process.exit(0);
      });
      // Encerrar pool do banco
      pool.end().catch(() => {});
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection:', reason);
    });
    process.on('uncaughtException', (err) => {
      console.error('Uncaught Exception:', err);
      if (err.message && err.message.includes('ECONNRESET')) return;
      process.exit(1);
    });
  });
}

iniciar();
