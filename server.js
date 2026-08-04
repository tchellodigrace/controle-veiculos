require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const path = require('path');
const rateLimit = require('express-rate-limit');
const uuid = () => crypto.randomBytes(16).toString('hex');

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

const JWT_SECRET = process.env.JWT_SECRET || 'arcatech-controle-portaria-2026-fallback-key';
if (!process.env.JWT_SECRET) console.warn('AVISO: JWT_SECRET nao definido. Usando fallback. Defina JWT_SECRET no ambiente!');

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
  res.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'");
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  next();
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
      'SELECT id, cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, saida, nota, obs, posicao, data_registro FROM registros WHERE cliente_id = $1 AND data_registro = CURRENT_DATE ORDER BY id ASC',
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
    const errEmpresa = validarString(empresa, 2, 100, 'Empresa');
    if (errEmpresa) return res.status(400).json({ erro: errEmpresa });
    const errModelo = validarString(modelo, 0, 100, 'Modelo');
    if (errModelo) return res.status(400).json({ erro: errModelo });
    const errMotorista = validarString(motorista, 0, 100, 'Motorista');
    if (errMotorista) return res.status(400).json({ erro: errMotorista });
    const errCnh = validarString(cnh, 0, 20, 'CNH');
    if (errCnh) return res.status(400).json({ erro: errCnh });
    const errNota = validarString(nota, 0, 50, 'Nota');
    if (errNota) return res.status(400).json({ erro: errNota });
    const errObs = validarString(obs, 0, 500, 'Observacao');
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
      [cid, hora, placaClean, sanitizarString(modelo).substring(0,100), sanitizarString(finalidade).substring(0,50), sanitizarString(empresa).substring(0,100), sanitizarString(motorista).substring(0,100), sanitizarString(cnh).substring(0,20), hora, sanitizarString(nota).substring(0,50), sanitizarString(obs).substring(0,500), pos.rows[0].prox]
    );
    res.status(201).json(result.rows[0]);
    logAuditoria(cid, req.usuario?.nome || '', 'Entrada', 'veiculo', placa.toUpperCase(), 'Motorista: ' + (motorista||'') + ' | Empresa: ' + empresa);
  } catch (err) {
    console.error('Erro ao criar registro:', err);
    res.status(500).json({ erro: 'Erro ao criar registro' });
  }
});

app.put('/api/registros/:id/saida', authMiddleware, apiLimiter, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ erro: 'ID invalido' });
  try {
    const hora = new Date().toLocaleTimeString('pt-BR'); // Sempre do servidor
    const result = await pool.query(
      'UPDATE registros SET saida = $1 WHERE id = $2 AND saida = $3 AND cliente_id = $4 RETURNING id, cliente_id, placa, modelo, saida',
      [hora, req.params.id, '', req.usuario.cliente_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Registro não encontrado ou já possui saída' });
    res.json(result.rows[0]);
    logAuditoria(req.usuario.cliente_id, req.usuario?.nome || '', 'Saida', 'veiculo', result.rows[0].placa, 'Saida registrada as ' + hora);
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
    const result = await pool.query(
      `SELECT DISTINCT empresa FROM registros
       WHERE cliente_id = $1 AND empresa != '' ORDER BY empresa ASC`,
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar empresas:', err);
    res.status(500).json({ erro: 'Erro ao listar empresas' });
  }
});

app.get('/api/empresas-lista-pre', apiLimiter, async (req, res) => {
  try {
    const cid = req.query.cliente_id;
    if (!cid || !/^\d+$/.test(String(cid))) return res.json([]);
    const result = await pool.query(
      `SELECT DISTINCT empresa FROM registros WHERE cliente_id = $1 AND empresa != '' ORDER BY empresa ASC`, [cid]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar empresas:', err);
    res.status(500).json({ erro: 'Erro ao listar empresas' });
  }
});

app.get('/api/visitantes-lista', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT nome, cpf, empresa FROM visitantes
       WHERE cliente_id = $1 AND nome != '' ORDER BY nome ASC`,
      [req.usuario.cliente_id]
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
    const result = await pool.query(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE saida = '')::int AS aguardando,
        COUNT(*) FILTER (WHERE saida != '')::int AS saidas
      FROM registros WHERE cliente_id = $1 AND data_registro = CURRENT_DATE
    `, [req.usuario.cliente_id]);
    res.json(result.rows[0]);
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
      'SELECT id, cliente_id, nome, cpf, empresa, tipo, placa, nota, obs, entrada, saida, posicao, data_registro FROM visitantes WHERE cliente_id = $1 AND data_registro = CURRENT_DATE ORDER BY id ASC',
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
    const { nome, cpf, empresa, tipo, placa, nota, obs } = req.body;
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
      `INSERT INTO visitantes (cliente_id, nome, cpf, empresa, tipo, placa, nota, obs, entrada, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, cliente_id, nome, cpf, empresa, tipo, placa, nota, obs, entrada, saida, posicao, data_registro`,
      [cid, sanitizarString(nome).toUpperCase(), (cpf||'').replace(/[^0-9]/g, ''), sanitizarString(empresa), sanitizarString(tipo), (placa||'').toUpperCase().replace(/[^A-Z0-9]/g, '').substring(0,8), sanitizarString(nota).substring(0,50), sanitizarString(obs).substring(0,500), hora, pos.rows[0].prox]
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
    const result = await pool.query(
      'INSERT INTO contas_motoristas (cliente_id, usuario, senha, nome, empresa, ativo) VALUES ($1, $2, $3, $4, $5, FALSE) RETURNING id, usuario, nome',
      [cliente_id, usuario.toLowerCase(), senhaHash, nome.toUpperCase(), empresa||'']
    );
    res.status(201).json({ mensagem: 'Conta criada com sucesso. Aguarde a ativação da portaria.', motorista: result.rows[0] });
  } catch (err) {
    console.error('Erro ao cadastrar motorista:', err);
    res.status(500).json({ erro: 'Erro ao criar conta' });
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

app.get('/api/pre-registros', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs, criado_em FROM pre_registros WHERE cliente_id = $1 ORDER BY id ASC',
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
    res.status(201).json(registro.rows[0]);
    logAuditoria(cid, req.usuario?.nome || '', 'Confirmacao pre-registro', 'veiculo', d.placa, 'Motorista: ' + (d.motorista||'') + ' | Empresa: ' + d.empresa);
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
      'SELECT id, usuario, nome, empresa, ativo, criado_em FROM contas_motoristas WHERE cliente_id = $1 ORDER BY nome',
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
    const cid = req.usuario.cliente_id;
    const result = await pool.query(
      'INSERT INTO contas_motoristas (cliente_id, usuario, senha, nome, empresa) VALUES ($1, $2, $3, $4, $5) RETURNING id, usuario, nome, empresa',
      [cid, usuario.toLowerCase(), senhaHash, nome.toUpperCase(), empresa||'']
    );
    res.status(201).json(result.rows[0]);
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

app.post('/api/cadastro-visitante', preRegistroLimiter, async (req, res) => {
  try {
    const { cliente_id, nome, usuario, senha, cpf, empresa } = req.body;
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
    const result = await pool.query(
      'INSERT INTO contas_visitantes (cliente_id, usuario, senha, nome, cpf, empresa, ativo) VALUES ($1, $2, $3, $4, $5, $6, FALSE) RETURNING id, usuario, nome',
      [cliente_id, usuario.toLowerCase(), senhaHash, nome.toUpperCase(), cpf||'', empresa||'']
    );
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
    const { cliente_id, visitante_id, nome, cpf, empresa, tipo, placa, nota, obs } = req.body;
    const finalNome = nome || '';
    if (!cliente_id || !finalNome) return res.status(400).json({ erro: 'Nome e empresa são obrigatórios' });
    if (!/^\d+$/.test(String(cliente_id))) return res.status(400).json({ erro: 'ID de cliente invalido' });
    const errCpfPreV = validarCpf(cpf);
    if (errCpfPreV) return res.status(400).json({ erro: errCpfPreV });
    const result = await pool.query(
      `INSERT INTO pre_registros_visitantes (cliente_id, visitante_id, nome, cpf, empresa, tipo, placa, nota, obs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, cliente_id, visitante_id, nome, cpf, empresa, tipo, placa, nota, obs, criado_em`,
      [cliente_id, visitante_id || null, sanitizarString(finalNome).toUpperCase(), (cpf||'').replace(/[^0-9]/g, ''), sanitizarString(empresa), sanitizarString(tipo), (placa||'').toUpperCase().replace(/[^A-Z0-9]/g, '').substring(0,8), sanitizarString(nota).substring(0,50), sanitizarString(obs).substring(0,500)]
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
      'SELECT id, cliente_id, visitante_id, nome, cpf, empresa, tipo, placa, nota, obs, criado_em FROM pre_registros_visitantes WHERE cliente_id = $1 ORDER BY id ASC',
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
    const pre = await pool.query('SELECT id, cliente_id, visitante_id, nome, cpf, empresa, tipo, placa, nota, obs, criado_em FROM pre_registros_visitantes WHERE id = $1 AND cliente_id = $2', [req.params.id, cid]);
    if (pre.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    const d = pre.rows[0];
    const hora = new Date().toLocaleTimeString('pt-BR'); // Sempre do servidor
    const hoje = new Date().toLocaleDateString('en-CA'); // Sempre do servidor
    const pos = await pool.query(
      `SELECT COALESCE(MAX(posicao), 0) + 1 AS prox FROM visitantes WHERE cliente_id = $1 AND data_registro = $2`,
      [cid, hoje]
    );
    const visitante = await pool.query(
      `INSERT INTO visitantes (cliente_id, nome, cpf, empresa, tipo, placa, nota, obs, entrada, data_registro, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id, cliente_id, nome, cpf, empresa, tipo, placa, nota, obs, entrada, saida, data_registro, posicao`,
      [cid, d.nome, d.cpf, d.empresa, d.tipo||'', d.placa||'', d.nota||'', d.obs||'', hora, hoje, pos.rows[0].prox]
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
    const result = await pool.query('DELETE FROM pre_registros_visitantes WHERE id = $1 AND cliente_id = $2 RETURNING id, cliente_id, nome, cpf, empresa', [req.params.id, req.usuario.cliente_id]);
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
    const { usuario, senha, nome, cpf, empresa } = req.body;
    if (!usuario || !senha || !nome) return res.status(400).json({ erro: 'Usuário, senha e nome são obrigatórios' });
    if (senha.length < 8 || senha.length > 100) return res.status(400).json({ erro: 'Senha deve ter entre 8 e 100 caracteres' });
    const errComp5 = validarComplexidadeSenha(senha);
    if (errComp5) return res.status(400).json({ erro: errComp5 });
    const errCpfCV = validarCpf(cpf);
    if (errCpfCV) return res.status(400).json({ erro: errCpfCV });
    const senhaHash = await bcrypt.hash(senha, 10);
    const cid = req.usuario.cliente_id;
    const result = await pool.query(
      'INSERT INTO contas_visitantes (cliente_id, usuario, senha, nome, cpf, empresa) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, usuario, nome',
      [cid, usuario.toLowerCase(), senhaHash, nome.toUpperCase(), cpf||'', empresa||'']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    console.error('Erro ao criar conta visitante:', err);
    res.status(500).json({ erro: 'Erro ao criar conta' });
  }
});

app.get('/api/contas-visitantes', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, usuario, nome, cpf, empresa, ativo, criado_em FROM contas_visitantes WHERE cliente_id = $1 ORDER BY nome',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar contas visitantes:', err);
    res.status(500).json({ erro: 'Erro ao buscar contas' });
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
    const result = await pool.query('SELECT id, nome, usuario, senha FROM admin_users WHERE usuario = $1', [usuario.toLowerCase()]);
    if (result.rows.length === 0) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    const admin = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, admin.senha);
    if (!senhaValida) { recordFailedAttempt(lockKey); return res.status(401).json({ erro: 'Usuário ou senha inválidos' }); }
    clearAttempts(lockKey);
    const token = jwt.sign({ id: admin.id, nome: admin.nome, admin: true }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, admin: { id: admin.id, nome: admin.nome } });
  } catch (err) {
    console.error('Erro no login admin:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

app.get('/api/admin/clientes', adminMiddleware, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, empresa, cnpj, responsavel, email, telefone, telefone_fixo, plano, valor_mensal, data_expiracao, dominio, ativo, criado_em FROM clientes ORDER BY criado_em DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar clientes:', err);
    res.status(500).json({ erro: 'Erro ao buscar clientes' });
  }
});

app.post('/api/admin/clientes', adminMiddleware, async (req, res) => {
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
    if (ativo !== undefined) { params.push(ativo); updates.push(`ativo = $${params.length}`); }
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
    const result = await pool.query('SELECT id, nome, usuario, ativo FROM usuarios WHERE cliente_id = $1 ORDER BY nome', [req.params.id]);
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
      'INSERT INTO usuarios (cliente_id, nome, usuario, senha) VALUES ($1, $2, $3, $4) RETURNING id, nome, usuario',
      [cliente_id, n, u.toLowerCase(), senhaHash]
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
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS telefone_fixo VARCHAR(20) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS obs VARCHAR(500) DEFAULT ''",
      "ALTER TABLE visitantes ADD COLUMN IF NOT EXISTS posicao INTEGER DEFAULT 0",
      "CREATE TABLE IF NOT EXISTS faturamento (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, valor DECIMAL(10,2) NOT NULL, descricao VARCHAR(200) DEFAULT '', data_pagamento DATE DEFAULT CURRENT_DATE, criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS logs_acesso (id SERIAL PRIMARY KEY, admin_id INTEGER, admin_usuario VARCHAR(100) DEFAULT '', acao VARCHAR(200) NOT NULL, detalhes TEXT DEFAULT '', ip VARCHAR(100) DEFAULT '', user_agent TEXT DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS chamados (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, titulo VARCHAR(200) NOT NULL, descricao TEXT DEFAULT '', status VARCHAR(20) DEFAULT 'aberto', prioridade VARCHAR(20) DEFAULT 'media', resposta TEXT DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP, atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS historico_clientes (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE SET NULL, admin_usuario VARCHAR(100) DEFAULT '', acao VARCHAR(200) NOT NULL, detalhes TEXT DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS config_geral (chave VARCHAR(100) PRIMARY KEY, valor TEXT DEFAULT '', descricao VARCHAR(200) DEFAULT '')",
      "CREATE TABLE IF NOT EXISTS logs_auditoria (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, usuario VARCHAR(100) DEFAULT '', acao VARCHAR(100) NOT NULL, tipo VARCHAR(50) DEFAULT '', alvo VARCHAR(200) DEFAULT '', detalhes TEXT DEFAULT '', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "CREATE TABLE IF NOT EXISTS mural (id SERIAL PRIMARY KEY, cliente_id INTEGER REFERENCES clientes(id) ON DELETE CASCADE, titulo VARCHAR(200) NOT NULL, texto TEXT DEFAULT '', prioridade VARCHAR(20) DEFAULT 'normal', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP, atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
      "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS trocar_senha BOOLEAN DEFAULT FALSE",
      "ALTER TABLE contas_motoristas ADD COLUMN IF NOT EXISTS trocar_senha BOOLEAN DEFAULT FALSE",
      "ALTER TABLE contas_visitantes ADD COLUMN IF NOT EXISTS trocar_senha BOOLEAN DEFAULT FALSE",
      "ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS trocar_senha BOOLEAN DEFAULT FALSE"
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
  });
}

iniciar();
