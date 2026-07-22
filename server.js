require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'oceanica-secret-key';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

app.post('/api/login', async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    if (!usuario || !senha) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios' });
    const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1 AND ativo = TRUE', [usuario.toLowerCase()]);
    if (result.rows.length === 0) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    const user = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, user.senha);
    if (!senhaValida) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    const token = gerarToken(user);
    const cliente = user.cliente_id ? (await pool.query('SELECT * FROM clientes WHERE id = $1', [user.cliente_id])).rows[0] : null;
    res.json({ token, usuario: { nome: user.nome, usuario: user.usuario, cliente_id: user.cliente_id }, empresa: cliente ? cliente.empresa : '' });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

app.get('/api/verificar-token', authMiddleware, (req, res) => {
  res.json({ valido: true, usuario: req.usuario });
});

app.get('/api/registros', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM registros WHERE cliente_id = $1 AND data_registro = CURRENT_DATE ORDER BY id ASC',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar registros:', err);
    res.status(500).json({ erro: 'Erro ao buscar registros' });
  }
});

app.get('/api/registros/todos', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM registros WHERE cliente_id = $1 ORDER BY data_registro DESC, id DESC LIMIT 500',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar registros:', err);
    res.status(500).json({ erro: 'Erro ao buscar registros' });
  }
});

app.post('/api/registros', authMiddleware, async (req, res) => {
  try {
    const { placa, modelo, finalidade, empresa, motorista, cnh, nota, obs, hora: clientHora } = req.body;
    if (!placa || !empresa) return res.status(400).json({ erro: 'Placa e Empresa são obrigatórios' });
    const hora = clientHora || new Date().toLocaleTimeString('pt-BR');
    const cid = req.usuario.cliente_id;
    const pos = await pool.query(
      `SELECT COALESCE(MAX(posicao), 0) + 1 AS prox FROM registros WHERE cliente_id = $1 AND data_registro = CURRENT_DATE`,
      [cid]
    );
    const result = await pool.query(
      `INSERT INTO registros (cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, nota, obs, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [cid, hora, placa.toUpperCase(), modelo||'', finalidade||'', empresa, motorista||'', cnh||'', hora, nota||'', obs||'', pos.rows[0].prox]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao criar registro:', err);
    res.status(500).json({ erro: 'Erro ao criar registro' });
  }
});

app.put('/api/registros/:id/saida', authMiddleware, async (req, res) => {
  try {
    const hora = req.body.hora || new Date().toLocaleTimeString('pt-BR');
    const result = await pool.query(
      'UPDATE registros SET saida = $1 WHERE id = $2 AND saida = $3 AND cliente_id = $4 RETURNING *',
      [hora, req.params.id, '', req.usuario.cliente_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Registro não encontrado ou já possui saída' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao marcar saída:', err);
    res.status(500).json({ erro: 'Erro ao marcar saída' });
  }
});

app.delete('/api/registros/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM registros WHERE id = $1 AND cliente_id = $2 RETURNING *', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Registro não encontrado' });
    res.json({ mensagem: 'Registro excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir registro:', err);
    res.status(500).json({ erro: 'Erro ao excluir registro' });
  }
});

app.get('/api/auto-preenchimento', authMiddleware, async (req, res) => {
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

app.get('/api/motoristas-lista', authMiddleware, async (req, res) => {
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

app.get('/api/empresas-lista', authMiddleware, async (req, res) => {
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

app.get('/api/empresas-lista-pre', async (req, res) => {
  try {
    const cid = req.query.cliente_id;
    if (!cid) return res.json([]);
    const result = await pool.query(
      `SELECT DISTINCT empresa FROM registros WHERE cliente_id = $1 AND empresa != '' ORDER BY empresa ASC`, [cid]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar empresas:', err);
    res.status(500).json({ erro: 'Erro ao listar empresas' });
  }
});

app.get('/api/visitantes-lista', authMiddleware, async (req, res) => {
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

app.get('/api/auto-preenchimento-visitante', authMiddleware, async (req, res) => {
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

app.get('/api/resumo', authMiddleware, async (req, res) => {
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

app.get('/api/usuarios', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, nome, usuario, senha_exibicao, ativo, criado_em FROM usuarios WHERE cliente_id = $1 ORDER BY nome',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar usuários:', err);
    res.status(500).json({ erro: 'Erro ao buscar usuários' });
  }
});

app.post('/api/usuarios', authMiddleware, async (req, res) => {
  try {
    const { nome, usuario, senha } = req.body;
    if (!nome || !usuario || !senha) return res.status(400).json({ erro: 'Nome, usuário e senha são obrigatórios' });
    const senhaHash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (cliente_id, nome, usuario, senha, senha_exibicao) VALUES ($1, $2, $3, $4, $5) RETURNING id, nome, usuario, senha_exibicao',
      [req.usuario.cliente_id, nome, usuario.toLowerCase(), senhaHash, senha]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    console.error('Erro ao criar usuário:', err);
    res.status(500).json({ erro: 'Erro ao criar usuário' });
  }
});

app.put('/api/config', authMiddleware, async (req, res) => {
  try {
    const { nome, senha } = req.body;
    if (senha) {
      const senhaHash = await bcrypt.hash(senha, 10);
      await pool.query('UPDATE usuarios SET nome=$1, senha=$2 WHERE id=$3', [nome, senhaHash, req.usuario.id]);
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

app.get('/api/visitantes', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM visitantes WHERE cliente_id = $1 AND data_registro = CURRENT_DATE ORDER BY id ASC',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar visitantes:', err);
    res.status(500).json({ erro: 'Erro ao buscar visitantes' });
  }
});

app.post('/api/visitantes', authMiddleware, async (req, res) => {
  try {
    const { nome, cpf, empresa, tipo, placa, nota, hora: clientHora } = req.body;
    if (!nome) return res.status(400).json({ erro: 'Nome é obrigatório' });
    const hora = clientHora || new Date().toLocaleTimeString('pt-BR');
    const cid = req.usuario.cliente_id;
    const result = await pool.query(
      `INSERT INTO visitantes (cliente_id, usuario_id, nome, cpf, empresa, tipo, placa, nota, entrada)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [cid, req.usuario.id, nome.toUpperCase(), cpf||'', empresa||'', tipo||'', (placa||'').toUpperCase(), nota||'', hora]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao criar visitante:', err);
    res.status(500).json({ erro: 'Erro ao criar visitante' });
  }
});

app.put('/api/visitantes/:id/saida', authMiddleware, async (req, res) => {
  try {
    const hora = req.body.hora || new Date().toLocaleTimeString('pt-BR');
    const result = await pool.query(
      'UPDATE visitantes SET saida = $1 WHERE id = $2 AND saida = $3 AND cliente_id = $4 RETURNING *',
      [hora, req.params.id, '', req.usuario.cliente_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Visitante não encontrado ou já possui saída' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao marcar saída:', err);
    res.status(500).json({ erro: 'Erro ao marcar saída' });
  }
});

app.delete('/api/visitantes/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM visitantes WHERE id = $1 AND cliente_id = $2 RETURNING *', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Visitante não encontrado' });
    res.json({ mensagem: 'Visitante excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir visitante:', err);
    res.status(500).json({ erro: 'Erro ao excluir visitante' });
  }
});

app.post('/api/pre-registro', async (req, res) => {
  try {
    const { cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs } = req.body;
    const finalEmpresa = empresa || '';
    const finalMotorista = motorista || '';
    if (!cliente_id || !finalMotorista || !placa) return res.status(400).json({ erro: 'Empresa, motorista e placa são obrigatórios' });
    const result = await pool.query(
      `INSERT INTO pre_registros (cliente_id, empresa, motorista, cnh, placa, modelo, finalidade, nota, obs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [cliente_id, finalEmpresa.toUpperCase(), finalMotorista.toUpperCase(), cnh||'', placa.toUpperCase(), modelo||'', finalidade||'', nota||'', obs||'']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro no pre-registro:', err);
    res.status(500).json({ erro: 'Erro ao realizar pré-registro: ' + err.message });
  }
});

app.post('/api/cadastro-motorista', async (req, res) => {
  try {
    const { cliente_id, nome, usuario, senha, empresa } = req.body;
    if (!cliente_id || !nome || !usuario || !senha) return res.status(400).json({ erro: 'Nome, usuário e senha são obrigatórios' });
    const existe = await pool.query('SELECT id FROM contas_motoristas WHERE cliente_id = $1 AND usuario = $2', [cliente_id, usuario.toLowerCase()]);
    if (existe.rows.length > 0) return res.status(400).json({ erro: 'Usuário já existe' });
    const senhaHash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO contas_motoristas (cliente_id, usuario, senha, nome, empresa, senha_exibicao, ativo) VALUES ($1, $2, $3, $4, $5, $6, FALSE) RETURNING id, usuario, nome',
      [cliente_id, usuario.toLowerCase(), senhaHash, nome.toUpperCase(), empresa||'', senha]
    );
    res.status(201).json({ mensagem: 'Conta criada com sucesso. Aguarde a ativação da portaria.', motorista: result.rows[0] });
  } catch (err) {
    console.error('Erro ao cadastrar motorista:', err);
    res.status(500).json({ erro: 'Erro ao criar conta: ' + err.message });
  }
});

app.post('/api/login-motorista', async (req, res) => {
  try {
    const { usuario, senha, cliente_id } = req.body;
    if (!usuario || !senha || !cliente_id) return res.status(400).json({ erro: 'Usuário, senha e empresa são obrigatórios' });
    const result = await pool.query('SELECT * FROM contas_motoristas WHERE cliente_id = $1 AND usuario = $2 AND ativo = TRUE', [cliente_id, usuario.toLowerCase()]);
    if (result.rows.length === 0) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    const conta = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, conta.senha);
    if (!senhaValida) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    const token = jwt.sign({ id: conta.id, nome: conta.nome, cliente_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, motorista: { id: conta.id, nome: conta.nome } });
  } catch (err) {
    console.error('Erro no login motorista:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

app.get('/api/pre-registros', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM pre_registros WHERE cliente_id = $1 ORDER BY id ASC',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar pre-registros:', err);
    res.status(500).json({ erro: 'Erro ao buscar pré-registros' });
  }
});

app.post('/api/pre-registros/:id/confirmar', authMiddleware, async (req, res) => {
  try {
    const cid = req.usuario.cliente_id;
    const pre = await pool.query('SELECT * FROM pre_registros WHERE id = $1 AND cliente_id = $2', [req.params.id, cid]);
    if (pre.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    const d = pre.rows[0];
    const hora = req.body.hora || new Date().toLocaleTimeString('pt-BR');
    const hoje = req.body.data || new Date().toLocaleDateString('en-CA');
    const pos = await pool.query(
      `SELECT COALESCE(MAX(posicao), 0) + 1 AS prox FROM registros WHERE cliente_id = $1 AND data_registro = $2`,
      [cid, hoje]
    );
    const posicao = pos.rows[0].prox;
    const registro = await pool.query(
      `INSERT INTO registros (cliente_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, nota, obs, data_registro, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [cid, hora, d.placa, d.modelo, d.finalidade, d.empresa, d.motorista, d.cnh, hora, d.nota || '', d.obs, hoje, posicao]
    );
    await pool.query('DELETE FROM pre_registros WHERE id = $1', [req.params.id]);
    res.status(201).json(registro.rows[0]);
  } catch (err) {
    console.error('Erro ao confirmar pre-registro:', err);
    res.status(500).json({ erro: 'Erro ao confirmar pré-registro' });
  }
});

app.delete('/api/pre-registros/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM pre_registros WHERE id = $1 AND cliente_id = $2 RETURNING *', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    res.json({ mensagem: 'Pré-registro excluído' });
  } catch (err) {
    console.error('Erro ao excluir pre-registro:', err);
    res.status(500).json({ erro: 'Erro ao excluir pré-registro' });
  }
});

app.get('/api/contas-motoristas', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, usuario, nome, empresa, senha_exibicao, ativo, criado_em FROM contas_motoristas WHERE cliente_id = $1 ORDER BY nome',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar contas:', err);
    res.status(500).json({ erro: 'Erro ao buscar contas' });
  }
});

app.post('/api/contas-motoristas', authMiddleware, async (req, res) => {
  try {
    const { usuario, senha, nome, empresa } = req.body;
    if (!usuario || !senha || !nome) return res.status(400).json({ erro: 'Usuário, senha e nome são obrigatórios' });
    const senhaHash = await bcrypt.hash(senha, 10);
    const cid = req.usuario.cliente_id;
    const result = await pool.query(
      'INSERT INTO contas_motoristas (cliente_id, usuario, senha, nome, empresa, senha_exibicao) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, usuario, nome, empresa',
      [cid, usuario.toLowerCase(), senhaHash, nome.toUpperCase(), empresa||'', senha]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    console.error('Erro ao criar conta motorista:', err);
    res.status(500).json({ erro: 'Erro ao criar conta: ' + err.message });
  }
});

app.put('/api/contas-motoristas/:id', authMiddleware, async (req, res) => {
  try {
    const { nome, ativo, empresa } = req.body;
    const updates = []; const params = [];
    if (nome) { params.push(nome.toUpperCase()); updates.push(`nome = $${params.length}`); }
    if (empresa !== undefined) { params.push(empresa); updates.push(`empresa = $${params.length}`); }
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

app.post('/api/cadastro-visitante', async (req, res) => {
  try {
    const { cliente_id, nome, usuario, senha, cpf, empresa } = req.body;
    if (!cliente_id || !nome || !usuario || !senha) return res.status(400).json({ erro: 'Nome, usuário e senha são obrigatórios' });
    const existe = await pool.query('SELECT id FROM contas_visitantes WHERE cliente_id = $1 AND usuario = $2', [cliente_id, usuario.toLowerCase()]);
    if (existe.rows.length > 0) return res.status(400).json({ erro: 'Usuário já existe' });
    const senhaHash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO contas_visitantes (cliente_id, usuario, senha, nome, cpf, empresa, senha_exibicao, ativo) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE) RETURNING id, usuario, nome',
      [cliente_id, usuario.toLowerCase(), senhaHash, nome.toUpperCase(), cpf||'', empresa||'', senha]
    );
    res.status(201).json({ mensagem: 'Conta criada. Aguarde ativação da portaria.', visitante: result.rows[0] });
  } catch (err) {
    console.error('Erro ao cadastrar visitante:', err);
    res.status(500).json({ erro: 'Erro ao criar conta: ' + err.message });
  }
});

app.post('/api/login-visitante', async (req, res) => {
  try {
    const { usuario, senha, cliente_id } = req.body;
    if (!usuario || !senha || !cliente_id) return res.status(400).json({ erro: 'Usuário, senha e empresa são obrigatórios' });
    const result = await pool.query('SELECT * FROM contas_visitantes WHERE cliente_id = $1 AND usuario = $2 AND ativo = TRUE', [cliente_id, usuario.toLowerCase()]);
    if (result.rows.length === 0) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    const conta = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, conta.senha);
    if (!senhaValida) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    const token = jwt.sign({ id: conta.id, nome: conta.nome, cliente_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, visitante: { id: conta.id, nome: conta.nome, cpf: conta.cpf, empresa: conta.empresa } });
  } catch (err) {
    console.error('Erro no login visitante:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

app.post('/api/pre-registro-visitante', async (req, res) => {
  try {
    const { cliente_id, visitante_id, nome, cpf, empresa, tipo, placa, nota, obs } = req.body;
    const finalNome = nome || '';
    if (!cliente_id || !finalNome) return res.status(400).json({ erro: 'Nome e empresa são obrigatórios' });
    const result = await pool.query(
      `INSERT INTO pre_registros_visitantes (cliente_id, visitante_id, nome, cpf, empresa, tipo, placa, nota, obs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [cliente_id, visitante_id || null, finalNome.toUpperCase(), cpf||'', empresa||'', tipo||'', (placa||'').toUpperCase(), nota||'', obs||'']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro no pre-registro visitante:', err);
    res.status(500).json({ erro: 'Erro ao realizar pré-registro: ' + err.message });
  }
});

app.get('/api/pre-registros-visitantes', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM pre_registros_visitantes WHERE cliente_id = $1 ORDER BY id ASC',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar pre-registros visitantes:', err);
    res.status(500).json({ erro: 'Erro ao buscar pré-registros de visitantes' });
  }
});

app.post('/api/pre-registros-visitantes/:id/confirmar', authMiddleware, async (req, res) => {
  try {
    const cid = req.usuario.cliente_id;
    const pre = await pool.query('SELECT * FROM pre_registros_visitantes WHERE id = $1 AND cliente_id = $2', [req.params.id, cid]);
    if (pre.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    const d = pre.rows[0];
    const hora = req.body.hora || new Date().toLocaleTimeString('pt-BR');
    const hoje = req.body.data || new Date().toLocaleDateString('en-CA');
    const visitante = await pool.query(
      `INSERT INTO visitantes (cliente_id, nome, cpf, empresa, tipo, placa, nota, entrada, data_registro)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [cid, d.nome, d.cpf, d.empresa, d.tipo||'', d.placa||'', d.nota||'', hora, hoje]
    );
    await pool.query('DELETE FROM pre_registros_visitantes WHERE id = $1', [req.params.id]);
    res.status(201).json(visitante.rows[0]);
  } catch (err) {
    console.error('Erro ao confirmar pre-registro visitante:', err);
    res.status(500).json({ erro: 'Erro ao confirmar pré-registro de visitante: ' + err.message });
  }
});

app.delete('/api/pre-registros-visitantes/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM pre_registros_visitantes WHERE id = $1 AND cliente_id = $2 RETURNING *', [req.params.id, req.usuario.cliente_id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    res.json({ mensagem: 'Pré-registro excluído' });
  } catch (err) {
    console.error('Erro ao excluir pre-registro visitante:', err);
    res.status(500).json({ erro: 'Erro ao excluir pré-registro' });
  }
});

app.post('/api/contas-visitantes', authMiddleware, async (req, res) => {
  try {
    const { usuario, senha, nome, cpf, empresa } = req.body;
    if (!usuario || !senha || !nome) return res.status(400).json({ erro: 'Usuário, senha e nome são obrigatórios' });
    const senhaHash = await bcrypt.hash(senha, 10);
    const cid = req.usuario.cliente_id;
    const result = await pool.query(
      'INSERT INTO contas_visitantes (cliente_id, usuario, senha, nome, cpf, empresa, senha_exibicao) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, usuario, nome',
      [cid, usuario.toLowerCase(), senhaHash, nome.toUpperCase(), cpf||'', empresa||'', senha]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    console.error('Erro ao criar conta visitante:', err);
    res.status(500).json({ erro: 'Erro ao criar conta: ' + err.message });
  }
});

app.get('/api/contas-visitantes', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, usuario, nome, cpf, empresa, senha_exibicao, ativo, criado_em FROM contas_visitantes WHERE cliente_id = $1 ORDER BY nome',
      [req.usuario.cliente_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar contas visitantes:', err);
    res.status(500).json({ erro: 'Erro ao buscar contas' });
  }
});

app.put('/api/contas-visitantes/:id', authMiddleware, async (req, res) => {
  try {
    const { nome, ativo } = req.body;
    const updates = []; const params = [];
    if (nome) { params.push(nome.toUpperCase()); updates.push(`nome = $${params.length}`); }
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

app.get('/api/nome-empresa', authMiddleware, async (req, res) => {
  try {
    if (!req.usuario.cliente_id) return res.json({ empresa: '' });
    const result = await pool.query('SELECT empresa FROM clientes WHERE id = $1', [req.usuario.cliente_id]);
    res.json({ empresa: result.rows[0] ? result.rows[0].empresa : '' });
  } catch (err) {
    res.json({ empresa: '' });
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

app.post('/api/admin/login', async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    if (!usuario || !senha) return res.status(400).json({ erro: 'Usuário e senha são obrigatórios' });
    const result = await pool.query('SELECT * FROM admin_users WHERE usuario = $1', [usuario.toLowerCase()]);
    if (result.rows.length === 0) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    const admin = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, admin.senha);
    if (!senhaValida) return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    const token = jwt.sign({ id: admin.id, nome: admin.nome, admin: true }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, admin: { id: admin.id, nome: admin.nome } });
  } catch (err) {
    console.error('Erro no login admin:', err);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

app.get('/api/admin/clientes', adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clientes ORDER BY criado_em DESC');
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
    const cliResult = await client.query(
      `INSERT INTO clientes (empresa, cnpj, responsavel, email, telefone, telefone_fixo, plano, valor_mensal, data_expiracao, dominio)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [empresa.toUpperCase(), cnpj||'', responsavel||'', email||'', telefone||'', telefone_fixo||'', plano||'basico', valor_mensal||0, data_expiracao||null, dominio||'']
    );
    const cliente = cliResult.rows[0];
    const userLogin = empresa.toUpperCase().replace(/[^A-Z0-9]/g, '').substring(0, 20) + '_portaria';
    const defaultSenha = 'portaria123';
    const senhaHash = await bcrypt.hash(defaultSenha, 10);
    try {
      await client.query(
        'INSERT INTO usuarios (cliente_id, nome, usuario, senha, senha_exibicao) VALUES ($1, $2, $3, $4, $5)',
        [cliente.id, 'PORTARIA ' + empresa.toUpperCase(), userLogin.toLowerCase(), senhaHash, defaultSenha]
      );
    } catch (e) {
      console.log('Aviso: não criou usuário portaria:', e.message);
    }
    await client.query('COMMIT');
    res.status(201).json({ ...cliente, portaria_usuario: userLogin.toLowerCase(), portaria_senha: defaultSenha });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Erro ao criar cliente:', err);
    res.status(500).json({ erro: 'Erro ao criar cliente: ' + err.message });
  } finally {
    client.release();
  }
});

app.put('/api/admin/clientes/:id', adminMiddleware, async (req, res) => {
  try {
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
    res.json({ mensagem: 'Cliente atualizado' });
  } catch (err) {
    console.error('Erro ao atualizar cliente:', err);
    res.status(500).json({ erro: 'Erro ao atualizar cliente' });
  }
});

app.delete('/api/admin/clientes/:id', adminMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM clientes WHERE id = $1', [req.params.id]);
    res.json({ mensagem: 'Cliente excluído' });
  } catch (err) {
    console.error('Erro ao excluir cliente:', err);
    res.status(500).json({ erro: 'Erro ao excluir cliente' });
  }
});

app.get('/api/admin/clientes/:id/usuarios', adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nome, usuario, senha_exibicao, ativo FROM usuarios WHERE cliente_id = $1 ORDER BY nome', [req.params.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar usuários' });
  }
});

app.post('/api/admin/clientes/:id/usuarios', adminMiddleware, async (req, res) => {
  try {
    const { usuario, senha, nome } = req.body;
    const cliente_id = req.params.id;
    const cliRes = await pool.query('SELECT empresa FROM clientes WHERE id = $1', [cliente_id]);
    if (cliRes.rows.length === 0) return res.status(404).json({ erro: 'Cliente não encontrado' });
    const u = usuario || (cliRes.rows[0].empresa.toUpperCase().replace(/[^A-Z0-9]/g, '').substring(0, 20) + '_portaria');
    const s = senha || 'portaria123';
    const n = nome || 'PORTARIA ' + cliRes.rows[0].empresa.toUpperCase();
    const senhaHash = await bcrypt.hash(s, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (cliente_id, nome, usuario, senha, senha_exibicao) VALUES ($1, $2, $3, $4, $5) RETURNING id, nome, usuario, senha_exibicao',
      [cliente_id, n, u.toLowerCase(), senhaHash, s]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'Usuário já existe' });
    res.status(500).json({ erro: 'Erro ao criar usuário: ' + err.message });
  }
});

app.get('/api/admin/dashboard', adminMiddleware, async (req, res) => {
  try {
    const clientes = await pool.query('SELECT COUNT(*)::int AS total FROM clientes');
    const ativos = await pool.query("SELECT COUNT(*)::int AS total FROM clientes WHERE ativo = TRUE");
    const expirados = await pool.query("SELECT COUNT(*)::int AS total FROM clientes WHERE data_expiracao < CURRENT_DATE AND ativo = TRUE");
    const receita = await pool.query("SELECT COALESCE(SUM(valor_mensal), 0)::float AS total FROM clientes WHERE ativo = TRUE");
    const faturamento = await pool.query("SELECT COALESCE(SUM(valor), 0)::float AS total FROM faturamento");
    const recentes = await pool.query("SELECT * FROM faturamento ORDER BY data_pagamento DESC LIMIT 10");
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

app.post('/api/admin/faturamento', adminMiddleware, async (req, res) => {
  try {
    const { cliente_id, valor, descricao, data_pagamento } = req.body;
    if (!cliente_id || !valor) return res.status(400).json({ erro: 'Cliente e valor são obrigatórios' });
    const result = await pool.query(
      'INSERT INTO faturamento (cliente_id, valor, descricao, data_pagamento) VALUES ($1, $2, $3, $4) RETURNING *',
      [cliente_id, valor, descricao||'', data_pagamento||new Date().toISOString().substring(0,10)]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao registrar faturamento:', err);
    res.status(500).json({ erro: 'Erro ao registrar faturamento' });
  }
});

app.get('/api/admin/faturamento', adminMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT f.*, c.empresa FROM faturamento f 
       LEFT JOIN clientes c ON f.cliente_id = c.id 
       ORDER BY f.data_pagamento DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar faturamento:', err);
    res.status(500).json({ erro: 'Erro ao buscar faturamento' });
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

async function iniciar() {
  try {
    await pool.query('SELECT 1');
    console.log('Conectado ao PostgreSQL');
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
      "ALTER TABLE clientes ADD COLUMN IF NOT EXISTS telefone_fixo VARCHAR(20) DEFAULT ''"
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
        'INSERT INTO admin_users (nome, usuario, senha) VALUES ($1, $2, $3)',
        ['SUPER ADMIN', 'superadmin', senhaSuper]
      );
      console.log('Admin padrão criado (superadmin/admin123)');
    }
  } catch (err) {
    console.error('Erro ao conectar ao PostgreSQL:', err.message);
    console.log('Iniciando servidor mesmo sem banco...');
  }
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
  });
}

iniciar();
