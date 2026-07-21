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
    { id: usuario.id, usuario: usuario.usuario, nome: usuario.nome },
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

app.post('/api/login', async (req, res) => {
  try {
    const { usuario, senha } = req.body;
    if (!usuario || !senha) {
      return res.status(400).json({ erro: 'Usuário e senha são obrigatórios' });
    }
    const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1 AND ativo = TRUE', [usuario.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    }
    const user = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, user.senha);
    if (!senhaValida) {
      return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    }
    const token = gerarToken(user);
    res.json({ token, usuario: { nome: user.nome, usuario: user.usuario } });
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
      'SELECT * FROM registros WHERE data_registro = CURRENT_DATE ORDER BY id ASC'
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
      'SELECT * FROM registros ORDER BY data_registro DESC, id DESC LIMIT 500'
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
    if (!placa || !empresa) {
      return res.status(400).json({ erro: 'Placa e Empresa são obrigatórios' });
    }
    const hora = clientHora || new Date().toLocaleTimeString('pt-BR');
    const result = await pool.query(
      `INSERT INTO registros (usuario_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, nota, obs)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [req.usuario.id, hora, placa.toUpperCase(), modelo||'', finalidade||'', empresa, motorista||'', cnh||'', hora, nota||'', obs||'']
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
      'UPDATE registros SET saida = $1 WHERE id = $2 AND saida = $3 RETURNING *',
      [hora, req.params.id, '']
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: 'Registro não encontrado ou já possui saída' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao marcar saída:', err);
    res.status(500).json({ erro: 'Erro ao marcar saída' });
  }
});

app.delete('/api/registros/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM registros WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: 'Registro não encontrado' });
    }
    res.json({ mensagem: 'Registro excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir registro:', err);
    res.status(500).json({ erro: 'Erro ao excluir registro' });
  }
});

app.get('/api/auto-preenchimento', authMiddleware, async (req, res) => {
  try {
    const { motorista, placa, empresa, cnh } = req.query;
    const params = [];
    const conds = [];
    if (motorista) { params.push(`%${motorista}%`); conds.push(`motorista ILIKE $${params.length}`); }
    if (placa) { params.push(`%${placa}%`); conds.push(`placa ILIKE $${params.length}`); }
    if (empresa) { params.push(`%${empresa}%`); conds.push(`empresa ILIKE $${params.length}`); }
    if (cnh) { const digits = cnh.replace(/[^0-9]/g, ''); if(digits) { params.push(`%${digits}%`); conds.push(`regexp_replace(cnh, '[^0-9]', '', 'g') ILIKE $${params.length}`); } }
    if (conds.length === 0) return res.json(null);
    const sql = `SELECT DISTINCT ON (COALESCE(NULLIF(motorista,''),placa)) motorista, placa, modelo, empresa, cnh, finalidade, entrada
                 FROM registros WHERE (${conds.join(' OR ')}) AND motorista != ''
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
       WHERE motorista != '' ORDER BY motorista ASC`
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
       WHERE empresa != '' ORDER BY empresa ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar empresas:', err);
    res.status(500).json({ erro: 'Erro ao listar empresas' });
  }
});

app.get('/api/empresas-lista-pre', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT empresa FROM registros
       WHERE empresa != '' ORDER BY empresa ASC`
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
      `SELECT DISTINCT nome, cpf, empresa, setor_visitado FROM visitantes
       WHERE nome != '' ORDER BY nome ASC`
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
    const params = [];
    const conds = [];
    if (nome) { params.push(`%${nome}%`); conds.push(`nome ILIKE $${params.length}`); }
    if (cpf) { const digits = cpf.replace(/[^0-9]/g, ''); if(digits) { params.push(`%${digits}%`); conds.push(`regexp_replace(cpf, '[^0-9]', '', 'g') ILIKE $${params.length}`); } }
    if (empresa) { params.push(`%${empresa}%`); conds.push(`empresa ILIKE $${params.length}`); }
    if (conds.length === 0) return res.json(null);
    const sql = `SELECT DISTINCT ON (COALESCE(NULLIF(nome,''),cpf)) nome, cpf, empresa, setor_visitado
                 FROM visitantes WHERE (${conds.join(' OR ')}) AND nome != ''
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
      FROM registros WHERE data_registro = CURRENT_DATE
    `);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao buscar resumo:', err);
    res.status(500).json({ erro: 'Erro ao buscar resumo' });
  }
});

app.get('/api/usuarios', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nome, usuario, ativo, criado_em FROM usuarios ORDER BY nome');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar usuários:', err);
    res.status(500).json({ erro: 'Erro ao buscar usuários' });
  }
});

app.post('/api/usuarios', authMiddleware, async (req, res) => {
  try {
    const { nome, usuario, senha } = req.body;
    if (!nome || !usuario || !senha) {
      return res.status(400).json({ erro: 'Nome, usuário e senha são obrigatórios' });
    }
    const senhaHash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nome, usuario, senha) VALUES ($1, $2, $3) RETURNING id, nome, usuario',
      [nome, usuario.toLowerCase(), senhaHash]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ erro: 'Usuário já existe' });
    }
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
      'SELECT * FROM visitantes WHERE data_registro = CURRENT_DATE ORDER BY id ASC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar visitantes:', err);
    res.status(500).json({ erro: 'Erro ao buscar visitantes' });
  }
});

app.post('/api/visitantes', authMiddleware, async (req, res) => {
  try {
    const { nome, cpf, empresa, setor_visitado, hora: clientHora } = req.body;
    if (!nome) {
      return res.status(400).json({ erro: 'Nome é obrigatório' });
    }
    const hora = clientHora || new Date().toLocaleTimeString('pt-BR');
    const result = await pool.query(
      `INSERT INTO visitantes (usuario_id, nome, cpf, empresa, setor_visitado, entrada)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [req.usuario.id, nome.toUpperCase(), cpf||'', empresa||'', setor_visitado||'', hora]
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
      'UPDATE visitantes SET saida = $1 WHERE id = $2 AND saida = $3 RETURNING *',
      [hora, req.params.id, '']
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: 'Visitante não encontrado ou já possui saída' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao marcar saída:', err);
    res.status(500).json({ erro: 'Erro ao marcar saída' });
  }
});

app.delete('/api/visitantes/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM visitantes WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ erro: 'Visitante não encontrado' });
    }
    res.json({ mensagem: 'Visitante excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir visitante:', err);
    res.status(500).json({ erro: 'Erro ao excluir visitante' });
  }
});

app.post('/api/pre-registro', async (req, res) => {
  try {
    const { empresa, motorista, cnh, placa, modelo, finalidade, obs } = req.body;
    if (!empresa || !motorista || !placa) {
      return res.status(400).json({ erro: 'Empresa, motorista e placa são obrigatórios' });
    }
    const result = await pool.query(
      `INSERT INTO pre_registros (empresa, motorista, cnh, placa, modelo, finalidade, obs)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [empresa.toUpperCase(), motorista.toUpperCase(), cnh||'', placa.toUpperCase(), modelo||'', finalidade||'', obs||'']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro no pre-registro:', err);
    res.status(500).json({ erro: 'Erro ao realizar pré-registro' });
  }
});

app.get('/api/pre-registros', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM pre_registros ORDER BY id ASC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar pre-registros:', err);
    res.status(500).json({ erro: 'Erro ao buscar pré-registros' });
  }
});

app.post('/api/pre-registros/:id/confirmar', authMiddleware, async (req, res) => {
  try {
    const pre = await pool.query('SELECT * FROM pre_registros WHERE id = $1', [req.params.id]);
    if (pre.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    const d = pre.rows[0];
    const hora = new Date().toLocaleTimeString('pt-BR');
    const hoje = new Date().toLocaleDateString('en-CA');
    const pos = await pool.query(
      `SELECT COALESCE(MAX(posicao), 0) + 1 AS prox FROM registros WHERE data_registro = $1`,
      [hoje]
    );
    const posicao = pos.rows[0].prox;
    const registro = await pool.query(
      `INSERT INTO registros (usuario_id, chegada, placa, modelo, finalidade, empresa, motorista, cnh, entrada, nota, obs, data_registro, posicao)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [req.usuario.id, hora, d.placa, d.modelo, d.finalidade, d.empresa, d.motorista, d.cnh, hora, '', d.obs, hoje, posicao]
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
    const result = await pool.query('DELETE FROM pre_registros WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ erro: 'Pré-registro não encontrado' });
    res.json({ mensagem: 'Pré-registro excluído' });
  } catch (err) {
    console.error('Erro ao excluir pre-registro:', err);
    res.status(500).json({ erro: 'Erro ao excluir pré-registro' });
  }
});

app.get('/api/setup', async (req, res) => {
  try {
    const fs = require('fs');
    const sql = fs.readFileSync('./schema.sql', 'utf8');
    const statements = sql.split(';').map(s => s.trim()).filter(s => s.length > 0);
    for (const stmt of statements) {
      try { await pool.query(stmt); } catch(e) { console.log('Aviso setup:', e.message); }
    }
    const userCount = await pool.query('SELECT COUNT(*)::int AS total FROM usuarios');
    if (userCount.rows[0].total === 0) {
      const senhaPortaria = await bcrypt.hash('portaria123', 10);
      const senhaAdmin = await bcrypt.hash('admin123', 10);
      await pool.query(
        'INSERT INTO usuarios (nome, usuario, senha) VALUES ($1, $2, $3), ($4, $5, $6)',
        ['PORTARIA', 'portaria', senhaPortaria, 'ADMIN', 'admin', senhaAdmin]
      );
    }
    const users = await pool.query('SELECT id, nome, usuario, ativo FROM usuarios');
    res.json({ mensagem: 'OK', usuarios: users.rows });
  } catch (err) {
    console.error('Erro ao executar schema:', err);
    res.status(500).json({ erro: 'Erro ao inicializar banco: ' + err.message });
  }
});

app.get('/api/check-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, nome, usuario, ativo FROM usuarios');
    const tables = await pool.query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`);
    res.json({ usuarios: result.rows, tabelas: tables.rows.map(t => t.tablename) });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
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
    const userCount = await pool.query('SELECT COUNT(*)::int AS total FROM usuarios');
    if (userCount.rows[0].total === 0) {
      const senhaPortaria = await bcrypt.hash('portaria123', 10);
      const senhaAdmin = await bcrypt.hash('admin123', 10);
      await pool.query(
        'INSERT INTO usuarios (nome, usuario, senha) VALUES ($1, $2, $3), ($4, $5, $6)',
        ['PORTARIA', 'portaria', senhaPortaria, 'ADMIN', 'admin', senhaAdmin]
      );
      console.log('Usuários padrão criados (portaria/portaria123, admin/admin123)');
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
