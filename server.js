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
    const hora = new Date().toLocaleTimeString('pt-BR');
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

app.get('/api/motoristas', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM motoristas ORDER BY motorista ASC');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar motoristas:', err);
    res.status(500).json({ erro: 'Erro ao buscar motoristas' });
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

app.get('/api/setup', async (req, res) => {
  try {
    const fs = require('fs');
    const sql = fs.readFileSync('./schema.sql', 'utf8');
    await pool.query(sql);
    res.json({ mensagem: 'Banco de dados inicializado com sucesso' });
  } catch (err) {
    console.error('Erro ao executar schema:', err);
    res.status(500).json({ erro: 'Erro ao inicializar banco de dados' });
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
      await pool.query(sql);
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
