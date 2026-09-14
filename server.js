require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const verificarToken = require('./middleware/auth');

const app = express();
app.use(express.json());

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
});

app.get('/', (req, res) => {
  res.send('API do Orbit está funcionando!');
});

app.get('/testar-banco', async (req, res) => {
  try {
    const resultado = await pool.query('SELECT NOW()');
    res.json({ conectado: true, horario_banco: resultado.rows[0].now });
  } catch (erro) {
    res.status(500).json({ conectado: false, erro: erro.message });
  }
});

// Rota de cadastro de usuário
app.post('/cadastro', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ erro: 'Nome, email e senha são obrigatórios' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const resultado = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, created_at',
      [name, email, password_hash]
    );

    res.status(201).json(resultado.rows[0]);
  } catch (erro) {
    if (erro.code === '23505') {
      return res.status(409).json({ erro: 'Esse email já está cadastrado' });
    }
    res.status(500).json({ erro: erro.message });
  }
});

// Rota de login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ erro: 'Email e senha são obrigatórios' });
  }

  try {
    const resultado = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const usuario = resultado.rows[0];

    if (!usuario) {
      return res.status(401).json({ erro: 'Email ou senha incorretos' });
    }

    const senhaCorreta = await bcrypt.compare(password, usuario.password_hash);
    if (!senhaCorreta) {
      return res.status(401).json({ erro: 'Email ou senha incorretos' });
    }

    const accessToken = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: usuario.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      accessToken,
      refreshToken,
      usuario: { id: usuario.id, name: usuario.name, email: usuario.email },
    });
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

// Gerar um novo access token usando o refresh token
app.post('/refresh-token', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ erro: 'Refresh token é obrigatório' });
  }

  try {
    // Confere se o refresh token é válido (assinado com o segredo certo, não expirado)
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Gera um novo access token pro mesmo usuário
    const novoAccessToken = jwt.sign(
      { id: payload.id },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ accessToken: novoAccessToken });
  } catch (erro) {
    return res.status(401).json({ erro: 'Refresh token inválido ou expirado' });
  }
});

// Criar um post (rota protegida)
app.post('/posts', verificarToken, async (req, res) => {
  const { content } = req.body;
  const userId = req.usuario.id;

  if (!content) {
    return res.status(400).json({ erro: 'O conteúdo do post é obrigatório' });
  }

  try {
    const resultado = await pool.query(
      'INSERT INTO posts (user_id, content) VALUES ($1, $2) RETURNING *',
      [userId, content]
    );
    res.status(201).json(resultado.rows[0]);
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

// Listar todos os posts (rota pública)
app.get('/posts', async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT posts.id, posts.content, posts.created_at, users.id AS user_id, users.name AS autor
       FROM posts
       JOIN users ON posts.user_id = users.id
       ORDER BY posts.created_at DESC`
    );
    res.json(resultado.rows);
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

// Editar um post (rota protegida, só o dono pode)
app.put('/posts/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  const userId = req.usuario.id;

  if (!content) {
    return res.status(400).json({ erro: 'O conteúdo do post é obrigatório' });
  }

  try {
    const resultado = await pool.query(
      'UPDATE posts SET content = $1 WHERE id = $2 AND user_id = $3 RETURNING *',
      [content, id, userId]
    );

    if (resultado.rows.length === 0) {
      return res.status(403).json({ erro: 'Post não encontrado ou você não é o dono' });
    }

    res.json(resultado.rows[0]);
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

// Apagar um post (rota protegida, só o dono pode)
app.delete('/posts/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.usuario.id;

  try {
    const resultado = await pool.query(
      'DELETE FROM posts WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, userId]
    );

    if (resultado.rows.length === 0) {
      return res.status(403).json({ erro: 'Post não encontrado ou você não é o dono' });
    }

    res.json({ mensagem: 'Post apagado com sucesso' });
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

// Curtir um post (rota protegida)
app.post('/posts/:id/like', verificarToken, async (req, res) => {
  const { id: postId } = req.params;
  const userId = req.usuario.id;

  try {
    const resultado = await pool.query(
      'INSERT INTO likes (user_id, post_id) VALUES ($1, $2) RETURNING *',
      [userId, postId]
    );
    res.status(201).json(resultado.rows[0]);
  } catch (erro) {
    if (erro.code === '23505') {
      return res.status(409).json({ erro: 'Você já curtiu esse post' });
    }
    if (erro.code === '23503') {
      return res.status(404).json({ erro: 'Post não encontrado' });
    }
    res.status(500).json({ erro: erro.message });
  }
});

// Descurtir um post (rota protegida)
app.delete('/posts/:id/like', verificarToken, async (req, res) => {
  const { id: postId } = req.params;
  const userId = req.usuario.id;

  try {
    const resultado = await pool.query(
      'DELETE FROM likes WHERE user_id = $1 AND post_id = $2 RETURNING *',
      [userId, postId]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: 'Você ainda não tinha curtido esse post' });
    }

    res.json({ mensagem: 'Curtida removida' });
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

// Comentar em um post (rota protegida)
app.post('/posts/:id/comments', verificarToken, async (req, res) => {
  const { id: postId } = req.params;
  const { content } = req.body;
  const userId = req.usuario.id;

  if (!content) {
    return res.status(400).json({ erro: 'O conteúdo do comentário é obrigatório' });
  }

  try {
    const resultado = await pool.query(
      'INSERT INTO comments (user_id, post_id, content) VALUES ($1, $2, $3) RETURNING *',
      [userId, postId, content]
    );
    res.status(201).json(resultado.rows[0]);
  } catch (erro) {
    if (erro.code === '23503') {
      return res.status(404).json({ erro: 'Post não encontrado' });
    }
    res.status(500).json({ erro: erro.message });
  }
});

// Listar comentários de um post (rota pública)
app.get('/posts/:id/comments', async (req, res) => {
  const { id: postId } = req.params;

  try {
    const resultado = await pool.query(
      `SELECT comments.id, comments.content, comments.created_at, users.id AS user_id, users.name AS autor
       FROM comments
       JOIN users ON comments.user_id = users.id
       WHERE comments.post_id = $1
       ORDER BY comments.created_at ASC`,
      [postId]
    );
    res.json(resultado.rows);
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

// Apagar um comentário (rota protegida, só o dono pode)
app.delete('/comments/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.usuario.id;

  try {
    const resultado = await pool.query(
      'DELETE FROM comments WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, userId]
    );

    if (resultado.rows.length === 0) {
      return res.status(403).json({ erro: 'Comentário não encontrado ou você não é o dono' });
    }

    res.json({ mensagem: 'Comentário apagado com sucesso' });
  } catch (erro) {
    res.status(500).json({ erro: erro.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});