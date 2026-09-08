const jwt = require('jsonwebtoken');

function verificarToken(req, res, next) {
  // O token vem no cabeçalho Authorization, no formato: "Bearer eyJhbGci..."
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({ erro: 'Token não fornecido' });
  }

  // Separa a palavra "Bearer" do token em si
  const partes = authHeader.split(' ');
  if (partes.length !== 2 || partes[0] !== 'Bearer') {
    return res.status(401).json({ erro: 'Formato de token inválido' });
  }

  const token = partes[1];

  try {
    // Verifica se o token é válido e não expirou
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    // Anexa os dados do usuário na requisição, pra rotas seguintes usarem
    req.usuario = payload;

    next(); // deixa a requisição continuar pra rota de verdade
  } catch (erro) {
    return res.status(401).json({ erro: 'Token inválido ou expirado' });
  }
}

module.exports = verificarToken;