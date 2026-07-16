const { verifyToken } = require('./auth');

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'No autorizado. Falta el token de acceso.' });
  }
  try {
    req.user = verifyToken(token);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalido o vencido. Inicia sesion de nuevo.' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'No tienes permiso para esta accion (se requiere rol: ' + role + ').' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };
