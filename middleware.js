const { verifyToken } = require('./auth');
const { query } = require('./db');

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'No autorizado. Falta el token de acceso.' });
  }
  let decoded;
  try {
    decoded = verifyToken(token);
  } catch (err) {
    return res.status(401).json({ error: 'Token invalido o vencido. Inicia sesion de nuevo.' });
  }
  // Revisar que esta sesion siga siendo la activa (si alguien mas inicio sesion despues
  // con el mismo correo y contrasena, esta sesion vieja queda invalidada automaticamente).
  try {
    const result = await query('SELECT active_session_id, deleted_at FROM users WHERE id = $1', [decoded.id]);
    const dbUser = result.rows[0];
    if (!dbUser || !decoded.sid || dbUser.active_session_id !== decoded.sid) {
      return res.status(401).json({ error: 'Tu sesion se cerro porque se inicio sesion con esta cuenta desde otro dispositivo.', session_replaced: true });
    }
    // Si la cuenta fue suspendida DESPUES de que este token se emitio, cerramos la sesion de
    // inmediato en vez de dejar que siga funcionando hasta que el token expire solo (hasta 30 dias).
    if (dbUser.deleted_at) {
      return res.status(401).json({ error: 'Tu cuenta fue suspendida. Contacta a soporte si crees que esto es un error.', account_suspended: true });
    }
  } catch (err) {
    console.error('Error verificando la sesion activa:', err);
    return res.status(500).json({ error: 'No se pudo verificar la sesion.' });
  }
  req.user = decoded;
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'No tienes permiso para esta accion (se requiere rol: ' + role + ').' });
    }
    next();
  };
}

// Solo deja pasar si el correo de la sesion esta en la lista de administradores
// (variable de entorno ADMIN_EMAILS, separada por comas).
function requireAdmin(req, res, next) {
  const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
  if (!req.user || !adminEmails.includes((req.user.email || '').toLowerCase())) {
    return res.status(403).json({ error: 'No tienes permiso de administrador para esta accion.' });
  }
  next();
}

module.exports = { requireAuth, requireRole, requireAdmin };
