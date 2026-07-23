const { verifyToken } = require('./auth');
const { query } = require('./db');

// Modo mantenimiento: mientras este activo, solo las cuentas con role='admin' pueden seguir
// usando rutas que requieren sesion. Se guarda en la tabla platform_settings (backend-index.js
// tiene su propia copia de este helper para sus propios endpoints publicos; esta copia es la
// que protege las rutas autenticadas).
async function isMaintenanceMode(){
  try {
    const result = await query(`SELECT value FROM platform_settings WHERE key = 'maintenance_mode'`);
    return !!result.rows[0] && result.rows[0].value === 'true';
  } catch (err) {
    console.error('No se pudo leer el interruptor de mantenimiento:', err);
    return false;
  }
}

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
    // Modo mantenimiento: si esta activo y esta persona no es admin (por rol real, no por
    // correo), se bloquea el acceso a cualquier ruta autenticada, sin cerrarle la sesion.
    if (decoded.role !== 'admin' && await isMaintenanceMode()) {
      return res.status(503).json({ error: 'La plataforma esta en mantenimiento en este momento. Vuelve a intentarlo en un rato.', maintenance_mode: true });
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

// Solo deja pasar si el rol de la sesion es 'admin' - un rol real en la base de datos, no una
// lista de correos comparados a mano. El rol ya viaja dentro del token (se firma en el login).
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No tienes permiso de administrador para esta accion.' });
  }
  next();
}

module.exports = { requireAuth, requireRole, requireAdmin };
