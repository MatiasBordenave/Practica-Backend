const checkRole = (rolesPermitidos) => {
    return (req, res, next) => {
        const userRole = req.user.role; // Asumiendo que ya tienes el usuario en el req

        if (rolesPermitidos.includes(userRole)) {
            next();
        } else {
            return res.status(403).json({ message: "No tienes permisos para esta acción" });
        }
    };
};

// Lógica específica para borrado según tus reglas
const canDelete = async (req, res, next) => {
    const userRole = req.user.role;
    const { id } = req.params;
    const User = require('../models/User');

    const userToDelete = await User.findByPk(id);
    if (!userToDelete) return res.status(404).json({ message: "Usuario no encontrado" });

    // Regla: Superadmin borra Admin y Usuario
    if (userRole === 'superadmin' && (userToDelete.role === 'admin' || userToDelete.role === 'usuario')) {
        return next();
    }

    // Regla: Admin solo borra Usuario
    if (userRole === 'admin' && userToDelete.role === 'usuario') {
        return next();
    }

    return res.status(403).json({ message: "No tienes jerarquía suficiente para borrar este usuario" });
};

const jwt = require('jsonwebtoken');

const verificarToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1]; // Formato: Bearer TOKEN
    if (!token) return res.status(401).json({ message: "Acceso denegado, falta token" });

    try {
        const verificado = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verificado; // Guardamos los datos del usuario logueado
        next();
    } catch (error) {
        res.status(400).json({ message: "Token no válido" });
    }
};

module.exports = { checkRole, canDelete, verificarToken };