const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { Op } = require('sequelize');
const jwt = require('jsonwebtoken');

exports.getUsers = async (req, res) => {
    const users = await User.findAll();
    
    const usersWithActivity = users.map(user => {
        const userData = user.toJSON();
        const diasInactivo = (new Date() - new Date(userData.lastLogin)) / (1000 * 60 * 60 * 24);
        
        if (diasInactivo > 7 && userData.status === 'active') {
            userData.status = 'inactive';
        }
        
        return userData;
    });

    res.json(usersWithActivity);
};

exports.getUserById = async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id, { 
            attributes: { exclude: ['password'] } 
        });
        if (!user) return res.status(404).json({ message: "Usuario no encontrado" });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: "Error al buscar usuario" });
    }
};

exports.register = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            username: username.trim(),
            email: email.trim(),
            password: hashedPassword,
            role: 'usuario',
            status: 'active'
        });

        res.status(201).json({ message: "¡Registro exitoso!", user: { id: newUser.id, username: newUser.username } });
    } catch (error) {
        res.status(400).json({ message: "Error al registrarse", error: error.message });
    }
};

exports.createUserAdmin = async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        const operadorRole = req.user.role;

        if (operadorRole !== 'admin' && operadorRole !== 'superadmin') {
            return res.status(403).json({ message: "No tienes permiso para crear usuarios" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            username: username.trim(),
            email: email.trim(),
            password: hashedPassword,
            role: role || 'usuario', 
            status: 'active'
        });

        res.status(201).json({ message: "Usuario creado por administrador", user: newUser });
    } catch (error) {
        res.status(400).json({ message: "Error en la creación administrativa", error: error.message });
    }
};

exports.updateUser = async (req, res) => {
    try {
        const { id } = req.params;
        const { username, email, password, role, status } = req.body;
        
        const operadorRole = req.user.role; 
        const operadorId = req.user.id;

        const userObjetivo = await User.findByPk(id);
        if (!userObjetivo) return res.status(404).json({ message: "No existe el usuario" });

        // --- VALIDACIONES DE AUTORIZACIÓN ---

        // 1. Un 'usuario' solo puede editarse a sí mismo
        if (operadorRole === 'usuario' && operadorId !== parseInt(id)) {
            return res.status(403).json({ message: "No puedes editar a otros usuarios" });
        }

        // 2. Un 'admin' no puede tocar a un 'superadmin' (aunque sea él mismo, si fuera el caso)
        if (userObjetivo.role === 'superadmin' && operadorRole !== 'superadmin') {
            return res.status(403).json({ message: "No puedes modificar a un Superadmin" });
        }

        // 3. Un 'admin' solo puede editar a 'usuarios' comunes o a sí mismo
        if (operadorRole === 'admin' && userObjetivo.role === 'admin' && operadorId !== parseInt(id)) {
            return res.status(403).json({ message: "Un Admin no puede editar a otros Admins" });
        }

        // 4. Protección de Rango: Nadie (excepto superadmin) puede asignar el rol 'superadmin'
        if (role === 'superadmin' && operadorRole !== 'superadmin') {
            return res.status(403).json({ message: "No tienes permiso para asignar el rango Superadmin" });
        }

        // 5. Protección de Rango: Un Admin no puede promoverse a sí mismo o a otros a Admin si no lo es (opcional)
        if (role === 'admin' && operadorRole === 'usuario') {
            return res.status(403).json({ message: "No puedes cambiar tu propio rol" });
        }

        // --- CONSTRUCCIÓN DEL OBJETO DE ACTUALIZACIÓN ---
        let camposAActualizar = {};
        if (username) camposAActualizar.username = username;
        if (email)    camposAActualizar.email = email;
        if (status)   camposAActualizar.status = status;
        
        // El rol solo se actualiza si el operador tiene permiso (ya validado arriba)
        if (role) camposAActualizar.role = role;

        if (password) {
            const salt = await bcrypt.genSalt(10);
            camposAActualizar.password = await bcrypt.hash(password, salt);
        }

        await userObjetivo.update(camposAActualizar);
        
        res.json({ 
            message: "Usuario actualizado correctamente",
            user: { id: userObjetivo.id, username: userObjetivo.username, role: userObjetivo.role }
        });

    } catch (error) {
        res.status(400).json({ message: "Error al actualizar", error: error.message });
    }
};

exports.login = async (req, res) => {
    try {
        const { identifier, password } = req.body; 

        const user = await User.findOne({ 
            where: {
                [Op.or]: [
                    { username: identifier },
                    { email: identifier }
                ],
                status: { [Op.ne]: 'deleted' } 
            } 
        });
        
        if (!user) return res.status(404).json({ message: "Usuario no encontrado o cuenta eliminada" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Contraseña incorrecta" });

        user.lastLogin = new Date();
        user.status = 'active'; 
        await user.save();

        const token = jwt.sign(
            { id: user.id, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '2h' }
        );

        res.json({ 
            token, 
            user: { 
                username: user.username, 
                email: user.email, 
                role: user.role,
                status: user.status,
                lastLogin: user.lastLogin 
            } 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error en el login" });
    }
};


exports.deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const operadorRole = req.user.role;
        const operadorId = req.user.id;

        const user = await User.findByPk(id);
        if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

        // Impedir que se borre a sí mismo
        if (operadorId === parseInt(id)) {
            return res.status(400).json({ message: "No puedes eliminar tu propia cuenta" });
        }

        const esSuperadmin = operadorRole === 'superadmin';
        const esAdminBorrandoUsuario = (operadorRole === 'admin' && user.role === 'usuario');

        if (!esSuperadmin && !esAdminBorrandoUsuario) {
            return res.status(403).json({ message: "No tienes permisos para eliminar este usuario" });
        }

        user.status = 'deleted';
        await user.save();

        res.json({ message: "Usuario marcado como eliminado con éxito" });
    } catch (error) {
        console.error("Error al borrar:", error);
        res.status(500).json({ message: "Error al eliminar" });
    }
};