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

        if (operadorRole === 'usuario' && operadorId !== parseInt(id)) {
            return res.status(403).json({ message: "No tienes permisos para editar otros usuarios" });
        }

        if (userObjetivo.role === 'superadmin' && operadorRole !== 'superadmin') {
            return res.status(403).json({ message: "Nivel insuficiente para modificar a un Superadmin" });
        }

        if (operadorRole === 'admin' && userObjetivo.role !== 'usuario' && operadorId !== parseInt(id)) {
            return res.status(403).json({ message: "Como Admin, solo puedes editar usuarios finales" });
        }

        if (role === 'superadmin' && operadorRole !== 'superadmin') {
            return res.status(403).json({ message: "Solo un Superadmin puede asignar ese rango" });
        }
        if (operadorId === parseInt(id) && status === 'deleted') {
            return res.status(400).json({ message: "No puedes eliminar tu propia cuenta desde aquí" });
        }

        let camposAActualizar = {};
        if (username) camposAActualizar.username = username;
        if (email) camposAActualizar.email = email;
        if (role) camposAActualizar.role = role;
        if (status) camposAActualizar.status = status;

        if (password) {
            const salt = await bcrypt.genSalt(10);
            camposAActualizar.password = await bcrypt.hash(password, salt);
        }

        await userObjetivo.update(camposAActualizar);
        
        // 5. Respuesta
        res.json({ 
            message: "Usuario actualizado correctamente",
            user: {
                id: userObjetivo.id,
                username: userObjetivo.username,
                email: userObjetivo.email,
                role: userObjetivo.role,
                status: userObjetivo.status,
                lastLogin: userObjetivo.lastLogin
            }
        });
    } catch (error) {
        console.error("Error al editar:", error);
        res.status(400).json({ message: "Error al actualizar", error: error.message });
    }
};

exports.deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findByPk(id);
        
        if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

        user.status = 'deleted';
        await user.save();

        res.json({ message: "Usuario marcado como eliminado con éxito" });
    } catch (error) {
        res.status(500).json({ message: "Error al eliminar" });
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