const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { Op } = require('sequelize');
const jwt = require('jsonwebtoken');

// 1. Mostrar todos los usuarios
// En tu ruta de obtener usuarios para el Dashboard
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

// 2. Agregar un usuario
exports.createUser = async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        
        // Verificar si ya existe el username o email
        const existe = await User.findOne({ where: { username } });
        if (existe) return res.status(400).json({ message: "El nombre de usuario ya existe" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            username,
            email,
            password: hashedPassword,
            role
        });

        res.status(201).json({ message: "Usuario creado", id: newUser.id });
    } catch (error) {
        res.status(400).json({ message: "Error al crear", error: error.message });
    }
};

// 3. Modificar usuario
exports.updateUser = async (req, res) => {
    try {
        const { id } = req.params;
        // Agregamos 'status' a los datos recibidos del body
        const { username, email, password, role, status } = req.body;
        
        // 1. Buscar al usuario
        const user = await User.findByPk(id);
        if (!user) return res.status(404).json({ message: "No existe el usuario" });

        // 2. Crear un objeto solo con los campos que vienen en el body
        let camposAActualizar = {};
        if (username) camposAActualizar.username = username;
        if (email) camposAActualizar.email = email;
        if (role) camposAActualizar.role = role;
        
        // Manejo del status (active, inactive, deleted)
        if (status) camposAActualizar.status = status;

        // 3. Si mandan password, encriptarlo antes de guardar
        if (password) {
            const salt = await bcrypt.genSalt(10);
            camposAActualizar.password = await bcrypt.hash(password, salt);
        }

        // 4. Ejecutar la actualización
        // Con Sequelize, update() actualiza la instancia y guarda en la DB automáticamente
        await user.update(camposAActualizar);
        
        // 5. Respuesta profesional
        res.json({ 
            message: "Usuario actualizado correctamente",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                status: user.status,
                lastLogin: user.lastLogin // Enviamos esto para que el dashboard se refresque bien
            }
        });
    } catch (error) {
        console.error("Error al editar:", error);
        res.status(400).json({ message: "Error al actualizar", error: error.message });
    }
};

// 4. Borrar usuario
exports.deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findByPk(id);
        
        if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

        // Borrado lógico: cambiamos el status en lugar de eliminar
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

        // 1. Buscamos al usuario (que no esté borrado)
        const user = await User.findOne({ 
            where: {
                [Op.or]: [
                    { username: identifier },
                    { email: identifier }
                ],
                // IMPORTANTE: Evitamos que alguien loguee si su estado es 'deleted'
                status: { [Op.ne]: 'deleted' } 
            } 
        });
        
        if (!user) return res.status(404).json({ message: "Usuario no encontrado o cuenta eliminada" });

        // 2. Verificar contraseña
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Contraseña incorrecta" });

        // 3. ACTUALIZACIÓN: Registro de última conexión y reset de estado
        // Si el usuario estaba 'inactive', al loguear vuelve a estar 'active'
        user.lastLogin = new Date();
        user.status = 'active'; 
        await user.save();

        // 4. Crear el Token
        const token = jwt.sign(
            { id: user.id, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '24h' }
        );

        res.json({ 
            token, 
            user: { 
                username: user.username, 
                email: user.email, 
                role: user.role,
                status: user.status,
                lastLogin: user.lastLogin // Lo mandamos para el dashboard
            } 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error en el login" });
    }
};