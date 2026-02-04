const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { Op } = require('sequelize');
const jwt = require('jsonwebtoken');

// 1. Mostrar todos los usuarios
exports.getUsers = async (req, res) => {
    try {
        const users = await User.findAll({ attributes: { exclude: ['password'] } });
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener usuarios" });
    }
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
        const { username, email, password, role } = req.body;
        
        // 1. Buscar al usuario
        const user = await User.findByPk(id);
        if (!user) return res.status(404).json({ message: "No existe el usuario" });

        // 2. Crear un objeto solo con los campos que vienen en el body
        let camposAActualizar = {};
        if (username) camposAActualizar.username = username;
        if (email) camposAActualizar.email = email;
        if (role) camposAActualizar.role = role;

        // 3. Si mandan password, encriptarlo antes de guardar
        if (password) {
            const salt = await bcrypt.genSalt(10);
            camposAActualizar.password = await bcrypt.hash(password, salt);
        }

        // 4. Ejecutar la actualización y FORZAR el guardado
        await user.update(camposAActualizar);
        
        // Opcional: Puedes usar await user.save() si quieres estar 100% seguro
        // pero update() debería bastar si los campos coinciden.

        res.json({ 
            message: "Usuario actualizado correctamente",
            datosActualizados: camposAActualizar // Esto te servirá para ver qué se mandó
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
        await User.destroy({ where: { id } });
        res.json({ message: "Usuario eliminado físicamente de la DB" });
    } catch (error) {
        res.status(500).json({ message: "Error al borrar" });
    }
};



exports.login = async (req, res) => {
    try {
        // Cambiamos el nombre de la variable de 'username' a 'identifier' 
        // para que quede más claro que puede ser cualquiera de las dos cosas.
        const { identifier, password } = req.body; 

        // 1. Buscar si existe el usuario por username O por email
        const user = await User.findOne({ 
            where: {
                [Op.or]: [
                    { username: identifier },
                    { email: identifier }
                ]
            } 
        });
        
        if (!user) return res.status(404).json({ message: "Usuario o Email no encontrado" });

        // 2. Verificar contraseña
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Contraseña incorrecta" });

        // 3. Crear el Token
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
                role: user.role 
            } 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error en el login" });
    }
};