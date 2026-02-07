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
// REGLA: Esta la usa cualquier persona desde la Web
exports.register = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Aquí NO pedimos req.user porque es público
        // Forzamos el rol a 'usuario' por seguridad
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            username: username.trim(),
            email: email.trim(),
            password: hashedPassword,
            role: 'usuario', // Siempre usuario
            status: 'active'
        });

        res.status(201).json({ message: "¡Registro exitoso!", user: { id: newUser.id, username: newUser.username } });
    } catch (error) {
        res.status(400).json({ message: "Error al registrarse", error: error.message });
    }
};

// REGLA: Esta la usa solo el Admin desde el Dashboard
exports.createUserAdmin = async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        const operadorRole = req.user.role; // Viene del verificarToken

        // Validación de seguridad: Solo Admin o Superadmin entran aquí
        if (operadorRole !== 'admin' && operadorRole !== 'superadmin') {
            return res.status(403).json({ message: "No tienes permiso para crear usuarios" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            username: username.trim(),
            email: email.trim(),
            password: hashedPassword,
            role: role || 'usuario', // El admin elige el rol
            status: 'active'
        });

        res.status(201).json({ message: "Usuario creado por administrador", user: newUser });
    } catch (error) {
        res.status(400).json({ message: "Error en la creación administrativa", error: error.message });
    }
};

// 3. Modificar usuario
exports.updateUser = async (req, res) => {
    try {
        const { id } = req.params;
        const { username, email, password, role, status } = req.body;
        
        // El 'operador' es quien hace la petición (datos del JWT)
        const operadorRole = req.user.role; 
        const operadorId = req.user.id;

        // 1. Buscar al usuario que se quiere modificar (el 'objetivo')
        const userObjetivo = await User.findByPk(id);
        if (!userObjetivo) return res.status(404).json({ message: "No existe el usuario" });

        // --- INICIO DE RESTRICCIONES DE SEGURIDAD ---

        // A. Un usuario común no puede editar a nadie (excepto quizás a sí mismo, pero aquí bloqueamos todo)
        if (operadorRole === 'usuario' && operadorId !== parseInt(id)) {
            return res.status(403).json({ message: "No tienes permisos para editar otros usuarios" });
        }

        // B. Protección de Superadmin: Nadie toca a un Superadmin excepto otro Superadmin
        if (userObjetivo.role === 'superadmin' && operadorRole !== 'superadmin') {
            return res.status(403).json({ message: "Nivel insuficiente para modificar a un Superadmin" });
        }

        // C. Restricción de Admin: Un Admin solo puede editar 'usuarios' (no a otros Admins ni Superadmins)
        if (operadorRole === 'admin' && userObjetivo.role !== 'usuario' && operadorId !== parseInt(id)) {
            return res.status(403).json({ message: "Como Admin, solo puedes editar usuarios finales" });
        }

        // D. Evitar escalada de poder: Un Admin no puede convertir a alguien en Superadmin
        if (role === 'superadmin' && operadorRole !== 'superadmin') {
            return res.status(403).json({ message: "Solo un Superadmin puede asignar ese rango" });
        }

        // E. Prevención de "Suicidio" de cuenta: No permitir borrado lógico de uno mismo
        if (operadorId === parseInt(id) && status === 'deleted') {
            return res.status(400).json({ message: "No puedes eliminar tu propia cuenta desde aquí" });
        }

        // --- FIN DE RESTRICCIONES ---

        // 2. Preparar campos a actualizar
        let camposAActualizar = {};
        if (username) camposAActualizar.username = username;
        if (email) camposAActualizar.email = email;
        if (role) camposAActualizar.role = role;
        if (status) camposAActualizar.status = status;

        // 3. Encriptar password si viene en el body
        if (password) {
            const salt = await bcrypt.genSalt(10);
            camposAActualizar.password = await bcrypt.hash(password, salt);
        }

        // 4. Ejecutar actualización
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