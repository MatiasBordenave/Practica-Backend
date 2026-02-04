const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { canDelete, verificarToken } = require('../middlewares/auth');

// Rutas básicas
router.get('/', userController.getUsers);
router.get('/:id', userController.getUserById);

router.post('/', userController.createUser);
router.post('/login', userController.login);

router.put('/:id', userController.updateUser);

// Ruta de borrado con tu regla especial de jerarquía
// El middleware 'canDelete' se ejecuta antes que el controlador
router.delete('/:id', verificarToken, canDelete, userController.deleteUser);

module.exports = router;