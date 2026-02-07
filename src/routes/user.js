const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { canDelete, verificarToken } = require('../middlewares/auth');

// Rutas de consulta (Protegidas para que solo usuarios logueados vean la lista)
router.get('/', verificarToken, userController.getUsers);
router.get('/all', userController.getUsers);
router.get('/:id', verificarToken, userController.getUserById);

// Rutas de Auth
router.post('/login', userController.login);
// Si quieres que cualquiera se registre, déjala sin verificarToken. 
// Si solo Admins crean usuarios, agrégalo.
router.post('/register', userController.register); 
router.post('/admin-create', userController.createUserAdmin); 

// RUTA PARA EDITAR (Aquí estaba el error)
// Agregamos verificarToken para que req.user exista en el controlador
router.put('/:id', verificarToken, userController.updateUser);

// Ruta de borrado
router.delete('/:id', verificarToken, canDelete, userController.deleteUser);

module.exports = router;