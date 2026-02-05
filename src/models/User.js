const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const User = sequelize.define('User', {
    username: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        unique: true 
    },
    email: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        unique: true,
        validate: { isEmail: true }
    },
    password: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    role: { 
        type: DataTypes.ENUM('superadmin', 'admin', 'usuario'), 
        defaultValue: 'usuario' 
    },
    // --- NUEVOS CAMPOS ---
    status: {
        type: DataTypes.ENUM('active', 'inactive', 'deleted'),
        defaultValue: 'active'
    },
    lastLogin: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW // Se inicializa con la fecha de creación
    }
}, {
    timestamps: true
});

module.exports = User;