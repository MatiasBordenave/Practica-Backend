const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: false // Necesario para conectar a Render desde afuera
        }
    }
});

const conectarDB = async () => {
    try {
        await sequelize.authenticate();
        
        // Importamos el modelo aquí para que Sequelize lo registre
        require('../models/User'); 
        
        await sequelize.sync({ alter: true }); 
        console.log('✅ Conexión a PostgreSQL y tablas sincronizadas');
    } catch (error) {
        console.error('❌ Error en conexión Postgres:', error);
    }
};

module.exports = { sequelize, conectarDB };