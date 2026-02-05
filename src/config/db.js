const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false, 
    dialectOptions: {
        ssl: {
            require: true,
            rejectUnauthorized: false 
        }
    }
});

const conectarDB = async () => {
    try {
        await sequelize.authenticate();
        
        // Importamos el modelo
        require('../models/User'); 
        
        // Agregamos 'await' para que realmente termine de sincronizar antes de avisar
        await sequelize.sync(); 
        
        console.log('✅ Conexión a PostgreSQL y tablas sincronizadas');
    } catch (error) {
        console.error('❌ Error en conexión Postgres:', error);
    }
};

module.exports = { sequelize, conectarDB };