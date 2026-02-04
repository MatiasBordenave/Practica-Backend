require('dotenv').config();
const express = require('express');
const { conectarDB } = require('./src/config/db');
const cors = require('cors');

const app = express();

// --- ESTO ES LO QUE FALTA ---
app.use(express.json()); // Permite que tu API entienda JSON
app.use(express.urlencoded({ extended: true })); 
app.use(cors());

// Rutas
app.use("/api/users", require('./src/routes/user'));

app.get("/", (req, res) => {
    res.send("¡API funcionando con PostgreSQL en Render!");
});

// Conectar DB y Arrancar Servidor
const PORT = process.env.PORT || 8000;

conectarDB().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 Escuchando en el puerto ${PORT}`);
    });
});