const express = require('express');
const app = express();
const PORT = 3000;

// Middleware para entender JSON
app.use(express.json());

// Ruta de prueba (Endpoint)
app.get('/', (req, res) => {
  res.send('¡Hola! Tu servidor Node/Express está vivo 🚀');
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});