const express = require('express');
const app = express();

const routes = [];

// Sobrescribimos app.METHOD para capturar rutas
['get', 'post', 'put', 'delete', 'patch', 'all', 'use'].forEach(method => {
  const original = app[method];
  app[method] = function (path) {
    routes.push({ method, path });
    return original.apply(this, arguments);
  }
});

// Requerir tu server.js (o archivo donde defines rutas)
require('./server.js');

console.log('Rutas registradas:');
routes.forEach(r => console.log(`${r.method.toUpperCase()} ${r.path}`));
