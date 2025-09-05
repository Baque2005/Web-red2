require('dotenv').config();
const express = require('express');
const app = express();
const { Pool } = require('pg');
const paypal = require('@paypal/checkout-server-sdk'); // SDK oficial

// Configuración PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL_PROD, // tu URL de Render/PostgreSQL
  ssl: { rejectUnauthorized: false },
});

// Configuración PayPal
const environment = new paypal.core.LiveEnvironment(
  process.env.PAYPAL_CLIENT_ID,
  process.env.PAYPAL_CLIENT_SECRET
);
const client = new paypal.core.PayPalHttpClient(environment);
const WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID; // ID del webhook creado en PayPal

// Middleware para JSON
app.use(express.json({ type: 'application/json' }));

// Endpoint de webhook
app.post('/api/paypal/webhook', async (req, res) => {
  const event = req.body;

  try {
    // 1️⃣ Validación de la firma del webhook
    const verifyReq = new paypal.notifications.WebhookEventVerifySignatureRequest();
    verifyReq.requestBody({
      auth_algo: req.headers['paypal-auth-algo'],
      cert_url: req.headers['paypal-cert-url'],
      transmission_id: req.headers['paypal-transmission-id'],
      transmission_sig: req.headers['paypal-transmission-sig'],
      transmission_time: req.headers['paypal-transmission-time'],
      webhook_id: WEBHOOK_ID,
      webhook_event: event,
    });

    const verifyResponse = await client.execute(verifyReq);
    if (verifyResponse.result.verification_status !== 'SUCCESS') {
      console.log('Webhook inválido');
      return res.status(400).send('Webhook inválido');
    }

    // 2️⃣ Procesar eventos
    if (event.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
      const orderId = event.resource.id;
      const payerEmail = event.resource.payer.email_address;
      const amount = event.resource.amount.value;

      // 3️⃣ Evitar duplicados
      const exists = await pool.query(
        'SELECT 1 FROM file_purchases WHERE paypal_order_id = $1 LIMIT 1',
        [orderId]
      );
      if (exists.rows.length) return res.status(200).send('Compra ya registrada');

      // 4️⃣ Relacionar metadata (ejemplo usando custom_id)
      const fileId = event.resource.custom_id; // Debe haberse enviado desde el frontend al crear el pedido
      const userId = event.resource.invoice_id; // Ejemplo: usar invoice_id o metadata para identificar usuario

      // 5️⃣ Registrar compra en base de datos
      await pool.query(
        'INSERT INTO file_purchases (file_id, user_id, paypal_order_id, payer_email, amount) VALUES ($1, $2, $3, $4, $5)',
        [fileId, userId, orderId, payerEmail, amount]
      );

      console.log('Compra registrada:', orderId, payerEmail, fileId, userId);
    }

    // Otros eventos opcionales
    if (event.event_type === 'PAYMENT.CAPTURE.DENIED') {
      console.log('Pago denegado:', event.resource.id);
    }
    if (event.event_type === 'PAYMENT.CAPTURE.PENDING') {
      console.log('Pago pendiente:', event.resource.id);
    }

    res.sendStatus(200); // OK para PayPal
  } catch (err) {
    console.error('Error procesando webhook PayPal:', err);
    res.status(500).send('Error interno al procesar el webhook');
  }
});

// Iniciar servidor (para pruebas locales)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor webhook PayPal corriendo en puerto ${PORT}`));

module.exports = app;