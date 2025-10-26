// server.js
import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Vapi Middleware läuft!");
});

// Beispiel für Vapi-Webhook
app.post("/vapi-webhook", async (req, res) => {
  console.log("Vapi Request:", req.body);

  // Hier würdest du später mit Outlook kommunizieren
  res.json({ message: "Webhook empfangen!" });
});

app.listen(3000, () => {
  console.log("Server läuft auf http://localhost:3000");
});

