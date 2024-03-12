const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
require("dotenv").config();

const connection = mysql.createPool({
  host: "localhost",
  user: "wesley",
  password: "Goku1997@",
  database: "logger_db",
});

const secret = "guela";

router.use((req, res, next) => {
  req.dbConnection = connection;
  next();
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await connection.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );
    const user = rows[0];

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    const token = jwt.sign({ userId: user.id }, secret, { expiresIn: "1h" });

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro no servidor" });
  }
});

router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Nome de usuário e senha são obrigatórios." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await req.dbConnection.query(
      "INSERT INTO users (username, password) VALUES (?,?)",
      [username, hashedPassword]
    );

    res.status(201).json({ message: "Usuário cadastrado com sucesso." });
  } catch (error) {
    console.error("Erro ao cadastrar usuário:", error);
    res.status(500).json({ error: "Erro interno do servidor." });
  }
});

module.exports = router;
