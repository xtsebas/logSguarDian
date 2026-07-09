const express = require("express");
const { logsguardian } = require("../dist/index");

const USE_MIDDLEWARE = process.env.USE_MW === "1";
const app = express();

if (USE_MIDDLEWARE) {
  app.use(logsguardian({
    mode: "monitor",           // just monitor latency
    timeoutMs: 50,
    dbPath: ":memory:",
    modelDir: require("path").join(__dirname, "../../../training/models"),
  }));
}

app.get("/api/users", (req, res) => res.json({ ok: true }));
app.get("/api/products", (req, res) => res.json({ ok: true }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`server on :${port} MW=${USE_MIDDLEWARE}`));
