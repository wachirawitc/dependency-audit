const express = require("express");
const _ = require("lodash");
const jwt = require("jsonwebtoken");
const request = require("request");
const logger = require("@acme/logger");

const app = express();
app.use(express.json());

const defaults = { currency: "EUR", shipping: { method: "standard" } };

// Merge per-request checkout options into the defaults.
app.post("/checkout/options", (req, res) => {
  const options = _.merge({}, defaults, req.body);
  res.json(options);
});

app.get("/orders/:id", (req, res) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  let claims;
  try {
    claims = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: "invalid token" });
  }
  request(
    { url: `${process.env.ORDERS_URL}/orders/${encodeURIComponent(req.params.id)}`, json: true },
    (err, upstream, body) => {
      if (err) {
        logger.error(err);
        return res.status(502).end();
      }
      res.json({ order: body, customer: claims.sub });
    }
  );
});

app.listen(process.env.PORT || 3000);
