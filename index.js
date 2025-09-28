// index.js — GoldenSpaceAI Orders
// Express server that serves static files and processes payment webhooks
// Supports: LemonSqueezy + NOWPayments (crypto)
// On successful payment, sends an email to OWNER_EMAIL (and optional buyer)

import express from "express";
import dotenv from "dotenv";
import morgan from "morgan";
import cors from "cors";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import nodemailer from "nodemailer";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- capture raw body for HMAC verification on specific routes
const rawBodySaver = (req, res, buf) => {
  if (buf && buf.length) req.rawBody = buf.toString("utf8");
};

// Use raw body only for webhook routes; JSON elsewhere
app.use((req, res, next) => {
  if (req.path.startsWith("/webhook/")) {
    express.raw({ type: "*/*", verify: rawBodySaver })(req, res, next);
  } else {
    express.json({ verify: rawBodySaver })(req, res, next);
  }
});

app.use(cors());
app.use(morgan("tiny"));

// --- static site (put your frontend in /public)
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// --- small config endpoint for frontend (optional)
app.get("/config.json", (_req, res) => {
  res.json({
    site: process.env.SITE_NAME || "GoldenSpaceAI",
    env: process.env.APP_ENV || "dev",
    baseUrl: process.env.PUBLIC_BASE_URL || "",
  });
});

// --- Mailer (SMTP or provider credentials from .env)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: String(process.env.SMTP_SECURE || "true") === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/** Send order emails */
async function notifyOrder({ buyerEmail, websiteType, amount, currency, raw }) {
  const ownerEmail = process.env.OWNER_EMAIL;
  if (!ownerEmail) throw new Error("OWNER_EMAIL not set");

  const subject = `New ${websiteType || "website"} order ${buyerEmail ? "from " + buyerEmail : ""}`;
  const html = `
    <h2>New Website Order</h2>
    <p><b>Type:</b> ${websiteType || "unknown"}</p>
    <p><b>Buyer:</b> ${buyerEmail || "unknown"}</p>
    <p><b>Total:</b> ${amount || "?"} ${currency || ""}</p>
    <pre style="background:#0d1117;color:#e6edf3;padding:12px;border-radius:8px;overflow:auto">
${JSON.stringify(raw, null, 2)}
    </pre>
  `;

  await transporter.sendMail({
    from: `Orders <${process.env.SMTP_USER}>`,
    to: ownerEmail,
    subject,
    html,
  });

  // Optional confirmation to buyer
  if (buyerEmail && /\S+@\S+\.\S+/.test(buyerEmail) && process.env.SEND_BUYER_CONFIRMATION === "true") {
    await transporter.sendMail({
      from: `Faris • Coding Engineer <${process.env.SMTP_USER}>`,
      to: buyerEmail,
      subject: `Thanks! I received your ${websiteType || "website"} order`,
      html: `
        <h3>Thank you!</h3>
        <p>I just got your order. I'll email you shortly to collect requirements.</p>
        <p>— Faris</p>
      `,
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Webhook #1: LemonSqueezy                                           */
/*  Docs: https://docs.lemonsqueezy.com/                               */
/*  Header: x-signature = HMAC-SHA256(rawBody, LEMONSQUEEZY_SIGNING_SECRET) */
/*  Success event: "order_created" or "subscription_payment_success"   */
/* ------------------------------------------------------------------ */
function verifyLemonSignature(raw, header, secret) {
  if (!raw || !header || !secret) return false;
  const hmac = crypto.createHmac("sha256", secret);
  const digest = hmac.update(raw, "utf8").digest("hex");
  return crypto.timingSafeEqual(Buffer.from(header), Buffer.from(digest));
}

app.post("/webhook/lemonsqueezy", async (req, res) => {
  try {
    const sig = req.headers["x-signature"];
    const secret = process.env.LEMONSQUEEZY_SIGNING_SECRET;

    if (!verifyLemonSignature(req.rawBody, sig, secret)) {
      return res.status(400).send("Invalid LemonSqueezy signature");
    }

    const evt = JSON.parse(req.rawBody || "{}");
    const type = evt?.meta?.event_name || evt?.event;

    // Handle common success signals
    if (type === "order_created" || type === "subscription_payment_success") {
      const data = evt?.data || {};
      const attributes = data?.attributes || {};

      // If you passed custom fields (e.g., websiteType, buyer email) via checkout data/variants,
      // extract them here as needed. LemonSqueezy sends "customer_email" etc.
      const buyerEmail = attributes?.user_email || attributes?.customer_email || null;
      const currency = attributes?.currency || "USD";
      const amount = (attributes?.total ?? 0) / 100; // usually cents

      // You can attach websiteType using variants or custom fields; default to 'simple/ai/subscription'
      // If you used multiple products: map product_id or variant_id → type here.
      const websiteType =
        (attributes?.custom?.websiteType) ||
        (evt?.meta?.custom_data?.websiteType) ||
        "unknown";

      await notifyOrder({
        buyerEmail,
        websiteType,
        amount,
        currency,
        raw: evt,
      });
    }

    res.status(200).send("ok");
  } catch (e) {
    console.error("LS webhook error:", e);
    res.status(500).send("server error");
  }
});

/* ------------------------------------------------------------------ */
/*  Webhook #2: NOWPayments (Crypto)                                   */
/*  Docs: https://documenter.getpostman.com/view/7907941/S1a32n38      */
/*  Header: x-nowpayments-sig = HMAC-SHA512(rawBody, NOWPAYMENTS_IPN_SECRET) */
/*  Success status: payment_status === "finished"                       */
/* ------------------------------------------------------------------ */
function verifyNowPaymentsSignature(raw, header, secret) {
  if (!raw || !header || !secret) return false;
  const hmac = crypto.createHmac("sha512", secret);
  const digest = hmac.update(raw, "utf8").digest("hex");
  return crypto.timingSafeEqual(Buffer.from(header), Buffer.from(digest));
}

app.post("/webhook/nowpayments", async (req, res) => {
  try {
    const sig = req.headers["x-nowpayments-sig"];
    const secret = process.env.NOWPAYMENTS_IPN_SECRET;

    if (!verifyNowPaymentsSignature(req.rawBody, sig, secret)) {
      return res.status(400).send("Invalid NOWPayments signature");
    }

    const evt = JSON.parse(req.rawBody || "{}");

    // Check success
    if (evt?.payment_status === "finished") {
      // You can attach websiteType & buyer email via "order_description" or "order_id" mapping
      const buyerEmail = evt?.customer_email || null;
      const amount = evt?.price_amount;
      const currency = evt?.price_currency || "USD";

      // Try to parse websiteType from order_description like "type=ai;email=..."
      let websiteType = "unknown";
      if (typeof evt?.order_description === "string") {
        const m = evt.order_description.match(/type=(\w+)/i);
        if (m) websiteType = m[1].toLowerCase();
      }

      await notifyOrder({
        buyerEmail,
        websiteType,
        amount,
        currency,
        raw: evt,
      });
    }

    res.status(200).send("ok");
  } catch (e) {
    console.error("NOWPayments webhook error:", e);
    res.status(500).send("server error");
  }
});

/* ------------------------------------------------------------------ */

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
});
