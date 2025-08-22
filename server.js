
import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import ejs from 'ejs';
import puppeteer from 'puppeteer';
import { promisify } from 'util';
import { exec } from 'child_process';

// Configure Puppeteer for Render.com environment
const isProd = process.env.NODE_ENV === 'production';
const puppeteerConfig = {
    args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1920x1080'
    ],
    headless: 'new',
    executablePath: isProd ? '/usr/bin/chromium' : undefined
};
import path from 'path';
import { promises as fs } from 'fs';
import crypto from 'crypto';

dotenv.config();

// Token signing config for secure short-lived download links
const DOWNLOAD_TOKEN_SECRET = process.env.DOWNLOAD_TOKEN_SECRET || process.env.ENCRYPTION_KEY || 'dev-download-secret';
const DOWNLOAD_TOKEN_TTL = Number(process.env.DOWNLOAD_TOKEN_TTL_SECONDS || process.env.DOWNLOAD_TOKEN_TTL || 60 * 60); // seconds

// In-memory duplicate request protection: compute a short-lived HMAC signature
// of the incoming quote payload and ignore repeat requests within this window.
const DUPLICATE_WINDOW_SECONDS = Number(process.env.DUPLICATE_WINDOW_SECONDS || 15); // seconds
const recentRequests = new Map(); // signature -> unix timestamp (seconds)
// Records of fully processed requests (to make /send-quote idempotent)
const sentRecords = new Map(); // signature -> unix timestamp (seconds)
// Track recipients already sent for a given body signature to avoid duplicate sends
const sentRecipients = new Map(); // signature -> Set of email addresses

// Periodic cleanup to avoid unbounded memory growth
setInterval(() => {
    const now = Math.floor(Date.now() / 1000);
    for (const [sig, ts] of recentRequests.entries()) {
        if (now - ts > DUPLICATE_WINDOW_SECONDS) recentRequests.delete(sig);
    }
    // cleanup sentRecords as well (keep same window)
    for (const [sig, ts] of sentRecords.entries()) {
        if (now - ts > DUPLICATE_WINDOW_SECONDS) sentRecords.delete(sig);
    }
    for (const [sig, set] of sentRecipients.entries()) {
        if (!sentRecords.has(sig)) {
            // if the record expired, remove recipients set as well
            sentRecipients.delete(sig);
        }
    }
}, 60 * 1000);

function base64UrlEncode(input) {
    return Buffer.from(input).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function base64UrlDecode(input) {
    input = input.replace(/-/g, '+').replace(/_/g, '/');
    // pad
    while (input.length % 4) input += '=';
    return Buffer.from(input, 'base64').toString();
}

// Stable JSON stringify: sort object keys so logically-equal objects produce the same string
function stableStringify(obj) {
    const seen = new WeakSet();
    function canonicalize(value) {
        if (value && typeof value === 'object') {
            if (seen.has(value)) return; // avoid cycles
            seen.add(value);
            if (Array.isArray(value)) {
                return value.map(canonicalize);
            }
            const keys = Object.keys(value).sort();
            const out = {};
            for (const k of keys) {
                out[k] = canonicalize(value[k]);
            }
            return out;
        }
        return value;
    }
    return JSON.stringify(canonicalize(obj));
}

function signDownloadToken(payloadObj) {
    const payload = JSON.stringify(payloadObj);
    const payloadB64 = base64UrlEncode(payload);
    const mac = crypto.createHmac('sha256', DOWNLOAD_TOKEN_SECRET).update(payloadB64).digest('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return `${payloadB64}.${mac}`;
}

function verifyDownloadToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 2) return null;
        const [payloadB64, mac] = parts;
        const expectedMac = crypto.createHmac('sha256', DOWNLOAD_TOKEN_SECRET).update(payloadB64).digest('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const a = Buffer.from(mac);
        const b = Buffer.from(expectedMac);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
        const payloadJson = base64UrlDecode(payloadB64);
        const payload = JSON.parse(payloadJson);
        // check expiry
        const now = Math.floor(Date.now() / 1000);
        if (!payload.exp || payload.exp < now) return null;
        return payload;
    } catch (e) {
        return null;
    }
}

const app = express();
app.use(cors({
    origin: [
        'http://localhost:5173',
        'http://localhost:5174',
        'http://localhost:5175',
        'http://localhost:5176',
        'http://localhost:5177',
        'http://localhost:5178',
        'http://localhost:5179',
        'http://localhost:5180',
        'http://localhost:3000',
        'http://localhost:8080',
        process.env.FRONTEND_ORIGIN
    ],
    credentials: true
}));
app.use(express.json({ limit: '2mb' }));

// Middleware to check API key for /send-quote
const apiKey = process.env.API_KEY;
app.use('/send-quote', (req, res, next) => {
    const clientKey = req.headers['x-api-key'];
    if (!apiKey || clientKey !== apiKey) {
        return res.status(401).json({ success: false, error: 'Unauthorized: Invalid or missing API key.' });
    }
    next();
});

// Route for new email system (placeholder)
// app.post('/send-email', handleEmailRequest);

// Health check
app.get('/health', (req, res) => res.json({ ok: true }));

// debug endpoint removed in production

app.post('/send-quote', async (req, res) => {
  try {
        console.log('ENTER /send-quote handler, body:', JSON.stringify(req.body).slice(0,1000));
        // Quick duplicate detection: sign the JSON body with the DOWNLOAD_TOKEN_SECRET
    const bodyString = stableStringify(req.body || {});
        const bodySig = crypto.createHmac('sha256', DOWNLOAD_TOKEN_SECRET).update(bodyString).digest('hex');
        const now = Math.floor(Date.now() / 1000);
        const prev = recentRequests.get(bodySig);
        if (prev && now - prev < DUPLICATE_WINDOW_SECONDS) {
            console.log('Duplicate /send-quote request ignored (within window). Signature:', bodySig);
            return res.status(202).json({ success: true, duplicate: true, message: 'Duplicate request ignored.' });
        }
        // If this body was already fully processed recently, skip re-processing
        const alreadySent = sentRecords.get(bodySig);
        if (alreadySent && now - alreadySent < DUPLICATE_WINDOW_SECONDS) {
            console.log('Duplicate /send-quote request ignored (already processed). Signature:', bodySig);
            return res.status(202).json({ success: true, duplicate: true, message: 'Duplicate request already processed.' });
        }
        // record this incoming request footprint
        recentRequests.set(bodySig, now);
    const { name, email, phone, company, message, products } = req.body;

    if (!name || !email || !phone || !products || !Array.isArray(products) || products.length === 0) {
      return res.status(400).json({ success: false, error: 'Missing required fields or products.' });
    }


    // Nodemailer Gmail SMTP config from .env
    const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
    console.log('process.env.SMTP_HOST:', process.env.SMTP_HOST);
    console.log('SMTP_HOST:', SMTP_HOST);
    console.log('SMTP config:', SMTP_HOST, SMTP_PORT, SMTP_USER);
    const transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: Number(SMTP_PORT),
        secure: false,
        auth: {
            user: SMTP_USER,
            pass: SMTP_PASS
        },
        // enable logging/debug for investigation (remove in production)
        logger: true,
        debug: true
    });

    // Calculate total price for email subject
    const totalPrice = products.reduce((sum, item) => sum + item.totalPrice, 0);

    // Create a professional HTML email template with a PDF button placeholder
    const emailTemplate = `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Nouvelle demande de devis</title>
        <style>
            body { margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; }
            .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
            .header h1 { margin: 0; font-size: 28px; font-weight: 300; }
            .content { padding: 30px; }
            .section { margin-bottom: 25px; }
            .section-title { color: #2c3e50; font-size: 18px; font-weight: 600; margin-bottom: 15px; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
            .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 20px; }
            .info-item { background-color: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #3498db; }
            .info-label { font-weight: 600; color: #2c3e50; margin-bottom: 5px; }
            .info-value { color: #34495e; }
            .products-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            .products-table th { background-color: #3498db; color: white; padding: 12px; text-align: left; }
            .products-table td { padding: 12px; border-bottom: 1px solid #ecf0f1; }
            .products-table tr:nth-child(even) { background-color: #f8f9fa; }
            .total-row { background-color: #e8f4fd !important; font-weight: 600; }
            .message-box { background-color: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #2ecc71; margin: 20px 0; }
            .footer { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
            .footer p { margin: 5px 0; }
            .highlight { color: #3498db; font-weight: 600; }
            @media (max-width: 600px) {
                .info-grid { grid-template-columns: 1fr; }
                .content { padding: 20px; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📋 Nouvelle Demande de Devis</h1>
                <p style="margin: 10px 0 0 0; opacity: 0.9;">Reçue le ${new Date().toLocaleDateString('fr-FR', {
                    weekday: 'long',
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                })}</p>
            </div>

            <div class="content">
                <div class="section">
                    <div class="section-title">👤 Informations Client</div>
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">Nom et Prénom</div>
                            <div class="info-value">${name}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Email</div>
                            <div class="info-value"><a href="mailto:${email}" style="color: #3498db; text-decoration: none;">${email}</a></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Téléphone</div>
                            <div class="info-value"><a href="tel:${phone}" style="color: #3498db; text-decoration: none;">${phone}</a></div>
                        </div>
                        ${company ? `
                        <div class="info-item">
                            <div class="info-label">Société</div>
                            <div class="info-value">${company}</div>
                        </div>
                        ` : ''}
                    </div>
                </div>

                <div class="section">
                    <div class="section-title">🛍️ Produits Demandés</div>
                    <table class="products-table">
                        <thead>
                            <tr>
                                <th>Produit</th>
                                <th>Quantité</th>
                                <th>Prix Unitaire</th>
                                <th>Total</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${products.map(item => `
                                <tr>
                                    <td><strong>${item.product.name}</strong></td>
                                    <td>${item.quantity}</td>
                                    <td>${item.product.price.toLocaleString()} TND</td>
                                    <td><span class="highlight">${item.totalPrice.toLocaleString()} TND</span></td>
                                </tr>
                            `).join('')}
                            <tr class="total-row">
                                <td colspan="3"><strong>Total Estimé</strong></td>
                                <td><strong class="highlight">${totalPrice.toLocaleString()} TND</strong></td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                ${message ? `
                <div class="section">
                    <div class="section-title">💬 Message du Client</div>
                    <div class="message-box">
                        ${message.replace(/\n/g, '<br>')}
                    </div>
                </div>
                ` : ''}

                <div class="section">
                    <div style="background-color: #e8f4fd; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db;">
                        <h3 style="margin: 0 0 10px 0; color: #2c3e50;">⏰ Prochaines Étapes</h3>
                        <ul style="margin: 0; padding-left: 20px; color: #34495e;">
                            <li>Analyser la demande et vérifier la disponibilité des produits</li>
                            <li>Préparer un devis personnalisé avec les meilleures conditions</li>
                            <li>Contacter le client dans les 24h maximum</li>
                            <li>Proposer des alternatives si nécessaire</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="footer">
                <p><strong>🏢 Système de Gestion des Devis</strong></p>
                <p>Email automatique - Ne pas répondre directement</p>
                <p style="font-size: 12px; opacity: 0.8;">Contactez directement le client via les coordonnées fournies ci-dessus</p>
            </div>
            <!-- PDF_BUTTON_PLACEHOLDER -->
        </div>
    </body>
    </html>
    `;

    // Render PDF from EJS template and attach it
    const templatePath = path.join(process.cwd(), 'templates', 'devis-pdf.ejs');
    const pdfHtml = await ejs.renderFile(templatePath, {
        name,
        email,
        phone,
        company,
        message,
        products,
        totalPrice,
        // optional company details from env
        companySiret: process.env.COMPANY_SIRET,
        companyApe: process.env.COMPANY_APE,
        companyTva: process.env.COMPANY_TVA,
        companyPhone: process.env.COMPANY_PHONE,
        companyEmail: process.env.COMPANY_EMAIL,
        companySite: process.env.COMPANY_SITE,
        logoUrl: process.env.COMPANY_LOGO_URL,
        tvaRate: process.env.TVA_RATE ? Number(process.env.TVA_RATE) : 0.20,
        devisNumber: process.env.DEVIS_NUMBER || undefined
    });

    // Use Puppeteer to convert rendered HTML to PDF for reliable results
    console.log('process.cwd():', process.cwd());
    console.log('templatePath:', templatePath);
    let pdfBuffer;
    try {
        const browser = await puppeteer.launch(puppeteerConfig);
        const page = await browser.newPage();
        await page.setContent(pdfHtml, { waitUntil: 'networkidle0' });
        pdfBuffer = await page.pdf({ format: 'A4', margin: { top: '10mm', bottom: '10mm', left: '10mm', right: '10mm' } });
        await browser.close();
    } catch (e) {
        console.error('Error generating PDF with Puppeteer:', e);
        throw e;
    }

    console.log('PDF buffer length:', pdfBuffer ? pdfBuffer.length : 'null');

    // ensure folder exists and save the PDF so we can provide a download link
    const pdfDir = path.join(process.cwd(), 'generated-pdfs');
    console.log('pdfDir will be:', pdfDir);
    await fs.mkdir(pdfDir, { recursive: true });
    const fileName = `devis-${Date.now()}.pdf`;
    const filePath = path.join(pdfDir, fileName);
    try {
        await fs.writeFile(filePath, pdfBuffer);
        console.log('PDF written to:', filePath);
    } catch (e) {
        console.error('Error writing PDF file:', e);
        throw e;
    }
    // Build a download URL based on request and sign a short-lived token that includes the filename + expiry
    const baseUrl = req.protocol + '://' + req.get('host');
    const tokenPayload = {
        name: fileName,
        exp: Math.floor(Date.now() / 1000) + DOWNLOAD_TOKEN_TTL
    };
    const token = signDownloadToken(tokenPayload);
    const downloadUrl = `${baseUrl}/download-devis/${encodeURIComponent(fileName)}?token=${encodeURIComponent(token)}`;

    const receiver = process.env.RECEIVER_EMAIL || SMTP_USER;
    // support multiple admin recipients separated by commas in RECEIVER_EMAIL
    const receiverList = (receiver || '').split(',').map(s => s.trim()).filter(Boolean);
    // Debugging: log receiver/raw and parsed list to troubleshoot delivery issues
    try {
        console.log('DEBUG RECEIVER raw ->', receiver);
        console.log('DEBUG RECEIVER_LIST ->', JSON.stringify(receiverList));
        console.log('DEBUG BODY_SIG ->', bodySig);
    } catch (e) {
        console.warn('Could not log receiver debug info', e && e.message);
    }
    // Replace placeholder with a visible download button linking to the stored PDF (tokenized)
    const pdfButtonHtml = `
            <div style="text-align:center;margin:20px 0;">
                <a href="${downloadUrl}" style="background:#e74c3c;color:white;padding:12px 20px;text-decoration:none;border-radius:5px;font-weight:bold;display:inline-block;">📄 Télécharger le Devis (PDF)</a>
                <p style="font-size:12px;color:#666;margin-top:8px;">Le devis est également disponible en pièce jointe.</p>
            </div>
        `;

    const mailHtml = emailTemplate.replace('<!-- PDF_BUTTON_PLACEHOLDER -->', pdfButtonHtml);

    // Send exactly one email to admin
    const mail = {
        from: `"Système de Devis" <${SMTP_USER}>`,
        to: receiverList.join(', '),
        subject: `🔔 Nouvelle demande de devis - ${name} (${totalPrice.toLocaleString()} TND)`,
        html: mailHtml,
        attachments: [
            {
                filename: fileName,
                content: pdfBuffer,
                contentType: 'application/pdf',
                contentDisposition: 'attachment',
                cid: 'devis.pdf'
            }
        ]
    };

    try {
        let recSet = sentRecipients.get(bodySig);
        if (!recSet) {
            recSet = new Set();
            sentRecipients.set(bodySig, recSet);
        }
        // determine which admin recipients still need the email
        const toSendAdmins = receiverList.filter(r => !recSet.has(r));
        if (toSendAdmins.length > 0) {
            console.log('Sending admin emails individually to:', toSendAdmins.join(', '));
            for (const adminAddr of toSendAdmins) {
                const singleMail = { ...mail, to: adminAddr };
                // Defensively remove any unexpected cc/bcc fields before sending
                try {
                    if (singleMail.bcc) {
                        console.warn('Removing unexpected admin mail.bcc for', adminAddr, singleMail.bcc);
                        delete singleMail.bcc;
                    }
                    if (singleMail.cc) {
                        console.warn('Removing unexpected admin mail.cc for', adminAddr, singleMail.cc);
                        delete singleMail.cc;
                    }
                } catch (err) {
                    console.warn('Could not clean admin mail cc/bcc', err && err.message);
                }
                // Debug: log envelope/headers we will send to SMTP for this recipient
                try {
                    const envelope = { from: SMTP_USER, to: adminAddr };
                    // attach explicit SMTP envelope to force RCPT TO at transport level
                    singleMail.envelope = envelope;
                    console.log('ADMIN MAIL PREVIEW ->', JSON.stringify({
                        to: singleMail.to,
                        cc: singleMail.cc || null,
                        bcc: singleMail.bcc || null,
                        subject: singleMail.subject,
                        attachments: singleMail.attachments ? singleMail.attachments.map(a => a.filename) : [],
                        envelope
                    }));
                } catch (err) {
                    console.warn('Could not stringify admin mail preview', err && err.message);
                }
                console.log('ADMIN SMTP ENVELOPE ->', { from: SMTP_USER, to: adminAddr });
                const info = await transporter.sendMail(singleMail);
                console.log(`✅ Email sent successfully to admin ${adminAddr}. MessageId: ${info.messageId}`);
                try {
                    console.log('ADMIN SEND INFO ->', info);
                    if (info && info.envelope) console.log('ADMIN SEND ENVELOPE ->', info.envelope);
                } catch (err) {
                    console.warn('Could not stringify admin send info', err && err.message);
                }
                recSet.add(adminAddr);
            }
        } else {
            console.log('All admin recipients already sent for this signature, skipping admin send:', receiverList.join(', '));
        }
        // Mark this body as processed to avoid accidental re-sends
        sentRecords.set(bodySig, Math.floor(Date.now() / 1000));
    } catch (e) {
        console.error('Error sending admin email:', e);
    }

    // Send exactly one email to the client (email provided in the request body)
    try {
        const clientEmail = (req.body && req.body.email) || email || null;
        if (clientEmail && clientEmail !== receiver) {
            const clientMail = {
                from: `"Système de Devis" <${SMTP_USER}>`,
                to: clientEmail,
                subject: `Votre devis - ${name} (${totalPrice.toLocaleString()} TND)`,
                html: mailHtml,
                attachments: [
                    {
                        filename: fileName,
                        content: pdfBuffer,
                        contentType: 'application/pdf',
                        contentDisposition: 'attachment',
                        cid: 'devis.pdf'
                    }
                ]
            };
            try {
                let recSet = sentRecipients.get(bodySig);
                if (!recSet) {
                    recSet = new Set();
                    sentRecipients.set(bodySig, recSet);
                }
                if (!recSet.has(clientEmail)) {
                    // Defensively remove any unexpected cc/bcc fields before sending
                    try {
                        if (clientMail.bcc) {
                            console.warn('Removing unexpected client mail.bcc:', clientMail.bcc);
                            delete clientMail.bcc;
                        }
                        if (clientMail.cc) {
                            console.warn('Removing unexpected client mail.cc:', clientMail.cc);
                            delete clientMail.cc;
                        }
                    } catch (err) {
                        console.warn('Could not clean client mail cc/bcc', err && err.message);
                    }
                    // Debug: log envelope/headers we will send to SMTP
                    try {
                        const envelope = { from: SMTP_USER, to: clientEmail };
                        clientMail.envelope = envelope;
                        console.log('CLIENT MAIL PREVIEW ->', JSON.stringify({
                            to: clientMail.to,
                            cc: clientMail.cc || null,
                            bcc: clientMail.bcc || null,
                            subject: clientMail.subject,
                            attachments: clientMail.attachments ? clientMail.attachments.map(a => a.filename) : [],
                            envelope
                        }));
                    } catch (err) {
                        console.warn('Could not stringify client mail preview', err && err.message);
                    }
                    console.log('CLIENT SMTP ENVELOPE ->', { from: SMTP_USER, to: clientEmail });
                    const infoClient = await transporter.sendMail(clientMail);
                    console.log(`✅ Email sent successfully to client ${clientEmail}. MessageId: ${infoClient.messageId}`);
                    try {
                        console.log('CLIENT SEND INFO ->', infoClient);
                        if (infoClient && infoClient.envelope) console.log('CLIENT SEND ENVELOPE ->', infoClient.envelope);
                    } catch (err) {
                        console.warn('Could not stringify client send info', err && err.message);
                    }
                    recSet.add(clientEmail);
                    sentRecords.set(bodySig, Math.floor(Date.now() / 1000));
                } else {
                    console.log('Client already sent for this signature, skipping client send:', clientEmail);
                }
            } catch (e) {
                console.error('Error sending client email:', e);
            }
        } else if (clientEmail && clientEmail === receiver) {
            console.log('Client email equals admin email; client will not receive a separate email to avoid duplicate.');
            // already processed by admin send; ensure recorded
            sentRecords.set(bodySig, Math.floor(Date.now() / 1000));
        } else {
            console.log('No client email provided; skipping client send.');
            // mark as processed
            sentRecords.set(bodySig, Math.floor(Date.now() / 1000));
        }
    } catch (e) {
        console.error('Error sending email to client:', e);
    }
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('❌ Error in /send-quote:', err);
        if (err.code === 'EAUTH') {
            console.error('🔑 Authentication failed. Please check Gmail SMTP credentials in .env file.');
        }
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Admin test endpoint: return cart row for a user (protected by SERVICE_ROLE_KEY)
app.get('/admin/cart/:userId', async (req, res) => {
    try {
        const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
        if (!serviceKey) return res.status(403).json({ error: 'Service role key not configured' });
        const userId = req.params.userId;
        // Use supabase client server-side only if configured; fallback to direct PG query is not implemented here.
        // For simplicity, we'll use node-postgres if SUPABASE_URL and SERVICE_ROLE_KEY are provided via environment.
        const fetch = (await import('node-fetch')).default;
        const supabaseUrl = process.env.VITE_SUPABASE_URL;
        const resp = await fetch(`${supabaseUrl}/rest/v1/carts?user_id=eq.${userId}`, {
            headers: {
                apikey: serviceKey,
                Authorization: `Bearer ${serviceKey}`
            }
        });
        const data = await resp.json();
        return res.json({ data });
    } catch (e) {
        console.error('Error in /admin/cart/:userId', e);
        return res.status(500).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 5000;
// Route to download generated PDFs
app.get('/download-devis/:name', async (req, res) => {
    try {
        const name = req.params.name;
        const token = req.query.token;
        if (!token || typeof token !== 'string') {
            return res.status(401).send('Unauthorized: missing token');
        }
        const payload = verifyDownloadToken(token);
        if (!payload || payload.name !== name) {
            return res.status(403).send('Forbidden: invalid or expired token');
        }
        const p = path.join(process.cwd(), 'generated-pdfs', name);
        // Ensure file exists before attempting download
        try {
            await fs.access(p);
        } catch (e) {
            console.error('Requested PDF not found:', p, e);
            return res.status(404).send('Not found');
        }
        return res.download(p);
    } catch (e) {
        console.error('Error serving PDF', e);
        return res.status(500).send('Internal error');
    }
});

// Health check endpoint
app.get('/health', async (req, res) => {
    try {
        const execAsync = promisify(exec);
        const { stdout } = await execAsync('chromium --version');
        res.json({
            status: 'healthy',
            chrome: stdout.trim(),
            node: process.version,
            env: process.env.NODE_ENV
        });
    } catch (error) {
        res.status(500).json({ status: 'error', error: error.message });
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
