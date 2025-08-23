import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import ejs from 'ejs';
import puppeteer from 'puppeteer';
import { promisify } from 'util';
import { exec } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configure Puppeteer for production environment
const isProd = process.env.NODE_ENV === 'production';
const puppeteerConfig = {
    args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1920x1080'
    ]
};

const app = express();

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Configure CORS
app.use(cors({
    origin: process.env.FRONTEND_ORIGIN || 'https://bedoui-firas-projects-e7e8a63d.vercel.app',
    credentials: true
}));

// Parse JSON bodies
app.use(express.json());

// Basic route to test the server
app.get('/', (req, res) => {
    res.json({ message: 'Server is running' });
});

// Configure nodemailer
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Send quote route
app.post('/send-quote', async (req, res) => {
    try {
        const { cartItems, totalPrice, customerInfo } = req.body;
        
        // Generate PDF
        const browser = await puppeteer.launch(puppeteerConfig);
        const page = await browser.newPage();
        
        // Read the EJS template
        const template = await ejs.renderFile(
            join(__dirname, 'templates', 'devis-pdf.ejs'),
            { cartItems, totalPrice, customerInfo }
        );
        
        await page.setContent(template);
        
        // Generate PDF filename
        const pdfFileName = `devis-${Date.now()}.pdf`;
        const pdfPath = join(__dirname, 'generated-pdfs', pdfFileName);
        
        // Ensure directory exists
        if (!fs.existsSync(join(__dirname, 'generated-pdfs'))) {
            fs.mkdirSync(join(__dirname, 'generated-pdfs'), { recursive: true });
        }
        
        // Generate PDF
        await page.pdf({
            path: pdfPath,
            format: 'A4'
        });
        
        await browser.close();
        
        // Send email with PDF
        const mailOptions = {
            from: process.env.SMTP_USER,
            to: process.env.RECEIVER_EMAIL,
            subject: 'Nouveau devis',
            text: 'Un nouveau devis a été généré.',
            attachments: [{
                filename: pdfFileName,
                path: pdfPath
            }]
        };
        
        await transporter.sendMail(mailOptions);
        
        res.json({ message: 'Devis envoyé avec succès' });
    } catch (error) {
        console.error('Error in /send-quote:', error);
        res.status(500).json({ error: 'Erreur lors de l\'envoi du devis' });
    }
});

// Error handler for unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Error handler for uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
    console.log('Environment:', process.env.NODE_ENV);
    console.log('Frontend Origin:', process.env.FRONTEND_ORIGIN);
});
