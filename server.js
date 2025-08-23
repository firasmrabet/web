import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import ejs from 'ejs';
import puppeteer from 'puppeteer';
import { promisify } from 'util';
import { exec } from 'child_process';

// Load environment variables
dotenv.config();

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
    ]
};

const app = express();

// Configure CORS
app.use(cors({
    origin: process.env.FRONTEND_ORIGIN,
    credentials: true
}));

// Parse JSON bodies
app.use(express.json());
