#!/bin/bash
set -e

echo "=== Bootstrapping firmarpdfcertificado ==="

export PATH="/data/data/com.termux/files/usr/bin:$PATH"
cd /data/data/com.termux/files/home/firmarpdfcertificado

echo "1. Checking Node & NPM..."
node --version
npm --version

echo "2. Installing dependencies..."
npm install

echo "3. Building project..."
npm run build

echo "=== Bootstrap & Build Complete! ==="
