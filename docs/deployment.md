# Deployment Guide

This guide explains how to deploy the **NetScope-DPI** application to production hosts with continuous integration/continuous delivery (CI/CD) so that any future changes pushed to your GitHub repository automatically sync and update the live website.

---

## 🎨 Frontend Deployment: Vercel

Vercel is the recommended hosting provider for the React/Next.js frontend. It offers automatic build triggers upon pushing commits to your repository.

### Steps to Deploy:
1. **Sign Up / Log In**: Visit [Vercel](https://vercel.com) and log in with your GitHub account.
2. **Import Repository**:
   * Click **Add New** -> **Project**.
   * Import your **`NetScope-DPI`** repository.
3. **Configure Settings**:
   * **Root Directory**: Click *Edit* and select the `frontend` folder.
   * **Framework Preset**: Select **Next.js** (it is auto-detected).
   * **Environment Variables**:
     * Add a variable named `NEXT_PUBLIC_API_URL`.
     * Set its value to your live hosted backend URL (e.g. `https://netscope-api.onrender.com`).
4. **Deploy**:
   * Click **Deploy**. Vercel will build and host your frontend, providing a public `.vercel.app` URL.

---

## ☕ Backend Deployment: Render

Render is a developer-friendly platform to host Java/Spring Boot Web Services directly from GitHub.

### Steps to Deploy:
1. **Sign Up / Log In**: Visit [Render](https://render.com) and log in with GitHub.
2. **Create Web Service**:
   * Click **New** -> **Web Service**.
   * Select your **`NetScope-DPI`** repository.
3. **Configure Build & Run**:
   * **Name**: `netscope-api` (or any preferred identifier).
   * **Root Directory**: `java-packet-analyzer`.
   * **Language**: Select **Java**.
   * **Build Command**: `mvn clean package -DskipTests`
   * **Start Command**: `java -jar target/java-packet-analyzer-1.0-SNAPSHOT.jar`
   * **Instance Type**: Select **Free**.
4. **Deploy**:
   * Click **Create Web Service**. Render will download dependencies, package the JAR, and spin up the Tomcat container on port 8080.

---

## 🔄 Automatic Syncing & Updates

Once both platforms are linked to your GitHub repository:
- Any new commits pushed to the `main` branch (via `git push`) will trigger Vercel and Render to automatically rebuild and deploy.
- There is no need to manually package files or redeploy servers.


Thank you!