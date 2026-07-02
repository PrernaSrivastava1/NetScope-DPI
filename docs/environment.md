# Environment Configurations

This document outlines the environment variables, networking configurations, and active ports used by **NetScope-DPI** in production and development environments.

---

## 🌐 Frontend Environment Variables

The Next.js frontend uses client-side environment variables to connect to the backend REST API.

| Variable Name | Purpose | Example Value | Default (Fallback) |
| :--- | :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | The public base URL of the active Spring Boot API. | `https://netscope-api.onrender.com` | `http://localhost:8080` |

> **Note**: In Next.js, client-side environment variables must be prefixed with `NEXT_PUBLIC_` so they are accessible inside the browser bundle.

---

## ☕ Backend Configurations

The Spring Boot backend utilizes standard property structures. You can customize the server port and CORS settings.

### Application Properties
Located at: `java-packet-analyzer/src/main/resources/application.properties`

* **`server.port`**: Defines which port the Tomcat server binds to.
  * Default: `8080` (can be overridden by Render/Railway via the `PORT` environment variable).
* **CORS Settings**: The `DPIController` allows cross-origin requests from the default Next.js client URL (`http://localhost:3000`). If hosting your frontend on Vercel, you can customize the CORS whitelist inside the Controller annotations.

---

## 🔌 Default Ports Summary

* **Frontend Dev Server**: `3000`
* **Backend Tomcat Server**: `8080`


Thank YOU!