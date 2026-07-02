# Troubleshooting Guide

This guide compiles common build, deployment, and execution issues for **NetScope-DPI** and provides step-by-step solutions to resolve them.

---

## 🚫 1. Maven clean fails: "Failed to delete target/classes/..."
* **Problem**: Running `mvn clean` returns a build failure stating that a PCAP file or classes folder under `target/` cannot be deleted.
* **Reason**: The Spring Boot application is still running in the background and locking those files.
* **Solution**:
  1. Kill the running Spring Boot server process (e.g. close the terminal running the server).
  2. Run `mvn clean compile` again.

---

## 🔒 2. API Request Blocked: CORS Errors in Browser Console
* **Problem**: The web app landing page loads, but clicking "Or Load Sample PCAP" or rules configurations throws a network error, and the browser console logs a CORS policy violation.
* **Reason**: The backend REST API does not trust your frontend domain.
* **Solution**: Ensure your live backend allows requests from your live frontend URL. In development, the default config allows requests from `http://localhost:3000`.

---

## 💾 3. Out-Of-Memory (OOM) Crashes on Large PCAP Files
* **Problem**: The backend server crashes or returns `500 Internal Server Error` during the analysis of very large PCAP logs (over 200MB).
* **Reason**: Java heap memory limit constraints.
* **Solution**:
  * Allocate more heap space to the Java Virtual Machine (JVM) when running the JAR:
    ```bash
    java -Xmx1024m -jar target/java-packet-analyzer-1.0-SNAPSHOT.jar
    ```

---

## 🔌 4. Server fails to start: "Port 8080 already in use"
* **Problem**: Starting the Spring Boot backend returns a bind exception.
* **Reason**: Another program (or a previously detached backend run) is already listening on port 8080.
* **Solution**:
  * **Windows**:
    ```powershell
    # Find process ID on port 8080
    Get-NetTCPConnection -LocalPort 8080
    # Stop that process
    Stop-Process -Id <PID> -Force
    ```
  * **Mac / Linux**:
    ```bash
    kill -9 $(lsof -t -i:8080)
    ```


THANK you! 