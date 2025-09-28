# Proxy to Sing-box Converter

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue.svg?cacheSeconds=2592000" />
</p>

## 🚀 Project Overview

Proxy to Sing-box Converter is a web-based tool designed to simplify the process of converting various proxy configurations to the Sing-box format and vice versa. This intuitive web application supports multiple proxy protocols and can handle plain configurations, Sing-box JSON configurations, links (including `ssconf://`), and Base64-encoded data, making it easy for users to generate and manage configurations.

https://4n0nymou3.github.io/proxy-to-singbox-converter/

## ✨ Features

- Supports multiple proxy protocols:
  - VMess
  - VLESS
  - Trojan
  - Hysteria2
  - Shadowsocks (ss)

- Accepts various input types:
  - Plain proxy configurations
  - Sing-box JSON configurations
  - Links (http, https, ssconf)
  - Base64-encoded configurations

- User-friendly web interface
- Real-time configuration conversion (both to Sing-box and from Sing-box to proxy configs)
- Terminal-like aesthetic design
- Clipboard copy functionality
- Animated JSON configuration display

## 🛠️ Supported Protocols

The converter currently supports the following proxy protocols:
- VMess
- VLESS
- Trojan
- Hysteria2
- Shadowsocks (ss)

## 🖥️ Technologies Used

- HTML5
- CSS3
- JavaScript
- Ace Editor
- Modern web technologies

## 📦 Installation

### Cloning and Running Locally

If you want to run this project locally on your device (e.g., Linux, macOS, Windows, Termux, or iSH), follow these steps:

1. Clone the repository:
   ```sh
   git clone https://github.com/4n0nymou3/proxy-to-singbox-converter.git
   ```

2. Navigate to the project directory:
   ```sh
   cd proxy-to-singbox-converter
   ```

3. Start a local HTTP server:
   
   - **For Python 3.x Users:**
     ```sh
     python -m http.server 8080
     ```
   
   - **For Python 2.x Users:**
     ```sh
     python -m SimpleHTTPServer 8080
     ```

   - **For Termux (Android) Users:** (Ensure Python is installed using `pkg install python`)
     ```sh
     python -m http.server 8080
     ```

   - **For iSH (iOS) Users:** (Ensure Python is installed in Alpine Linux via `apk add python3`)
     ```sh
     python3 -m http.server 8080
     ```

4. Open your web browser and go to:
   ```
   http://localhost:8080
   ```
   This will load the web application in your default browser, where you can use it normally.

### Stopping the Local Server

If you need to stop the local server without closing the terminal, use one of the following methods:

- Press **`Ctrl + C`** in the terminal where the server is running.
- If the terminal session is lost, find the server process with:
  ```sh
  lsof -i :8080
  ```
  Then stop it using:
  ```sh
  kill -9 PID
  ```
  (Replace `PID` with the actual process ID from the previous command.)

## 🚀 How to Use

1. Navigate to the web application
2. Paste your proxy configs, Sing-box JSON, links, or Base64-encoded data
3. Click "Convert to Sing-box" or "Convert to Proxy Configs" based on the input type
4. Copy or download the generated configuration

## 👨‍💻 Author

Developed by Anonymous
- Twitter: [@4n0nymou3](https://x.com/4n0nymou3)

## 🛡️ Disclaimer

This tool is for educational and testing purposes. Always ensure you're complying with local laws and regulations.