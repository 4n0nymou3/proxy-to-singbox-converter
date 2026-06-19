# Drill — Proxy Core Builder

<p align="center">
  <img src="https://img.shields.io/badge/version-3.2.0-blue.svg?cacheSeconds=2592000" />
</p>

## 🚀 Project Overview

Drill is a web-based tool that converts proxy configurations between different formats. It supports converting proxy URLs to Sing-box JSON or Clash YAML, converting between Sing-box and Clash formats directly, and extracting proxy URLs from existing Sing-box or Clash configs. It handles plain proxy URLs, subscription links, Base64-encoded data, Sing-box JSON, and Clash YAML/JSON as input.

https://4n0nymou3.github.io/proxy-core-builder/

## ✨ Features

- Supports multiple proxy protocols:
  - VMess
  - VLESS
  - Trojan
  - Hysteria2
  - Shadowsocks (ss)

- Accepts various input types:
  - Plain proxy URLs (`vmess://`, `vless://`, `trojan://`, `hysteria2://`, `ss://`)
  - Subscription links (http, https, ssconf)
  - Base64-encoded configurations
  - Sing-box JSON configurations
  - Clash YAML/JSON configurations

- **Conversion matrix — all supported directions:**
  - Proxy URLs → Sing-box JSON
  - Proxy URLs → Clash YAML
  - Sing-box JSON → Clash YAML
  - Clash YAML/JSON → Sing-box JSON
  - Sing-box JSON → Proxy URLs
  - Clash YAML/JSON → Proxy URLs

- Generated Sing-box configs include:
  - TUN + mixed inbound (port 2080)
  - urltest (best ping) + selector outbound groups
  - FakeIP DNS with split routing
  - Iran bypass via [Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules)
  - Ad/malware/phishing/cryptominer blocking
  - NTP sync via Cloudflare
  - Clash API dashboard support (port 9090)

- Generated Clash/Mihomo configs include:
  - TUN + mixed port (7890) with sniffer
  - url-test (best ping) + selector proxy groups
  - FakeIP DNS with split routing
  - Iran bypass via [Iran-clash-rules](https://github.com/Chocolate4U/Iran-clash-rules)
  - Ad/malware/phishing/cryptominer rule-providers
  - NTP sync via Cloudflare
  - External controller (port 9090)
  - Downloads as `.yaml` (JSON is valid YAML and recognized by all Clash clients)

- Smart button states: buttons automatically enable/disable based on detected input type
- Subscription link support with automatic fetch and decode via multiple CORS proxies
- Custom tag prefix for generated outbound/proxy names
- Paste from clipboard, URL, or file
- Copy to clipboard and download output

## 🛠️ Supported Protocols

| Protocol | → Sing-box | → Clash | → URLs |
|----------|:----------:|:-------:|:------:|
| VMess    | ✅ | ✅ | ✅ |
| VLESS    | ✅ | ✅ | ✅ |
| Trojan   | ✅ | ✅ | ✅ |
| Hysteria2 | ✅ | ✅ | ✅ |
| Shadowsocks | ✅ | ✅ | ✅ |

## 🖥️ Technologies Used

- HTML5
- CSS3
- JavaScript
- Ace Editor
- js-yaml (YAML parsing)
- Modern web technologies

## 📦 Installation

### Running with Docker

You can run the app as a static nginx container:

```sh
docker build -t proxy-core-builder .
docker run --rm -p 8080:80 proxy-core-builder
```

Then open:

```text
http://localhost:8080
```

### Running with Docker Compose

Start the app with Docker Compose:

```sh
docker compose up -d
```

Then open:

```text
http://localhost:8080
```

Stop the container with:

```sh
docker compose down
```

### Cloning and Running Locally

If you want to run this project locally on your device (e.g., Linux, macOS, Windows, Termux, or iSH), follow these steps:

1. Clone the repository:
   ```sh
   git clone https://github.com/4n0nymou3/proxy-core-builder.git
   ```

2. Navigate to the project directory:
   ```sh
   cd proxy-core-builder
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
2. Paste your input — proxy URLs, a subscription link, Base64 data, a Sing-box JSON, or a Clash YAML/JSON
3. The tool automatically detects the input type and enables the relevant buttons:
   - **Convert to Sing-box** — converts proxy URLs or Clash config to Sing-box JSON (disabled when input is already Sing-box)
   - **Convert to Clash** — converts proxy URLs or Sing-box JSON to Clash YAML (disabled when input is already Clash)
   - **Extract Proxy URLs** — extracts proxy URLs from a Sing-box or Clash config (enabled only when Sing-box/Clash input is detected)
4. Copy or download the output:
   - Sing-box output saves as `config.json`
   - Clash output saves as `config.yaml`
   - Extracted proxy URLs save as `config.txt`

## 👨‍💻 Author

Developed by Anonymous
- Twitter: [@4n0nymou3](https://x.com/4n0nymou3)

## 🛡️ Disclaimer

This tool is for educational and testing purposes. Always ensure you're complying with local laws and regulations.