#  Burp Source Map Finder Extension

This Burp Suite extension automatically detects `.js` files in HTTP responses and attempts to retrieve the associated `.js.map` files. If a `.map` file is publicly accessible, it is logged in a custom Burp tab and reported as an **Informational Issue**.

---

## ✨ Features

- ✅ Auto-detection of `.js` files in traffic
- 🧭 Automatically fetches `.js.map` files from the same path
- 🗂️ Displays results in a custom tab: `Map Finds`
- ⚠️ Raises a **Scanner Issue** when source maps are exposed

---

## 📦 Requirements

- [Burp Suite](https://portswigger.net/burp)
- [Jython 2.7.3 standalone JAR](https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar)

---

## 🚀 Installation

1. Download `jython-standalone-2.7.3.jar`
2. Open Burp → **Extender > Options > Python Environment**
3. Set the path to the Jython JAR
4. Open **Extender > Extensions**
5. Click **Add**:
   - Type: `Python`
   - File: `sourcemap_finder.py`

---

## 🔧 Usage

- Browse a web app with Burp (Proxy, Spider, etc.)
- The extension will monitor responses for `.js` files
- If a corresponding `.js.map` is found:
  - It is shown in the **Map Finds** tab
  - An issue is raised in **Scanner > Issues**

---

## 📚 Example

```

\[+] Checking: [https://example.com/static/app.js.map](https://example.com/static/app.js.map)
\[!] Source map found: [https://example.com/static/app.js.map](https://example.com/static/app.js.map)

```

---

## ❗ Why it matters

Publicly accessible `.map` files may expose:
- Original source code
- Comments and debug logic
- Directory structure and variable names

This extension helps detect and report these files during testing.

---

## 🛡️ Recommendation

Do not deploy source maps to production environments unless strictly necessary. Use proper access control or build tools to exclude them automatically.

---

## 📄 License

MIT – Free to use and modify.

