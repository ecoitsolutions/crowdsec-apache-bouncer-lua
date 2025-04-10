# 🛡️ CrowdSec Apache Bouncer with mod_lua

This project provides a CrowdSec bouncer for Apache using `mod_lua`. It integrates CrowdSec's decision engine directly into Apache, allowing you to block malicious IPs before they can access your web resources.

---

## ⚙️ Overview

**Key Capabilities:**

* Intercepts each incoming request to Apache and checks the client's IP against CrowdSec's Local API (LAPI).
* Blocks requests (returns HTTP `403`) for IPs flagged as malicious by CrowdSec.
* Uses caching to minimize LAPI queries, improving performance.
* Logs all actions (block, allow, cache hits, errors) to a dedicated log file.

**Why use this approach?**

* **Direct Integration with Apache:** Uses `mod_lua` to process requests in Apache's address space, potentially reducing overhead compared to external bouncers.
* **Automatic Installation & API Key Management:** A single script handles dependency installation and automatically generates/configures the bouncer API key using `cscli`.
* **Caching for Performance:** Reduces LAPI overhead by caching decisions for a configurable `cache_ttl`.
* **Comprehensive Logging:** Logs all events to `/var/log/crowdsec-apache-bouncer.log` for easy auditing.

---

## 📋 Prerequisites

While the installation script attempts to install most dependencies, ensure the following are met:

1.  **CrowdSec Installed and Running**:
    Ensure that CrowdSec is installed and the LAPI is accessible (commonly at `http://127.0.0.1:8080/`). The `cscli` command must be available in the system's `PATH`.
2.  **Apache Web Server**:
    Apache (`apache2` on Debian/Ubuntu, `httpd` on RHEL/CentOS/Fedora) must be installed. The script will attempt to install it if missing.
3.  **Root Privileges**:
    You need root privileges (or `sudo`) to run the installation script.
4.  **Internet Connection**:
    Required for downloading dependencies and potentially `lyaml` via LuaRocks.

---

## 🚀 Installation (Universal Script)

1.  **Download the necessary files:**
    Ensure you have the following files from this repository in the same directory (git clone this repo if you haven't already):
    * `install.sh`
    * `crowdsec_bouncer.lua`
    * `apache-bouncer.yaml` (this is the template)
    * `LICENSE` (Your chosen license file, e.g., AGPL-3.0)
2.  **Make the script executable:**
    ```bash
    chmod +x install.sh
    ```
3.  **Run the installation script:**
    ```bash
    sudo ./install.sh
    ```

**The script will perform the following actions:**

* Detect your operating system (Debian/Ubuntu or RHEL/CentOS/Fedora based).
* Install required packages: Apache (`httpd`/`apache2`), `mod_lua`, `lua-socket`, `lua-cjson`, and `lua-yaml` (or `lyaml` via LuaRocks if the system package is unavailable).
* Enable `mod_lua` for Apache (on Debian/Ubuntu).
* Create necessary directories (`/etc/crowdsec/bouncers`, `/usr/share/crowdsec-apache-bouncer`).
* Copy the `crowdsec_bouncer.lua` script and `LICENSE` file to `/usr/share/crowdsec-apache-bouncer/`.
* Copy the `apache-bouncer.yaml` template to `/etc/crowdsec/bouncers/`.
* Automatically generate a new bouncer API key using `cscli bouncers add apache-lua-bouncer`.
* Insert the generated API key into `/etc/crowdsec/bouncers/apache-bouncer.yaml`.
* Set appropriate ownership and permissions for the configuration file, Lua script, license file, and log file (`/var/log/crowdsec-apache-bouncer.log`).
* Provide instructions on how to activate the bouncer in your Apache configuration.

---

## 🔧 Apache Configuration Activation

After running the installation script, you **must** manually edit your Apache configuration to activate the bouncer. Add the following directives inside the relevant `<VirtualHost>` section(s) of your Apache configuration file (e.g., `/etc/httpd/conf.d/your-site.conf` on RHEL/CentOS or `/etc/apache2/sites-available/your-site.conf` on Debian/Ubuntu):

```apache
<VirtualHost *:80>
    ServerName yourdomain.com
    DocumentRoot /var/www/html

    # --- CrowdSec Lua Bouncer ---
    # Load the Lua script
    LuaLoadFile /usr/share/crowdsec-apache-bouncer/crowdsec_bouncer.lua

    # Hook into the access checker phase
    LuaHookAccessChecker check_access
    # --- End CrowdSec Lua Bouncer ---

    # Other standard Apache directives...
</VirtualHost>
### <ins>Understanding `LuaHookAccessChecker`</ins>

> *Note: The `check_access` function is called implicitly by `mod_lua` during the access checker phase specified by `LuaHookAccessChecker`. It receives the Apache request object (`r`) automatically, which contains client IP and other request details necessary for the bouncer's logic. This hook runs early in the request cycle, before content generation, allowing malicious IPs to be blocked efficiently.*

---

### <ins>Activating the Bouncer in Apache</ins>

> **⚠️ Important:** After adding the `LuaLoadFile` and `LuaHookAccessChecker` lines to your Apache configuration:
>
> 1.  **Test your Apache configuration for syntax errors:**
>     * Debian/Ubuntu: `sudo apache2ctl configtest`
>     * RHEL/CentOS/Fedora: `sudo apachectl configtest`
> 2.  **If the configuration test is successful, restart Apache to apply the changes:**
>     * Debian/Ubuntu: `sudo systemctl restart apache2`
>     * RHEL/CentOS/Fedora: `sudo systemctl restart httpd`
>
> ✅ The bouncer should now be active for the configured virtual host(s).

---

### <ins>File Descriptions</ins>

#### 📄 Configuration File

* **Location:** `/etc/crowdsec/bouncers/apache-bouncer.yaml`
* **Contents:**
    * `crowdsec_lapi_url`: URL of the CrowdSec Local API (default: `http://127.0.0.1:8080/`). **Must be reachable** by the Apache server process.
    * `api_key`: The API key for this bouncer, automatically generated by `install.sh`.
    * `cache_ttl`: Cache duration (in seconds) for decisions (default: `60`). How long an IP's block/allow status is remembered before querying the LAPI again.

####  Lua Script

* **Location:** `/usr/share/crowdsec-apache-bouncer/crowdsec_bouncer.lua`
* **Functionality:** Contains the core logic executed by `mod_lua`. It reads the configuration, implements the `check_access` function hooked by Apache, queries the CrowdSec LAPI, manages the cache, logs actions, and returns the appropriate HTTP status code (e.g., `403` for blocked IPs or allows Apache to continue processing).

#### 🪵 Log File

* **Location:** `/var/log/crowdsec-apache-bouncer.log`
* **Contents:** Records the bouncer's activity, including IPs checked against LAPI, cache hits, blocked requests, allowed requests (can be verbose), and any errors encountered during operation (e.g., LAPI connection issues, configuration errors).
* **Permissions:** The installation script attempts to set ownership to the Apache user (`www-data` or `apache`) and permissions (e.g., `640`) to allow Apache to write to this file. **Verify these permissions if logging doesn't work.**