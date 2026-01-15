# Better-IP-Filter

![Java Version](https://img.shields.io/badge/Java-21+-blue)
![PaperMC](https://img.shields.io/badge/Paper-1.21.x-white)
![Release](https://img.shields.io/github/v/release/AREKKUZZERA/better-IP-Filter&logo=github)
[![Modrinth](https://img.shields.io/badge/Modrinth-Available-1bd96a?logo=modrinth&logoColor=white)](-)

**Better-IP-Filter** is a lightweight and fast IP whitelist plugin for **Minecraft Paper servers**.  
It performs early IP validation during the login process and blocks connections from non-whitelisted IP addresses with minimal performance impact.

---

## ✨ Features

- IP whitelist filtering on player join  
- Uses `AsyncPlayerPreLoginEvent` (early, efficient check)  
- Toggleable filtering without server restart  
- Extremely lightweight (O(1) lookups)  
- No external dependencies  
- IPv4 validation  
- Persistent storage (`ips.yml`)  
- Fully compatible with LuckPerms (Bukkit permissions)

---

## 📦 Requirements

- **Java:** 21 or newer  
- **Server:** Paper 1.21 – 1.21.11  
- **Build tool:** Maven (only if building from source)

---

## 📥 Installation

1. Download the compiled `Better-IP-Filter.jar`
2. Place it into your server’s `plugins/` directory
3. Start the server once to generate configuration files
4. Edit `config.yml` if needed
5. Restart the server

---

## ⚙️ Configuration

The plugin configuration is located in `config.yml`.

### Example `config.yml`

```yml
enabled: true

messages:
  prefix: "&7[&aIPF&7]&r "
  notAllowed: "&cAccess denied. Your IP is not whitelisted."
  enabled: "&aIP filtering enabled."
  disabled: "&eIP filtering disabled."
  added: "&aAdded IP: &f{ip}"
  removed: "&aRemoved IP: &f{ip}"
  notFound: "&cIP not found: &f{ip}"
  invalidIp: "&cInvalid IP: &f{ip}"
  listHeader: "&7Whitelisted IPs (&f{count}&7):"
  noPermission: "&cNo permission."
```

### Key options

* `enabled` — enables or disables IP filtering globally
* `messages` — fully customizable plugin messages (supports color codes)

---

## 🧾 Commands

| Command            | Description                     |
| ------------------ | ------------------------------- |
| `/ipf add <ip>`    | Add an IP to the whitelist      |
| `/ipf remove <ip>` | Remove an IP from the whitelist |
| `/ipf list`        | Show all whitelisted IPs        |
| `/ipf on`          | Enable IP filtering             |
| `/ipf off`         | Disable IP filtering            |

---

## 🔐 Permissions

| Permission              | Description           | Default |
| ----------------------- | --------------------- | ------- |
| `betteripfilter.admin`  | Full access           | OP      |
| `betteripfilter.add`    | Add IPs               | OP      |
| `betteripfilter.remove` | Remove IPs            | OP      |
| `betteripfilter.list`   | View whitelist        | OP      |
| `betteripfilter.toggle` | Enable/disable filter | OP      |

> The plugin uses standard Bukkit permissions and works seamlessly with **LuckPerms**.

---

## 🧠 How It Works

* The plugin listens to `AsyncPlayerPreLoginEvent`
* The player’s IP address is checked **before** they fully join the server
* Whitelisted IPs are stored in memory (`HashSet`) for O(1) lookup
* If the IP is not allowed, the connection is denied immediately
* No permission bypass is used by design to keep checks fast and secure

---

## 🚀 Performance Notes

* No scheduled tasks
* No reflection or NMS usage
* Constant-time IP lookups
* Thread-safe handling for async login events
* Negligible memory footprint

Designed to run on production servers with zero noticeable overhead.

---

## 📁 Plugin File Structure

After first launch:

```
plugins/Better-IP-Filter/
├── Better-IP-Filter.jar
├── config.yml
└── ips.yml
```

---

## 🛠 Build from Source

```bash
mvn clean package
```

The compiled JAR will be available in:

```
target/Better-IP-Filter-1.0.0.jar
```

---

## ✅ Compatibility

* ✔ Paper only
* ✔ Minecraft 1.21 – 1.21.11
* ✖ Not compatible with Spigot or Fabric

---

## 📄 License

This project is licensed under the **MIT License**.
You are free to use, modify, and distribute it in both private and commercial projects.

---

**Better-IP-Filter** — simple, fast, and secure IP filtering for modern Paper servers.
