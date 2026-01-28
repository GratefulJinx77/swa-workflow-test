# Azure Static Web App Workflow Reference

## Saved Credentials & Configuration

### GoDaddy API
- **Credentials:** Azure Key Vault (`jinkslabs-vault`)
  - Secret: `godaddy-api-key`
  - Secret: `godaddy-api-secret`
- **API Docs:** https://developer.godaddy.com/doc
- **Load credentials:**
  ```bash
  export GODADDY_API_KEY=$(az keyvault secret show --vault-name jinkslabs-vault --name godaddy-api-key --query "value" -o tsv)
  export GODADDY_API_SECRET=$(az keyvault secret show --vault-name jinkslabs-vault --name godaddy-api-secret --query "value" -o tsv)
  ```

### Azure Key Vault
- **Vault Name:** `jinkslabs-vault`
- **Resource Group:** `jinkslabs-shared-rg`
- **Location:** `centralus`

### Azure
- **Subscription:** Primary PAYG (`86010fa7-268b-4d8e-95a6-6e0fab75c06c`)
- **Tenant:** Jinks Labs (`5a62aa80-bceb-44d3-9879-b4a48deb66de`)
- **Preferred Region:** `centralus`
- **Login command:** `az login --use-device-code`

### GitHub
- **Username:** GratefulJinx77
- **CLI location:** `~/.local/bin/gh`
- **Login command:** `gh auth login --hostname github.com --git-protocol https --web`
- **Setup git auth:** `gh auth setup-git`

---

## Workflow Steps

### 1. Create GitHub Repository
```bash
export PATH="$HOME/.local/bin:$PATH"
gh repo create GratefulJinx77/<REPO_NAME> --public --description "<DESCRIPTION>" --clone
```

### 2. Create Placeholder Content
Create `index.html` and `staticwebapp.config.json` in the repo directory.

### 3. Commit and Push
```bash
cd <REPO_DIR>
git config user.email "Brad@jinkslabs.com"
git config user.name "GratefulJinx77"
git add .
git commit -m "Initial placeholder site"
git branch -M main
git push -u origin main
```

### 4. Create Azure Resource Group
```bash
az group create --name <APP_NAME>-rg --location centralus
```

### 5. Create Static Web App (linked to GitHub)
```bash
az staticwebapp create \
  --name <APP_NAME> \
  --resource-group <APP_NAME>-rg \
  --location centralus \
  --sku Free \
  --source https://github.com/GratefulJinx77/<REPO_NAME> \
  --branch main \
  --app-location "/" \
  --output-location "" \
  --login-with-github
```
*This will prompt for GitHub device code authentication.*

### 6. Add Custom Domain to Azure
```bash
az staticwebapp hostname set \
  --name <APP_NAME> \
  --resource-group <APP_NAME>-rg \
  --hostname <DOMAIN> \
  --validation-method dns-txt-token

# Get validation token
az staticwebapp hostname show \
  --name <APP_NAME> \
  --resource-group <APP_NAME>-rg \
  --hostname <DOMAIN> \
  --query "validationToken" -o tsv
```

### 7. Configure GoDaddy DNS
```bash
# Load credentials from Key Vault
export GODADDY_API_KEY=$(az keyvault secret show --vault-name jinkslabs-vault --name godaddy-api-key --query "value" -o tsv)
export GODADDY_API_SECRET=$(az keyvault secret show --vault-name jinkslabs-vault --name godaddy-api-secret --query "value" -o tsv)

# Get Azure SWA default hostname for IP lookup
DEFAULT_HOST=$(az staticwebapp show --name <APP_NAME> --resource-group <APP_NAME>-rg --query "defaultHostname" -o tsv)
IP=$(getent hosts $DEFAULT_HOST | awk '{print $1}')

# Add DNS records
curl -X PATCH "https://api.godaddy.com/v1/domains/<DOMAIN>/records" \
  -H "Authorization: sso-key ${GODADDY_API_KEY}:${GODADDY_API_SECRET}" \
  -H "Content-Type: application/json" \
  -d '[
    {"type": "TXT", "name": "@", "data": "<VALIDATION_TOKEN>", "ttl": 3600},
    {"type": "A", "name": "@", "data": "'$IP'", "ttl": 3600}
  ]'
```

### 8. Verify Domain Status
```bash
az staticwebapp hostname show \
  --name <APP_NAME> \
  --resource-group <APP_NAME>-rg \
  --hostname <DOMAIN> \
  --query "status" -o tsv
```
*Wait for status to change: Validating -> Adding -> Ready*

---

## Placeholder HTML Template

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{DISPLAY_NAME}} | {{TAGLINE}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Georgia', serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e8e8e8;
        }
        .container { text-align: center; padding: 2rem; max-width: 600px; }
        h1 {
            font-size: 3.5rem; font-weight: 300; letter-spacing: 0.15em;
            margin-bottom: 0.5rem; color: #f5f5f5; text-transform: uppercase;
        }
        .tagline { font-size: 1.2rem; font-style: italic; color: #a0a0a0; margin-bottom: 3rem; letter-spacing: 0.1em; }
        .divider { width: 60px; height: 1px; background: linear-gradient(90deg, transparent, #e94560, transparent); margin: 0 auto 2rem; }
        .coming-soon { font-size: 1.1rem; color: #c0c0c0; margin-bottom: 2rem; }
        .icon { font-size: 4rem; margin-bottom: 2rem; opacity: 0.8; }
        footer { margin-top: 3rem; font-size: 0.85rem; color: #606060; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">{{ICON}}</div>
        <h1>{{DISPLAY_NAME}}</h1>
        <p class="tagline">{{TAGLINE}}</p>
        <div class="divider"></div>
        <p class="coming-soon">{{TEASER_LINE_1}}</p>
        <p class="coming-soon">{{TEASER_LINE_2}}</p>
        <footer>&copy; {{YEAR}} {{DISPLAY_NAME}}. All rights reserved.</footer>
    </div>
</body>
</html>
```

---

## Static Web App Config Template

```json
{
  "navigationFallback": {
    "rewrite": "/index.html"
  },
  "globalHeaders": {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'"
  }
}
```

---

## Existing Sites

| Site | Repo | Domain | Resource Group |
|------|------|--------|----------------|
| walter-tyrell | GratefulJinx77/walter-tyrell | tyrelltales.com | walter-tyrell-rg |

---

## Cleanup Command (if needed)
```bash
az group delete --name <APP_NAME>-rg --yes --no-wait
gh repo delete GratefulJinx77/<REPO_NAME> --yes
```
