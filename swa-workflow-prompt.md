# Azure Static Web App Setup Prompt

Copy and fill in the blanks, then paste to Claude:

---

## Prompt Template

```
Set up a new Azure Static Web App with the following details:

**Site/App Name:** _______________
(This will be used for the repo name, resource group, and Azure app name)

**Domain:** _______________
(e.g., example.com - must be registered in GoDaddy)

**Display Name:** _______________
(Name shown on the placeholder page, e.g., "Walter Tyrell")

**Tagline:** _______________
(Subtitle for the placeholder page, e.g., "Tyrell Tales")

**Teaser Text:** _______________
(What to show on the coming soon page, e.g., "Stories are being written...")

**Icon (optional):** _______________
(Unicode emoji or symbol for the page, e.g., ✍ or leave blank for default)

Use the workflow reference at ~/swa-workflow-reference.md. GoDaddy credentials are in Azure Key Vault (jinkslabs-vault). GitHub repo should be under GratefulJinx77. Deploy to Azure region centralus on Free tier. Minimize manual intervention.
```

---

## Example (filled in)

```
Set up a new Azure Static Web App with the following details:

**Site/App Name:** shadow-chronicles

**Domain:** shadowchronicles.com

**Display Name:** The Shadow Chronicles

**Tagline:** Tales from the Dark

**Teaser Text:** Darkness is coming...

**Icon (optional):** 🌑

Use the workflow reference at ~/swa-workflow-reference.md. GoDaddy credentials are in Azure Key Vault (jinkslabs-vault). GitHub repo should be under GratefulJinx77. Deploy to Azure region centralus on Free tier. Minimize manual intervention.
```

---

## Quick Version (minimal details)

```
New SWA: [APP_NAME] for [DOMAIN]. Pseudonym: [DISPLAY_NAME]. Use saved workflow reference and GoDaddy creds.
```

---

## Notes

- GitHub authentication may require device code (one-time per session)
- Azure GitHub integration will require device code (one-time per SWA creation)
- Domain validation takes 2-5 minutes after DNS is configured
- Reference file location: `~/swa-workflow-reference.md`
- GoDaddy credentials: Azure Key Vault `jinkslabs-vault` (secrets: `godaddy-api-key`, `godaddy-api-secret`)
