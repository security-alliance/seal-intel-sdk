# SEAL Intel SDK

SDK for interacting with SEAL Intel to block or trust web content (domains, IPs, URLs). 

## Usage

### Setup

```typescript
import { OpenCTIClient } from "@security-alliance/opencti-client";
import { generateIdentityId } from "@security-alliance/opencti-client/stix";
import { WebContentClient } from "@security-alliance/seal-intel-sdk";

// Create an OpenCTI client
const opencti = new OpenCTIClient("https://sealisac.org", "your-api-key");

// Generate your organization's identity ID (you create this, it's not provided by SEAL)
const YOUR_IDENTITY_ID = generateIdentityId({
  name: "Your Organization Name",
  identity_class: "organization",
});

// Initialize the SDK
const client = new WebContentClient(opencti, YOUR_IDENTITY_ID);
```

### Block or Trust Content

```typescript
// Block a domain
await client.blockWebContent({ type: "domain-name", value: "phishing-site.com" });

// Block a subdomain
await client.blockWebContent({ type: "domain-name", value: "scam.github.io" });

// Trust a domain
await client.trustWebContent({ type: "domain-name", value: "example.com" });

// Check status
const status = await client.getWebContentStatus({ type: "domain-name", value: "phishing-site.com" });
// Returns: { status: "blocked" | "trusted" | "unknown", actor?: Identifier<'identity'> }

// Unblock or untrust
await client.unblockWebContent({ type: "domain-name", value: "phishing-site.com" });
await client.untrustWebContent({ type: "domain-name", value: "example.com" });
```

### Domain vs URL Blocking

Prefer reporting domains or subdomains. Most platforms do not support URL blocking yet:
- URL blocking support varies by platform
- Some platforms only allow URL blocking for whitelisted domains
- Outcome for reporting URLs is not guaranteed

Domains and subdomains are supported across most platforms.

**When reporting:**
- Report the subdomain when only it is malicious: `scam.github.io`, `phishing.medium.com`
- Report the full domain when the entire domain is malicious: `phishing-site.com`
- Do not report parent domains when only a subdomain is malicious (e.g., `github.io`, `medium.com`)

### Available Content Types

```typescript
{ type: "url", value: "https://example.com/path" }
{ type: "domain-name", value: "example.com" }
{ type: "ipv4-addr", value: "192.168.1.1" }
{ type: "ipv6-addr", value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334" }
```