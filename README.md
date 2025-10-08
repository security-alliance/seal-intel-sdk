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
// Block a phishing URL
await client.blockWebContent({ type: "url", value: "https://phishing-site.com" });

// Trust a legitimate domain
await client.trustWebContent({ type: "domain-name", value: "example.com" });

// Check status
const status = await client.getWebContentStatus({ type: "url", value: "https://example.com" });
// Returns: { status: "blocked" | "trusted" | "unknown", actor?: Identifier<'identity'> }

// Unblock or untrust
await client.unblockWebContent({ type: "url", value: "https://phishing-site.com" });
await client.untrustWebContent({ type: "domain-name", value: "example.com" });
```

### Available Content Types

```typescript
{ type: "url", value: "https://example.com/path" }
{ type: "domain-name", value: "example.com" }
{ type: "ipv4-addr", value: "192.168.1.1" }
{ type: "ipv6-addr", value: "2001:0db8:85a3:0000:0000:8a2e:0370:7334" }
```