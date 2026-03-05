import { parse } from "tldts";
import { WebContent } from "../web-content/types.js";

/**
 * Normalizes web content to handle cases where a domain is accidentally reported as a URL.
 * Only converts http/https URLs to domain-name when the URL has no path (empty or just "/").
 * URLs with actual paths are kept as-is since the user likely wants to block that specific URL.
 * Preserves the full hostname including subdomains to avoid blocking legitimate parent domains.
 * 
 * Examples:
 * - "https://example.com" -> { type: "domain-name", value: "example.com" }
 * - "https://example.com/" -> { type: "domain-name", value: "example.com" }
 * - "https://phishing.github.io" -> { type: "domain-name", value: "phishing.github.io" } (keeps subdomain)
 * - "https://example.com/path" -> { type: "url", value: "https://example.com/path" } (kept as URL)
 * - "https://llama.airdrop-defi.io/claim" -> { type: "url", value: "https://llama.airdrop-defi.io/claim" } (kept as URL)
 * - "ipfs://xyz" -> { type: "url", value: "ipfs://xyz" } (kept as URL)
 */
export const normalizeWebContent = (content: WebContent): WebContent => {
    if (content.type !== "url") {
        return content;
    }

    try {
        const url = new URL(content.value);

        if (url.protocol === "http:" || url.protocol === "https:") {
            // Only normalize if path is empty or just "/"
            const hasPath = url.pathname !== "" && url.pathname !== "/";
            
            if (!hasPath) {
                const hostname = url.hostname;
                const parsed = parse(hostname);

                // isIcann = true for ICANN-managed public domains (.com, .org, .io, etc.)
                // Excludes special use TLDs (.local, .invalid), localhost, and IP addresses
                // Use hostname (not domain) to preserve subdomains and avoid blocking legitimate parent domains
                if (parsed.isIcann && parsed.hostname) {
                    return { type: "domain-name", value: parsed.hostname };
                }
            }
        }
    } catch {
        // If URL parsing fails, return as-is
    }

    return content;
};

