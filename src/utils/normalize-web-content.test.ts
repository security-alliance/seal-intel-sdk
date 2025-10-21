import assert from "node:assert";
import { describe, it } from "node:test";
import { normalizeWebContent } from "./normalize-web-content.js";
import { WebContent } from "../web-content/types.js";

describe("normalizeWebContent", () => {
    it("should keep non-URL types unchanged", () => {
        const cases: WebContent[] = [
            { type: "domain-name", value: "example.com" },
            { type: "domain-name", value: "sub.example.com" },
            { type: "ipv4-addr", value: "192.168.1.1" },
            { type: "ipv6-addr", value: "2001:0db8:85a3::8a2e:0370:7334" },
        ];
        
        cases.forEach(content => {
            assert.deepEqual(normalizeWebContent(content), content);
        });
    });

    it("should convert http(s) URLs without paths to domain-name", () => {
        const cases = [
            { url: "https://example.com", expected: "example.com" },
            { url: "https://example.com/", expected: "example.com" },
            { url: "http://example.com", expected: "example.com" },
            { url: "https://sub.example.com", expected: "sub.example.com" },
            { url: "https://example.com:8080", expected: "example.com" },
        ];
        
        cases.forEach(({ url, expected }) => {
            const result = normalizeWebContent({ type: "url", value: url });
            assert.equal(result.type, "domain-name");
            assert.equal(result.value, expected);
        });
    });

    it("should keep URLs with paths unchanged", () => {
        const urls = [
            "https://llama.airdrop-defi.io/claim",
            "http://example.com/path/to/resource",
            "https://example.com/path?query=value",
            "https://example.com/path#section",
            "https://example.com:8080/path",
        ];
        
        urls.forEach(url => {
            const content: WebContent = { type: "url", value: url };
            assert.deepEqual(normalizeWebContent(content), content);
        });
    });

    it("should keep non-http(s) URLs unchanged", () => {
        const urls = [
            "ipfs://QmXyz123",
            "ftp://files.example.com/file.txt",
            "custom://resource",
        ];
        
        urls.forEach(url => {
            const content: WebContent = { type: "url", value: url };
            assert.deepEqual(normalizeWebContent(content), content);
        });
    });

    it("should not normalize non-ICANN hostnames", () => {
        const urls = [
            "https://192.168.1.1/path",  // IP address
            "https://localhost/path",     // localhost
            "https://test.invalid/path",  // special use TLD
        ];
        
        urls.forEach(url => {
            const content: WebContent = { type: "url", value: url };
            assert.deepEqual(normalizeWebContent(content), content);
        });
    });

    it("should preserve subdomains when normalizing", () => {
        const result = normalizeWebContent({ type: "url", value: "https://phishing.github.io" });
        assert.equal(result.type, "domain-name");
        assert.equal(result.value, "phishing.github.io");
    });
});

