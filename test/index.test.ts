import { generateIdentityId } from "@security-alliance/opencti-client/stix";
import { describe, it } from "node:test";
import { randomInt, randomUUID } from "node:crypto";
import assert from "node:assert";
import { WebContentClient } from "../src/index.js";
import { OpenCTIClient } from "@security-alliance/opencti-client";
import { WebContent } from "../src/web-content/types.js";

const SEAL_IDENTITY = generateIdentityId({
    name: "SEAL",
    identity_class: "organization",
});

const runTestsForWebContent = (type: string, client: WebContentClient, generator: () => WebContent) => {
    describe(type, () => {
        it("should block successfully", async () => {
            const content = generator();

            assert.equal(await client.getWebContentStatus(content), "unknown");

            await client.blockWebContent(content, SEAL_IDENTITY);
            assert.equal(await client.getWebContentStatus(content), "blocked");

            await client.unblockWebContent(content);
            assert.equal(await client.getWebContentStatus(content), "unknown");

            await client.blockWebContent(content, SEAL_IDENTITY);
            assert.equal(await client.getWebContentStatus(content), "blocked");
        });

        it("should trust successfully", async () => {
            const content = generator();

            assert.equal(await client.getWebContentStatus(content), "unknown");

            await client.trustWebContent(content, SEAL_IDENTITY);
            assert.equal(await client.getWebContentStatus(content), "trusted");

            await client.untrustWebContent(content);
            assert.equal(await client.getWebContentStatus(content), "unknown");

            await client.trustWebContent(content, SEAL_IDENTITY);
            assert.equal(await client.getWebContentStatus(content), "trusted");
        });

        it("should block-trust-block successfully", async () => {
            const content = generator();

            assert.equal(await client.getWebContentStatus(content), "unknown");

            await client.blockWebContent(content, SEAL_IDENTITY);
            assert.equal(await client.getWebContentStatus(content), "blocked");

            await client.trustWebContent(content, SEAL_IDENTITY);
            assert.equal(await client.getWebContentStatus(content), "trusted");

            await client.blockWebContent(content, SEAL_IDENTITY);
            assert.equal(await client.getWebContentStatus(content), "blocked");
        });
    });
};

describe("Web Content", () => {
    const client = new WebContentClient(
        new OpenCTIClient("http://localhost:8080", "00000000-0000-0000-0000-000000000000"),
    );

    runTestsForWebContent("domains", client, () => {
        return { type: "domain-name", value: `${randomUUID()}.invalid` };
    });
    runTestsForWebContent("ipv4-addr", client, () => {
        return {
            type: "ipv4-addr",
            value: `${randomInt(255)}.${randomInt(255)}.${randomInt(255)}.${randomInt(255)}`,
        };
    });
    runTestsForWebContent("ipv6-addr", client, () => {
        const characters = "0123456789abcdef";
        const ipv6 = Array(8)
            .fill(0)
            .map(() =>
                Array(4)
                    .fill(0)
                    .map((v) => characters[randomInt(characters.length)])
                    .join(""),
            )
            .join(":");
        return { type: "ipv6-addr", value: ipv6 };
    });
    runTestsForWebContent("urls", client, () => {
        return {
            type: "url",
            value: `https://${randomUUID()}.invalid/path/to/content`,
        };
    });
    runTestsForWebContent("ipfs", client, () => {
        return { type: "url", value: `ipfs://${randomUUID()}` };
    });
});
