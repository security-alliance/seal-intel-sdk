import { generateIdentityId } from "@security-alliance/opencti-client/stix";
import { describe, it } from "node:test";
import { randomInt, randomUUID } from "node:crypto";
import assert from "node:assert";
import { WebContentClient } from "../src/index.js";
import { OpenCTIClient } from "@security-alliance/opencti-client";
import { WebContent, WebContentStatus } from "../src/web-content/types.js";
import { Identifier } from "@security-alliance/stix/2.1";

const SEAL_IDENTITY = generateIdentityId({
    name: "SEAL",
    identity_class: "organization",
});

const ACME_IDENTITY = generateIdentityId({
    name: "ACME",
    identity_class: "organization",
});

const runTestsForWebContent = (type: string, client: WebContentClient, generator: () => WebContent) => {
    const checkStatus = (actual: WebContentStatus, expected: { status: string; actor?: Identifier<"identity"> }) => {
        assert.equal(actual.status, expected.status);
        if (actual.status !== "unknown") {
            assert.equal(actual.actor?.standard_id, expected.actor);
        }
    };

    describe(type, () => {
        it("should block successfully", async () => {
            const content = generator();

            checkStatus(await client.getWebContentStatus(content), { status: "unknown" });

            await client.blockWebContent(content);
            checkStatus(await client.getWebContentStatus(content), {
                status: "blocked",
                actor: SEAL_IDENTITY,
            });

            await client.unblockWebContent(content);
            checkStatus(await client.getWebContentStatus(content), { status: "unknown" });

            await client.blockWebContent(content, ACME_IDENTITY);
            checkStatus(await client.getWebContentStatus(content), {
                status: "blocked",
                actor: ACME_IDENTITY,
            });
        });

        it("should trust successfully", async () => {
            const content = generator();

            checkStatus(await client.getWebContentStatus(content), { status: "unknown" });

            await client.trustWebContent(content);
            checkStatus(await client.getWebContentStatus(content), {
                status: "trusted",
                actor: SEAL_IDENTITY,
            });

            await client.untrustWebContent(content);
            checkStatus(await client.getWebContentStatus(content), { status: "unknown" });

            await client.trustWebContent(content, ACME_IDENTITY);
            checkStatus(await client.getWebContentStatus(content), {
                status: "trusted",
                actor: ACME_IDENTITY,
            });
        });

        it("should block-trust-block successfully", async () => {
            const content = generator();

            checkStatus(await client.getWebContentStatus(content), { status: "unknown" });

            await client.blockWebContent(content);
            checkStatus(await client.getWebContentStatus(content), {
                status: "blocked",
                actor: SEAL_IDENTITY,
            });

            await client.trustWebContent(content, ACME_IDENTITY);
            checkStatus(await client.getWebContentStatus(content), {
                status: "trusted",
                actor: ACME_IDENTITY,
            });

            await client.blockWebContent(content, ACME_IDENTITY);
            checkStatus(await client.getWebContentStatus(content), {
                status: "blocked",
                actor: ACME_IDENTITY,
            });

            await client.trustWebContent(content);
            checkStatus(await client.getWebContentStatus(content), {
                status: "trusted",
                actor: SEAL_IDENTITY,
            });
        });
    });
};

describe("Web Content", () => {
    const client = new WebContentClient(
        new OpenCTIClient("http://localhost:8080", "00000000-0000-0000-0000-000000000000"),
        SEAL_IDENTITY,
    );

    runTestsForWebContent("domains", client, () => {
        return { type: "domain-name", value: `${randomUUID()}.invalid` };
    });
    // runTestsForWebContent("ipv4-addr", client, () => {
    //     return {
    //         type: "ipv4-addr",
    //         value: `${randomInt(255)}.${randomInt(255)}.${randomInt(255)}.${randomInt(255)}`,
    //     };
    // });
    // runTestsForWebContent("ipv6-addr", client, () => {
    //     const characters = "0123456789abcdef";
    //     const ipv6 = Array(8)
    //         .fill(0)
    //         .map(() =>
    //             Array(4)
    //                 .fill(0)
    //                 .map((v) => characters[randomInt(characters.length)])
    //                 .join(""),
    //         )
    //         .join(":");
    //     return { type: "ipv6-addr", value: ipv6 };
    // });
    // runTestsForWebContent("urls", client, () => {
    //     return {
    //         type: "url",
    //         value: `https://${randomUUID()}.invalid/path/to/content`,
    //     };
    // });
    // runTestsForWebContent("ipfs", client, () => {
    //     return { type: "url", value: `ipfs://${randomUUID()}` };
    // });
});
