import {
    generateDomainNameId,
    generateIPv4AddrId,
    generateIPv6AddrId,
    generateUrlId,
    Identifier,
} from "@security-alliance/stix/2.1";
import { isIPv4, isIPv6 } from "node:net";
import { parse } from "tldts";
import { WebContent, WebContentType } from "./types.js";

export const parseWebContent = (value: string): WebContent | undefined => {
    if (isIPv4(value)) return { type: "ipv4-addr", value: value };
    if (isIPv6(value)) return { type: "ipv6-addr", value: value };
    try {
        new URL(value);
        return { type: "url", value: value };
    } catch {}

    const parsed = parse(value);
    if (parsed.isIcann) return { type: "domain-name", value: value };

    return undefined;
};

export const escapeSingleQuotes = (val: string) => val.replace(/'/g, `\\'`);

export const generatePatternForDomain = (domain: string) => {
    return `[domain-name:value = '${escapeSingleQuotes(domain)}']`;
};

export const generatePatternForIPv4 = (ip: string) => {
    return `[ipv4-addr:value = '${escapeSingleQuotes(ip)}']`;
};

export const generatePatternForIPv6 = (ip: string) => {
    return `[ipv6-addr:value = '${escapeSingleQuotes(ip)}']`;
};

export const generatePatternForUrl = (url: string) => {
    return `[url:value = '${escapeSingleQuotes(url)}']`;
};

export const generateObservableIdForWebContent = (content: WebContent): Identifier<WebContentType> => {
    switch (content.type) {
        case "domain-name":
            return generateDomainNameId(content);
        case "ipv4-addr":
            return generateIPv4AddrId(content);
        case "ipv6-addr":
            return generateIPv6AddrId(content);
        case "url":
            return generateUrlId(content);
    }
};

export const generatePatternForWebContent = (content: WebContent): string => {
    switch (content.type) {
        case "domain-name":
            return generatePatternForDomain(content.value);
        case "ipv4-addr":
            return generatePatternForIPv4(content.value);
        case "ipv6-addr":
            return generatePatternForIPv6(content.value);
        case "url":
            return generatePatternForUrl(content.value);
    }
};
