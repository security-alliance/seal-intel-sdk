import { Identity_Simple } from "@security-alliance/opencti-client";
import { DomainName, IPv4Addr, IPv6Addr, Url } from "@security-alliance/stix/2.1";

/**
 * @deprecated no longer supported
 */
export const BLOCKLISTED_DOMAIN_LABEL = "blocklisted domain";
/**
 * @deprecated no longer supported
 */
export const ALLOWLISTED_DOMAIN_LABEL = "allowlisted domain";

/**
 * The label to be applied when web content is considered "trusted"
 */
export const TRUSTED_WEB_CONTENT_LABEL = "trusted web content";

export type WebContentType = DomainName["type"] | Url["type"] | IPv4Addr["type"] | IPv6Addr["type"];

export type WebContent = {
    [U in WebContentType]: {
        type: U;
        value: string;
    };
}[WebContentType];

export type WebContentStatus =
    | {
          status: "unknown";
      }
    | {
          status: "blocked" | "trusted";
          actor?: Identity_Simple;
      };
