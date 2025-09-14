import {
    Indicator_All,
    Label_Simple,
    MutationStixCyberObservableAddArgs,
    OpenCTIClient,
    StixCyberObservable_All,
} from "@security-alliance/opencti-client";
import { generateIndicatorId, generateLabelId, MARKING_TLP_CLEAR } from "@security-alliance/opencti-client/stix";
import { Identifier } from "@security-alliance/stix/2.1";
import {
    ALLOWLISTED_DOMAIN_LABEL,
    BLOCKLISTED_DOMAIN_LABEL,
    TRUSTED_WEB_CONTENT_LABEL,
    WebContent,
    WebContentStatus,
} from "./types.js";
import { generateObservableIdForWebContent, generatePatternForWebContent } from "./utils.js";

type CreateOrUpdateProperties = {
    creator: Identifier<"identity">;
    addLabels?: string[];
    removeLabels?: string[];
};

const toOpenCTIObservableType = (type: "domain-name" | "ipv4-addr" | "ipv6-addr" | "url") => {
    switch (type) {
        case "domain-name":
            return "Domain-Name";
        case "ipv4-addr":
            return "IPv4-Addr";
        case "ipv6-addr":
            return "IPv6-Addr";
        case "url":
            return "Url";
    }
};

const ONE_YEAR_IN_MILLIS = 1000 * 60 * 60 * 24 * 365;

export class WebContentClient {
    private client: OpenCTIClient;
    private defaultIdentity: Identifier<"identity">;

    constructor(client: OpenCTIClient, defaultIdentity: Identifier<"identity">) {
        this.client = client;
        this.defaultIdentity = defaultIdentity;
    }

    private async createOrUpdateIndicator(
        content: WebContent,
        props: CreateOrUpdateProperties,

        observable: StixCyberObservable_All,
    ): Promise<Indicator_All> {
        const now = Date.now();

        const existingIndicator = await this.client.indicator({
            id: generateIndicatorId({ pattern: generatePatternForWebContent(content) }),
        });
        if (existingIndicator) {
            return (await this.client.indicatorFieldPatch({
                id: existingIndicator.id,
                input: [
                    { key: "valid_from", value: [new Date(now)] },
                    { key: "valid_until", value: [new Date(now + ONE_YEAR_IN_MILLIS)] },
                    { key: "x_opencti_score", value: [100] },
                    { key: "revoked", value: [false] },
                    { key: "createdBy", value: [props.creator] },
                ],
            }))!;
        }

        const indicator = (await this.client.indicatorAdd({
            input: {
                createdBy: props.creator,
                name: content.value,
                pattern_type: "stix",
                pattern: generatePatternForWebContent(content),
                x_opencti_main_observable_type: toOpenCTIObservableType(content.type),
                x_opencti_score: 100,
                valid_from: new Date(now),
                valid_until: new Date(now + ONE_YEAR_IN_MILLIS),
            },
        }))!;

        await this.client.stixCoreRelationshipAdd({
            input: {
                fromId: indicator?.id,
                toId: observable.id,
                relationship_type: "based-on",
            },
        });

        return indicator;
    }

    private async createOrUpdateObservable(
        content: WebContent,
        props: CreateOrUpdateProperties,
    ): Promise<StixCyberObservable_All> {
        const existingObservable = await this.client.stixCyberObservable({
            id: generateObservableIdForWebContent(content),
        });
        if (existingObservable) return await this.updateObservable(existingObservable, props);
        else return await this.createObservable(content, props);
    }

    private async createObservable(
        content: WebContent,
        props: CreateOrUpdateProperties,
    ): Promise<StixCyberObservable_All> {
        const commonArgs: Partial<MutationStixCyberObservableAddArgs> = {
            createdBy: props.creator,
            objectLabel: props.addLabels,
            objectMarking: [MARKING_TLP_CLEAR],
        };
        switch (content.type) {
            case "domain-name":
                return (await this.client.stixCyberObservableAddTyped("Domain-Name", {
                    ...commonArgs,
                    DomainName: { value: content.value },
                }))!;
            case "ipv4-addr":
                return (await this.client.stixCyberObservableAddTyped("IPv4-Addr", {
                    ...commonArgs,
                    IPv4Addr: { value: content.value },
                }))!;
            case "ipv6-addr":
                return (await this.client.stixCyberObservableAddTyped("IPv6-Addr", {
                    ...commonArgs,
                    IPv6Addr: { value: content.value },
                }))!;
            case "url":
                const url = new URL(content.value);

                const urlObservable = (await this.client.stixCyberObservableAddTyped("Url", {
                    ...commonArgs,
                    Url: { value: content.value },
                }))!;

                if (url.protocol === "http:" || url.protocol === "https:") {
                    const domainObservable = await this.createOrUpdateObservable(
                        { type: "domain-name", value: url.hostname },
                        { creator: props.creator },
                    );
                    await this.client.stixCoreRelationshipAdd({
                        input: {
                            fromId: urlObservable.id,
                            toId: domainObservable.id,
                            relationship_type: "related-to",
                        },
                    });
                }

                return urlObservable;
        }
    }

    private async updateObservable(
        observable: StixCyberObservable_All,
        props: CreateOrUpdateProperties,
    ): Promise<StixCyberObservable_All> {
        const labelsToAdd = (props.addLabels ?? []).filter((l) => this.findLabel(observable, l) === undefined);
        const labelsToRemove = (props.removeLabels ?? []).filter((l) => this.findLabel(observable, l) !== undefined);

        if (labelsToAdd.length > 0 || labelsToRemove.length > 0) {
            observable = (await this.client.stixCyberObservableEdit_fieldPatch(
                {
                    id: observable.id,
                },
                {
                    input: [
                        { key: "createdBy", value: [props.creator] },
                        {
                            key: "objectLabel",
                            value: [
                                ...(observable.objectLabel ?? [])
                                    .filter((l) => !l.value || !(props.removeLabels ?? []).includes(l.value))
                                    .map((v) => v.standard_id),
                                ...(props.addLabels ?? []).map((l) => generateLabelId({ value: l })),
                            ],
                        },
                    ],
                },
            ))!;
        }
        return observable;
    }

    private findLabel(observable: StixCyberObservable_All, labelName: string): Label_Simple | undefined {
        return observable.objectLabel?.find((label) => label.value === labelName);
    }

    public async getWebContentStatus(content: WebContent): Promise<WebContentStatus> {
        const [observable, indicator] = await Promise.all([
            this.client.stixCyberObservable({ id: generateObservableIdForWebContent(content) }),
            this.client.indicator({ id: generateIndicatorId({ pattern: generatePatternForWebContent(content) }) }),
        ]);

        if (observable) {
            if (this.findLabel(observable, TRUSTED_WEB_CONTENT_LABEL) !== undefined)
                return { status: "trusted", actor: observable.createdBy ?? undefined };

            if (this.findLabel(observable, ALLOWLISTED_DOMAIN_LABEL) !== undefined)
                return { status: "trusted", actor: observable.createdBy ?? undefined };

            if (this.findLabel(observable, BLOCKLISTED_DOMAIN_LABEL) !== undefined)
                return { status: "blocked", actor: observable.createdBy ?? undefined };
        }

        if (!indicator || indicator.revoked) {
            return { status: "unknown" };
        }

        return { status: "blocked", actor: indicator.createdBy ?? undefined };
    }

    public async blockWebContent(content: WebContent, creator?: Identifier<"identity">): Promise<Indicator_All> {
        creator ??= this.defaultIdentity;

        const observable = await this.createOrUpdateObservable(content, {
            creator: creator,
            removeLabels: [ALLOWLISTED_DOMAIN_LABEL, BLOCKLISTED_DOMAIN_LABEL, TRUSTED_WEB_CONTENT_LABEL],
        });

        const indicator = await this.createOrUpdateIndicator(
            content,
            {
                creator: creator,
            },
            observable,
        );

        return indicator;
    }

    public async unblockWebContent(
        content: WebContent,
        creator?: Identifier<"identity">,
    ): Promise<Indicator_All | undefined> {
        creator ??= this.defaultIdentity;

        const observable = await this.client.stixCyberObservable({ id: generateObservableIdForWebContent(content) });
        if (observable) {
            await this.updateObservable(observable, {
                creator: creator,
                removeLabels: [ALLOWLISTED_DOMAIN_LABEL, BLOCKLISTED_DOMAIN_LABEL],
            });
        }

        const indicator = await this.client.indicator({
            id: generateIndicatorId({ pattern: generatePatternForWebContent(content) }),
        });
        if (!indicator) return undefined;
        if (indicator.revoked) return indicator;

        return (await this.client.indicatorFieldPatch({
            id: indicator.id,
            input: [
                { key: "x_opencti_score", value: [0] },
                { key: "revoked", value: [true] },
            ],
        }))!;
    }

    public async trustWebContent(
        content: WebContent,
        creator?: Identifier<"identity">,
    ): Promise<StixCyberObservable_All> {
        creator ??= this.defaultIdentity;

        await this.unblockWebContent(content, creator);

        return await this.createOrUpdateObservable(content, {
            creator: creator,
            addLabels: [TRUSTED_WEB_CONTENT_LABEL],
            removeLabels: [ALLOWLISTED_DOMAIN_LABEL, BLOCKLISTED_DOMAIN_LABEL],
        });
    }

    public async untrustWebContent(
        content: WebContent,
        creator?: Identifier<"identity">,
    ): Promise<StixCyberObservable_All | undefined> {
        creator ??= this.defaultIdentity;

        const observable = await this.client.stixCyberObservable({ id: generateObservableIdForWebContent(content) });
        if (!observable) return undefined;

        return await this.updateObservable(observable, {
            creator: creator,
            removeLabels: [BLOCKLISTED_DOMAIN_LABEL, ALLOWLISTED_DOMAIN_LABEL, TRUSTED_WEB_CONTENT_LABEL],
        });
    }
}
