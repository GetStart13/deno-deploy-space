// deploy on deno
Deno.serve(async (req: Request) => {
    try {
        const parameters = req.url.split("?")[1];
        const paramObject = {};
        parameters.split("&").forEach(paramPair => {
            const paramBuffer = paramPair.split("=");
            paramObject[paramBuffer[0]] = paramBuffer[1];
        });
        const parser = new TrojanParser(paramObject.url);
        const yaml = await parser.getProxies();

        return new Response(yaml);
    } catch (error) {
        return new Response("Please check query parameter: url, ensure it is accessible, and base64 encode.", { status: 500 });
    }
});
class TrojanParser {
    #url;
    constructor(url) {
        this.#url = atob(url);
    }

    async goFetch(base64Decode = false, uriDecode = false) {
        const promise = await fetch(this.#url);
        const origin = await promise.text();
        let text = origin;

        if (base64Decode) {
            text = atob(origin);
        }

        if (uriDecode) {
            text = decodeURI(text);
        }
        return text;
    }

    async getProxies() {
        const subscribeText = await this.goFetch(true, true);
        return this.parse(subscribeText);
    }

    parse(subscribeText) {
        const proxies = [];

        const drafts = subscribeText.split(/\r?\n/);
        drafts
            .filter(item => item.trim())
            .forEach(item => {
                const proxy = this.convert(item);
                if (proxy) {
                    proxies.push(proxy);
                }
            });

        const lines = ["proxies: \r\n"];
        proxies.forEach(proxy => lines.push("  - " + JSON.stringify(proxy) + "\r\n"));
        return lines.join("");
    }

    convert(trojanURL) {
        const regex = /\w+:\/\/[^\s]+?\?(?:[^\s]+?=[^\s]+?)?/;
        if (!regex.test(trojanURL)) {
            return null;
        }
        const queryIndex = trojanURL.indexOf("?");

        const head = trojanURL.substring(0, queryIndex);
        //
        const headBuffer = head.split("://");
        const type = headBuffer[0];
        const pwdSerPorBuffer = headBuffer[1].split("@");
        const password = pwdSerPorBuffer[0];
        const serverPortBuffer = pwdSerPorBuffer[1].split(":");
        const server = serverPortBuffer[0];
        const port = serverPortBuffer[1];

        const rear = trojanURL.substring(queryIndex + 1);
        //
        const rearBuffer = rear.split("#");
        const name = rearBuffer[1];
        const paramBuffer = rearBuffer[0].split("&");
        const paramObject = {};
        paramBuffer.forEach(paramPair => {
            const paramPairBuffer = paramPair.split("=");
            const mapping = Trojan.mapping[paramPairBuffer[0]];
            if (mapping) {
                Object.assign(paramObject, mapping(paramPairBuffer[1]));
            }
        });

        return new Trojan({
            name: name,
            type: type,
            server: server,
            port: port,
            password: password,
            ...paramObject,
        });
    }
}

/**
 * Trojan
 */
class Trojan {
    constructor({ name, type, interfaceName, routingMark, server, port, password, udp, sni, alpn, skipCertVerify }) {
        this.name = name;
        this.type = type;
        this["interface-name"] = interfaceName;
        this["routing-mark"] = routingMark;
        this.server = server;
        this.port = parseInt(port);
        this.password = password;
        this.udp = udp ?? true;
        this.sni = sni;
        this.alpn = alpn;
        this["skip-cert-verify"] = skipCertVerify ?? true;
    }
    
    static mapping = {
        allowInsecure: value => {
            return { skipCertVerify: parseInt(value) == 1 ? true : false };
        },
        sni: value => {
            return { sni: value };
        },
    };
}
