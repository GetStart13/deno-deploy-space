import express from "express";
import fetch from "node-fetch";
const app = express();
const port = 9080;

// API endpoint that decodes base64 content from a given URL
app.get("/convert", async (req, res) => {
    const url = req.query.url;

    if (!url) {
        return res.status(400).send("url query parameter is required");
    }

    try {
        const parser = new TrojanParser(url);
        const proxies = await parser.getProxies();
        res.send(proxies);
    } catch (error) {
        console.error("Error fetching or decoding:", error);
        res.status(500).send("Please check query parameter: url, ensure it is accessible, and base64 encode.");
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

/**
 * trojan 协议解析器
 * 入参：url，base64 编码，订阅链接
 *
 * 方法: getProxies(), 将订阅链接内容封装成 proxies 返回
 * 方法: goFetch(), 访问 url，获取订阅连接内容 proxyURLs
 * 方法: parse(), 解析订阅内容，生成节点 yaml 内容
 * 方法: convert(), 转换 proxyURLs，定义映射关系，定义节点类 class，proxyURL 有节点类型、服务、各个参数 这些内容
 * 参考: trojan://pwdpwd@server.domain.com:443?allowInsecure=1&peer=domain.com&sni=domain.com&type=tcp#示例trojan
 * 解析后: {@code { name: 示例trojan, type: trojan, server: server.domain.com, port: 443, password: pwdpwd,
 *        udp: true(default), sni: domain.com, protocol: tcp, skip-cert-verify: true(by allowInsecure, 0: false, 1: true) } }
 */
class TrojanParser {
    #url;
    constructor(url) {
        this.#url = Buffer.from(url, "base64").toString();
    }

    /**
     * 获取订阅内容
     *
     * @param {Boolean} base64Decode 是否执行 base64 解码
     * @param {Boolean} uriDecode 是否执行 uri 解码
     * @returns utf8 文本
     */
    async goFetch(base64Decode = false, uriDecode = false) {
        // 获取订阅内容
        const promise = await fetch(this.#url);
        const origin = await promise.text();
        let text = origin;
        // 如果订阅内容使用了 base64 编码，则解码
        if (base64Decode) {
            text = Buffer.from(origin, "base64").toString();
        }
        // 如果订阅内容使用了 uri 编码，则解码
        if (uriDecode) {
            text = decodeURI(text);
        }
        return text;
    }

    /**
     * 获取 proxies 配置文件
     * @returns 订阅节点解析结果
     */
    async getProxies() {
        const subscribeText = await this.goFetch(true, true);
        return this.parse(subscribeText);
    }

    /**
     * 解析订阅内容，生成 proxies yaml 内容
     *
     * @param {string} subscribeText 订阅内容
     */
    parse(subscribeText) {
        const proxies = [];
        // 一行行读取
        const drafts = subscribeText.split(/\r?\n/);
        drafts
            // 过滤换行符
            .filter(item => item.trim())
            // 转换成节点对象
            .forEach(item => {
                const proxy = this.convert(item);
                if (proxy) {
                    proxies.push(proxy);
                }
            });

        // 拼接生成 yaml
        const lines = ["proxies: \r\n"];
        proxies.forEach(proxy => lines.push("  - " + JSON.stringify(proxy) + "\r\n"));
        return lines.join("");
    }

    convert(trojanURL) {
        // trojan://pwdpwd@server.domain.com:443?allowInsecure=1&peer=domain.com&sni=domain.com&type=tcp#示例trojan
        // 检查 URL 是否合法
        const regex = /\w+:\/\/[^\s]+?\?(?:[^\s]+?=[^\s]+?)?/;

        if (!regex.test(trojanURL)) {
            return null;
        }
        // 查找第一次出现的 "?"
        const queryIndex = trojanURL.indexOf("?");

        const head = trojanURL.substring(0, queryIndex);
        // 头部处理
        const headBuffer = head.split("://");
        const type = headBuffer[0];
        const pwdSerPorBuffer = headBuffer[1].split("@");
        const password = pwdSerPorBuffer[0];
        const serverPortBuffer = pwdSerPorBuffer[1].split(":");
        const server = serverPortBuffer[0];
        const port = serverPortBuffer[1];

        const rear = trojanURL.substring(queryIndex + 1);
        // 尾部处理
        const rearBuffer = rear.split("#");
        const name = rearBuffer[1];
        const paramBuffer = rearBuffer[0].split("&");
        const paramMap = new Map();
        paramBuffer.forEach(paramPair => {
            const paramPairBuffer = paramPair.split("=");
            paramMap.set(paramPairBuffer[0], paramPairBuffer[1]);
        });

        return new Trojan({
            name: name,
            type: type,
            server: server,
            port: port,
            password: password,
            sni: paramMap.get("sni"),
            skipCertVerify: paramMap.get("allowInsecure") ? true : false,
        });
    }
}

/**
 * Trojan 节点类
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
}
