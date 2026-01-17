#!/usr/bin/env node

const express = require("express");
const axios = require("axios");
const os = require("os");
const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
const { exec: execAsync } = require("child_process");
const { execSync } = require("child_process");

const execPromise = promisify(execAsync);
const crypto = require("crypto");



// ==================== 系统配置加载器 ====================
function loadSystemConfig() {
  return {
    uploadApiUrl: process.env.UPLOAD_URL || "",
    projectBaseUrl: process.env.PROJECT_URL || "",
    enableAutoKeepAlive: process.env.AUTO_ACCESS !== "false",
    storagePath: process.env.FILE_PATH || "./tmp",
    subscriptionRouteName: process.env.SUB_PATH || "sub",
    httpPort: process.env.SERVER_PORT || process.env.PORT || 3000,
    clientId: process.env.UUID || "aca19852-0a9b-452c-ab61-b1a4c8ea806b",
    monitorServerHost: process.env.NEZHA_SERVER || "",
    monitorServerPort: process.env.NEZHA_PORT || "",
    monitorClientKey: process.env.NEZHA_KEY || "",
    tunnelDomainFixed: process.env.ARGO_DOMAIN || "",
    tunnelAuthData: process.env.ARGO_AUTH || "",
    tunnelLocalPort: process.env.ARGO_PORT || 8001,
    cdnOptimizationDomain: process.env.CFIP || "www.amazon.com",
    cdnOptimizationPort: process.env.CFPORT || 443,
    nodeName: process.env.NAME || "",
  };
}

// ==================== 存储操作服务 ====================
class StorageService {
  constructor(storagePath) {
    this.rootPath = storagePath;
    this.initStorage();
  }

  initStorage() {
    if (!fs.existsSync(this.rootPath)) {
      fs.mkdirSync(this.rootPath, { recursive: true });
      console.log(`✓ 创建存储目录: ${this.rootPath}`);
    }
  }

  createRandomFileName(size = 6) {
    const alphabet = "abcdefghijklmnopqrstuvwxyz";
    return Array.from({ length: size }, () =>
      alphabet.charAt(Math.floor(Math.random() * alphabet.length))
    ).join("");
  }

  resolvePath(filename) {
    return path.join(this.rootPath, filename);
  }

  hasFile(filepath) {
    return fs.existsSync(filepath);
  }

  readFileContent(filepath, encoding = "utf-8") {
    try {
      return fs.readFileSync(filepath, encoding);
    } catch (err) {
      console.error(`读取文件失败: ${filepath}`, err.message);
      return null;
    }
  }

  persistContent(filepath, data) {
    try {
      fs.writeFileSync(filepath, data);
      console.log(`✓ 文件已保存: ${path.basename(filepath)}`);
    } catch (err) {
      console.error(`写入文件失败: ${filepath}`, err.message);
    }
  }

  removeFiles(filepaths) {
    filepaths.forEach((filepath) => {
      try {
        if (fs.existsSync(filepath)) {
          fs.unlinkSync(filepath);
        }
      } catch (err) {
        // 忽略错误
      }
    });
  }

  purgeDirectory() {
    try {
      const entries = fs.readdirSync(this.rootPath);
      entries.forEach((entry) => {
        const entryPath = path.join(this.rootPath, entry);
        const stat = fs.statSync(entryPath);
        if (stat.isFile()) {
          fs.unlinkSync(entryPath);
        }
      });
      console.log("✓ 存储目录已清理");
    } catch (err) {
      console.error("清理存储失败:", err.message);
    }
  }
}

// ==================== 配置构建引擎 ====================
class ConfigurationEngine {
  static buildXrayProtocolConfig(clientId, listeningPort) {
    return {
      log: {
        access: "/dev/null",
        error: "/dev/null",
        loglevel: "none",
      },
      inbounds: [
        // 传统 VLESS over TLS (主要方案)
        {
          port: listeningPort,
          protocol: "vless",
          settings: {
            clients: [
              {
                id: clientId,
              },
            ],
            decryption: "none",
          },
          streamSettings: {
            network: "tcp",
            security: "tls",
            tlsSettings: {
              minVersion: "1.3",
              cipherSuites: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
              fingerprint: "firefox",
            },
          },
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls", "quic"],
            metadataOnly: false,
          },
        },
        // VLESS over TLS with WebSocket (CDN 友好)
        {
          port: 3002,
          listen: "127.0.0.1",
          protocol: "vless",
          settings: {
            clients: [
              {
                id: clientId,
                level: 0,
              },
            ],
            decryption: "none",
          },
          streamSettings: {
            network: "ws",
            security: "tls",
            tlsSettings: {
              minVersion: "1.3",
              fingerprint: "firefox",
            },
            wsSettings: {
              path: "/vless-reality",
              headers: {
                "User-Agent":
                  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
              },
            },
          },
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls", "quic"],
            metadataOnly: false,
          },
        },
        // VMess over TLS
        {
          port: 3003,
          listen: "127.0.0.1",
          protocol: "vmess",
          settings: {
            clients: [
              {
                id: clientId,
                alterId: 0,
              },
            ],
          },
          streamSettings: {
            network: "ws",
            security: "tls",
            tlsSettings: {
              minVersion: "1.3",
              fingerprint: "firefox",
            },
            wsSettings: {
              path: "/vmess-reality",
              headers: {
                "User-Agent":
                  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
              },
            },
          },
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls", "quic"],
            metadataOnly: false,
          },
        },
        // Trojan over TLS
        {
          port: 3004,
          listen: "127.0.0.1",
          protocol: "trojan",
          settings: {
            clients: [
              {
                password: clientId,
              },
            ],
          },
          streamSettings: {
            network: "ws",
            security: "tls",
            tlsSettings: {
              minVersion: "1.3",
              fingerprint: "firefox",
            },
            wsSettings: {
              path: "/trojan-reality",
              headers: {
                "User-Agent":
                  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
              },
            },
          },
          sniffing: {
            enabled: true,
            destOverride: ["http", "tls", "quic"],
            metadataOnly: false,
          },
        },
      ],
      dns: {
        servers: ["https+local://1.1.1.1/dns-query"],
      },
      outbounds: [
        {
          protocol: "freedom",
          tag: "direct",
          settings: {
            domainStrategy: "UseIP",
          },
        },
        {
          protocol: "blackhole",
          tag: "block",
        },
      ],
      routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [
          {
            type: "field",
            outboundTag: "block",
            protocol: ["bittorrent"],
          },
        ],
      },
    };
  }

  static buildMonitoringAgentConfig(authToken, monitoringHost, clientId) {
    const portNumber = monitoringHost.includes(":")
      ? monitoringHost.split(":").pop()
      : "";
    const securePorts = ["443", "8443", "2096", "2087", "2083", "2053"];
    const useTls = securePorts.includes(portNumber) ? "true" : "false";

    return `client_secret: ${authToken}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${monitoringHost}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${useTls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${clientId}`;
  }

  static buildTunnelConfiguration(authSecret, listeningPort, tunnelDomain, configDirPath) {
    if (!authSecret.includes("TunnelSecret")) {
      return null;
    }

    const extractedId = authSecret.split('"')[11];
    return `tunnel: ${extractedId}
credentials-file: ${configDirPath}/tunnel.json
protocol: http2

ingress:
  - hostname: ${tunnelDomain}
    service: http://localhost:${listeningPort}
    originRequest:
      noTLSVerify: true
  - service: http_status:404`;
  }
}

// ==================== 文件获取服务 ====================
class FetchingService {
  static detectCpuArchitecture() {
    const sysArch = os.arch();
    return ["arm", "arm64", "aarch64"].includes(sysArch) ? "arm" : "amd";
  }

  static resolveDownloadTargets(cpuArch, hasMonitoring, monitoringPortConfig) {
    const downloadBase =
      cpuArch === "arm"
        ? "https://arm64.ssss.nyc.mn"
        : "https://amd64.ssss.nyc.mn";

    const targets = [
      { identifier: "web", location: `${downloadBase}/web` },
      { identifier: "bot", location: `${downloadBase}/bot` },
    ];

    if (hasMonitoring) {
      const monitorType = monitoringPortConfig ? "agent" : "v1";
      targets.unshift({
        identifier: monitorType,
        location: `${downloadBase}/${monitorType}`,
      });
    }

    return targets;
  }

  static async downloadResource(resourceUrl, outputPath) {
    try {
      const response = await axios({
        method: "get",
        url: resourceUrl,
        responseType: "stream",
        timeout: 30000,
      });

      return new Promise((resolve, reject) => {
        const outputStream = fs.createWriteStream(outputPath);
        response.data.pipe(outputStream);

        outputStream.on("finish", () => {
          console.log(`✓ 下载完成: ${path.basename(outputPath)}`);
          resolve(outputPath);
        });

        outputStream.on("error", (err) => {
          fs.unlink(outputPath, () => {});
          reject(
            new Error(
              `下载失败: ${path.basename(outputPath)} - ${err.message}`
            )
          );
        });
      });
    } catch (err) {
      throw new Error(`获取资源失败 ${resourceUrl}: ${err.message}`);
    }
  }

  static async downloadMultipleResources(resources) {
    return Promise.all(
      resources.map((resource) =>
        this.downloadResource(resource.location, resource.path).catch(
          (err) => {
            console.error(err.message);
            return null;
          }
        )
      )
    );
  }

  static configureFilePermissions(filepaths) {
    filepaths.forEach((filepath) => {
      if (fs.existsSync(filepath)) {
        fs.chmod(filepath, 0o775, (err) => {
          if (err) {
            console.error(`权限设置失败: ${filepath}`, err.message);
          } else {
            console.log(`✓ 权限已设置: ${path.basename(filepath)}`);
          }
        });
      }
    });
  }
}

// ==================== 进程执行器 ====================
class ProcessExecutor {
  static async runCommand(cmdString) {
    try {
      const { stdout, stderr } = await execPromise(cmdString);
      if (stderr) {
        console.warn(`命令警告: ${stderr}`);
      }
      return { completed: true, result: stdout };
    } catch (error) {
      console.error(`命令执行失败: ${error.message}`);
      return { completed: false, error: error.message };
    }
  }

  static async startMonitoringV0(executablePath, hostAddress, portNumber, secretKey, onWindows) {
    const securePortList = ["443", "8443", "2096", "2087", "2083", "2053"];
    const tlsRequired = securePortList.includes(portNumber) ? "--tls" : "";
    const cmd = `nohup ${executablePath} -s ${hostAddress}:${portNumber} -p ${secretKey} ${tlsRequired} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;

    return this.runCommand(cmd);
  }

  static async startMonitoringV1(executablePath, configFilePath, onWindows) {
    const cmd = `nohup ${executablePath} -c "${configFilePath}" >/dev/null 2>&1 &`;
    return this.runCommand(cmd);
  }

  static async startXrayProxy(executablePath, configFilePath, onWindows) {
    const cmd = `nohup ${executablePath} -c ${configFilePath} >/dev/null 2>&1 &`;
    return this.runCommand(cmd);
  }

  static async startCloudflareClient(executablePath, commandArgs, onWindows) {
    const cmd = `nohup ${executablePath} ${commandArgs} >/dev/null 2>&1 &`;
    return this.runCommand(cmd);
  }

  static async terminateProcess(processName, onWindows) {
    const cmd = onWindows
      ? `taskkill /f /im ${processName}.exe > nul 2>&1`
      : `pkill -f "[${processName.charAt(0)}]${processName.substring(1)}" > /dev/null 2>&1`;

    return this.runCommand(cmd);
  }
}

// ==================== 节点信息处理器 ====================
class NodeInformationHandler {
  static async removeOldNodes(apiEndpoint, subscriptionPath, storage) {
    try {
      if (!apiEndpoint || !storage.hasFile(subscriptionPath)) {
        return;
      }

      const savedContent = storage.readFileContent(subscriptionPath);
      if (!savedContent) return;

      const decodedContent = Buffer.from(savedContent, "base64").toString(
        "utf-8"
      );
      const nodeLines = decodedContent
        .split("\n")
        .filter((line) => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));

      if (nodeLines.length === 0) return;

      await axios.post(`${apiEndpoint}/api/delete-nodes`, JSON.stringify({ nodes: nodeLines }), {
        headers: { "Content-Type": "application/json" },
      });
      console.log("✓ 旧节点已移除");
    } catch (err) {
      console.error("移除节点失败:", err.message);
    }
  }

  static async persistNewNodes(apiEndpoint, baseProjectUrl, subscriptionPath, storage, subPathRoute) {
    try {
      if (apiEndpoint && baseProjectUrl) {
        const subscUrl = `${baseProjectUrl}/${subPathRoute}`;
        const uploadRes = await axios.post(
          `${apiEndpoint}/api/add-subscriptions`,
          { subscription: [subscUrl] },
          { headers: { "Content-Type": "application/json" } }
        );

        if (uploadRes.status === 200) {
          console.log("✓ 订阅已上传");
          return;
        }
      }

      if (apiEndpoint && storage.hasFile(subscriptionPath)) {
        const fileContent = storage.readFileContent(subscriptionPath);
        const nodeLines = fileContent
          .split("\n")
          .filter((line) => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));

        if (nodeLines.length > 0) {
          await axios.post(
            `${apiEndpoint}/api/add-nodes`,
            JSON.stringify({ nodes: nodeLines }),
            { headers: { "Content-Type": "application/json" } }
          );
          console.log("✓ 节点已上传");
        }
      }
    } catch (err) {
      if (err.response?.status !== 400) {
        console.error("上传节点失败:", err.message);
      }
    }
  }
}

// ==================== 订阅合成器 ====================
class SubscriptionComposer {
  static fetchIspInformation() {
    try {
      const shellCmd =
        'curl -sm 5 https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'';
      return execSync(shellCmd, { encoding: "utf-8" }).trim();
    } catch (err) {
      console.error("获取ISP信息失败:", err.message);
      return "Unknown";
    }
  }

  static synthesizeProxyConfig(configData, tunnelDomain, ispInfo) {
    const displayName = configData.nodeName
      ? `${configData.nodeName}-${ispInfo}`
      : ispInfo;

  // 支持直连切换：当环境变量 DIRECT=true 时使用直连主机和端口
  const directMode = (process.env.DIRECT || "").toLowerCase() === "true";
  const directHost = process.env.DIRECT_HOST || configData.cdnOptimizationDomain;
  const directPort = process.env.DIRECT_PORT || configData.cdnOptimizationPort;

  // TLS VLESS 连接信息（主要方案）
  const tlsTargetHost = directMode ? directHost : configData.cdnOptimizationDomain;
  const tlsTargetPort = directMode ? directPort : configData.cdnOptimizationPort;
  const tlsSni = directMode ? (process.env.DIRECT_SNI || tlsTargetHost) : tunnelDomain;

  const tlsVless = `vless://${configData.clientId}@${tlsTargetHost}:${tlsTargetPort}?encryption=none&security=tls&sni=${tlsSni}&fp=firefox&type=tcp#${displayName}-TLS`;

  // WebSocket + TLS 连接信息 (CDN/直连两用)
  const wsHostHeader = directMode ? (process.env.DIRECT_WS_HOST || tlsTargetHost) : tunnelDomain;
  const wsVless = `vless://${configData.clientId}@${tlsTargetHost}:${tlsTargetPort}?encryption=none&security=tls&sni=${tlsSni}&fp=firefox&type=ws&host=${wsHostHeader}&path=%2Fvless-reality%3Fed%3D2560#${displayName}-WS`;

    // VMess 连接信息
    const vmessPayload = {
      v: "2",
      ps: `${displayName}-VMess`,
      add: directMode ? directHost : configData.cdnOptimizationDomain,
      port: directMode ? Number(directPort) : configData.cdnOptimizationPort,
      id: configData.clientId,
      aid: "0",
      scy: "none",
      net: "ws",
      type: "none",
      host: directMode ? (process.env.DIRECT_WS_HOST || directHost) : tunnelDomain,
      path: "/vmess-reality?ed=2560",
      tls: "tls",
      sni: tlsSni,
      alpn: "",
      fp: "firefox",
    };

    // 兼容性备选：有时需要将连接目标(add)与 websocket Host 字段互换以适配不同的 CDN/隧道路由策略
    const vmessAltPayload = Object.assign({}, vmessPayload, {
      // 目标切换：直接用隧道域名作为连接地址，保留 CDN 域名作为 Host（WS 请求头）
      add: tunnelDomain,
      host: configData.cdnOptimizationDomain,
      ps: `${displayName}-VMess-ALT`,
    });

    // Trojan 连接信息
    const trojanTargetHost = directMode ? directHost : configData.cdnOptimizationDomain;
    const trojanTargetPort = directMode ? directPort : configData.cdnOptimizationPort;
    const trojanConn = `trojan://${configData.clientId}@${trojanTargetHost}:${trojanTargetPort}?security=tls&sni=${tlsSni}&fp=firefox&type=ws&host=${wsHostHeader}&path=%2Ftrojan-reality%3Fed%3D2560#${displayName}-Trojan`;


    // 合并所有连接信息
    const vmessPrimaryLine = `vmess://${Buffer.from(JSON.stringify(vmessPayload)).toString("base64")}`;
    const vmessAltLine = `vmess://${Buffer.from(JSON.stringify(vmessAltPayload)).toString("base64")}`;

    // 允许通过环境变量控制是否优先使用兼容性备选项（有些 CDN/隧道场景需要先试 alt）
    const preferAlt = (process.env.PREFER_VMESS_ALT || "").toLowerCase() === "true";

    const vmessSection = preferAlt
      ? `${vmessAltLine}\n\n${vmessPrimaryLine}`
      : `${vmessPrimaryLine}\n\n${vmessAltLine}`;

  // 合并所有连接信息（仅保留 VLESS、VMESS（含备选）和 TROJAN）
  const proxyContent = `${tlsVless}

${wsVless}

${vmessSection}

${trojanConn}`;

    return { content: proxyContent, name: displayName };
  }

  static extractDomainFromBootLog(logPath, storage) {
    try {
      const logContent = storage.readFileContent(logPath);
      if (!logContent) return null;

      const logLines = logContent.split("\n");
      for (const logLine of logLines) {
        const domainMatch = logLine.match(
          /https?:\/\/([^ ]*trycloudflare\.com)\/?/
        );
        if (domainMatch) {
          return domainMatch[1];
        }
      }
      return null;
    } catch (err) {
      console.error("域名提取失败:", err.message);
      return null;
    }
  }
}

// ==================== 启动引擎 ====================
class LaunchEngine {
  constructor() {
    this.sysConfig = loadSystemConfig();
    this.storage = new StorageService(this.sysConfig.storagePath);
    this.httpServer = express();
    this.isWindowsOS = process.platform === "win32";
    this.initializePaths();
  }

  initializePaths() {
    this.pathMapping = {
      monitoringAgent: this.storage.resolvePath(this.storage.createRandomFileName()),
      proxyApp: this.storage.resolvePath(this.storage.createRandomFileName()),
      cloudflareApp: this.storage.resolvePath(this.storage.createRandomFileName()),
      legacyMonitoringApp: this.storage.resolvePath(this.storage.createRandomFileName()),
      subscription: this.storage.resolvePath("sub.txt"),
      proxyConfiguration: this.storage.resolvePath("config.json"),
      launchLog: this.storage.resolvePath("boot.log"),
      monitoringConfiguration: this.storage.resolvePath("config.yaml"),
      tunnelJsonCreds: this.storage.resolvePath("tunnel.json"),
      tunnelYamlConfig: this.storage.resolvePath("tunnel.yml"),
    };
  }

  setupHttpRoutes() {
    this.httpServer.get("/", (req, res) => {
      res.send("Hello world!");
    });
  }

  async bootstrapApplication() {
    console.log("🚀 正在启动应用...\n");

    try {
      await NodeInformationHandler.removeOldNodes(
        this.sysConfig.uploadApiUrl,
        this.pathMapping.subscription,
        this.storage
      );
      this.storage.purgeDirectory();

      // 生成代理配置
      const proxyConfig = ConfigurationEngine.buildXrayProtocolConfig(
        this.sysConfig.clientId,
        this.sysConfig.tunnelLocalPort
      );
      this.storage.persistContent(
        this.pathMapping.proxyConfiguration,
        JSON.stringify(proxyConfig, null, 2)
      );

      // 下载所需的应用文件
      await this.downloadRequiredApplications();

      // 启动各项服务
      await this.startAllServices();

      // 获取隧道域名并生成订阅
      await this.generateSubscriptionInfo();

      // 上传生成的节点信息
      await NodeInformationHandler.persistNewNodes(
        this.sysConfig.uploadApiUrl,
        this.sysConfig.projectBaseUrl,
        this.pathMapping.subscription,
        this.storage,
        this.sysConfig.subscriptionRouteName
      );

      // 注册自动访问任务
      await this.registerAutomaticKeepAlive();

      // 计划清理临时文件
      this.scheduleCleanupTasks();

      // 启动HTTP服务器
      this.startHttpServer();
    } catch (err) {
      console.error("启动失败:", err.message);
    }
  }

  async downloadRequiredApplications() {
    console.log("📥 正在下载应用文件...");

    const cpuArch = FetchingService.detectCpuArchitecture();
    const needsMonitoring = this.sysConfig.monitorServerHost && this.sysConfig.monitorClientKey;
    const monitoringMode = this.sysConfig.monitorServerPort ? "agent" : "v1";

    const downloadList = FetchingService.resolveDownloadTargets(
      cpuArch,
      needsMonitoring,
      this.sysConfig.monitorServerPort
    );

    const downloadJobs = downloadList.map((item) => {
      let pathKey;
      if (item.identifier === "agent") {
        pathKey = "monitoringAgent";
      } else if (item.identifier === "v1") {
        pathKey = "legacyMonitoringApp";
      } else {
        pathKey = item.identifier === "web" ? "proxyApp" : "cloudflareApp";
      }

      return {
        location: item.location,
        path: this.pathMapping[pathKey],
      };
    });

    await FetchingService.downloadMultipleResources(downloadJobs);

    const permissionTargets = this.sysConfig.monitorServerPort
      ? [
        this.pathMapping.monitoringAgent,
        this.pathMapping.proxyApp,
        this.pathMapping.cloudflareApp,
      ]
      : [
        this.pathMapping.legacyMonitoringApp,
        this.pathMapping.proxyApp,
        this.pathMapping.cloudflareApp,
      ];

    FetchingService.configureFilePermissions(permissionTargets);
  }

  async startAllServices() {
    console.log("▶️ 正在启动服务...\n");

    // 启动监控客户端
    if (this.sysConfig.monitorServerHost && this.sysConfig.monitorClientKey) {
      if (this.sysConfig.monitorServerPort) {
        // V0版本
        const result = await ProcessExecutor.startMonitoringV0(
          this.pathMapping.monitoringAgent,
          this.sysConfig.monitorServerHost,
          this.sysConfig.monitorServerPort,
          this.sysConfig.monitorClientKey,
          this.isWindowsOS
        );
        if (result.completed) console.log("✓ 监控客户端V0已启动");
      } else {
        // V1版本
        const monitorConfig = ConfigurationEngine.buildMonitoringAgentConfig(
          this.sysConfig.monitorClientKey,
          this.sysConfig.monitorServerHost,
          this.sysConfig.clientId
        );
        this.storage.persistContent(
          this.pathMapping.monitoringConfiguration,
          monitorConfig
        );

        const result = await ProcessExecutor.startMonitoringV1(
          this.pathMapping.legacyMonitoringApp,
          this.pathMapping.monitoringConfiguration,
          this.isWindowsOS
        );
        if (result.completed) console.log("✓ 监控客户端V1已启动");
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    // 启动代理应用
    const proxyResult = await ProcessExecutor.startXrayProxy(
      this.pathMapping.proxyApp,
      this.pathMapping.proxyConfiguration,
      this.isWindowsOS
    );
    if (proxyResult.completed) console.log("✓ 代理应用已启动");
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // 启动隧道应用
    await this.startTunnelApplication();
  }

  async startTunnelApplication() {
    if (!this.storage.hasFile(this.pathMapping.cloudflareApp)) {
      return;
    }

    let launchArgs;
    if (
      this.sysConfig.tunnelAuthData.match(/^[A-Z0-9a-z=]{120,250}$/)
    ) {
      launchArgs = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${this.sysConfig.tunnelAuthData}`;
    } else if (this.sysConfig.tunnelAuthData.match(/TunnelSecret/)) {
      // 生成隧道配置
      this.storage.persistContent(
        this.pathMapping.tunnelJsonCreds,
        this.sysConfig.tunnelAuthData
      );
      const tunnelYmlContent = ConfigurationEngine.buildTunnelConfiguration(
        this.sysConfig.tunnelAuthData,
        this.sysConfig.tunnelLocalPort,
        this.sysConfig.tunnelDomainFixed,
        this.sysConfig.storagePath
      );
      if (tunnelYmlContent) {
        this.storage.persistContent(
          this.pathMapping.tunnelYamlConfig,
          tunnelYmlContent
        );
        launchArgs = `tunnel --edge-ip-version auto --config ${this.pathMapping.tunnelYamlConfig} run`;
      }
    } else {
      launchArgs = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${this.pathMapping.launchLog} --loglevel info --url http://localhost:${this.sysConfig.tunnelLocalPort}`;
    }

    const tunnelResult = await ProcessExecutor.startCloudflareClient(
      this.pathMapping.cloudflareApp,
      launchArgs,
      this.isWindowsOS
    );
    if (tunnelResult.completed) console.log("✓ 隧道应用已启动");
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  async generateSubscriptionInfo() {
    console.log("🔗 正在生成订阅...\n");

    let tunnelDomain = this.sysConfig.tunnelDomainFixed;

    if (!tunnelDomain) {
      // 等待临时隧道域名
      tunnelDomain = await this.waitForTunnelDomain();
    }

    if (!tunnelDomain) {
      console.error("❌ 无法获取隧道域名");
      return;
    }

    console.log(`✓ 隧道域名: ${tunnelDomain}`);

    // 生成订阅
    const ispInfo = SubscriptionComposer.fetchIspInformation();
    const { content: subscriptionData, name: subscriptionName } =
      SubscriptionComposer.synthesizeProxyConfig(
        this.sysConfig,
        tunnelDomain,
        ispInfo
      );

    // 保存订阅
    const encodedSubscription = Buffer.from(subscriptionData).toString("base64");
    this.storage.persistContent(this.pathMapping.subscription, encodedSubscription);
    console.log(`✓ 订阅已生成: ${subscriptionName}\n`);
    console.log("订阅内容 (Base64编码):");
    console.log(encodedSubscription);

    // 配置订阅路由
    this.httpServer.get(`/${this.sysConfig.subscriptionRouteName}`, (req, res) => {
      res.set("Content-Type", "text/plain; charset=utf-8");
      res.send(encodedSubscription);
    });

    // 调试路由：返回 base64、解码内容与解析后的节点列表，便于排查连接返回 -1 的原因
    this.httpServer.get(`/${this.sysConfig.subscriptionRouteName}/debug`, (req, res) => {
      const decoded = subscriptionData;

      // 简单解析订阅中每一行的节点信息（支持 vless, vmess, trojan）
      const lines = decoded
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.length > 0);

      const parsed = lines.map((line) => {
        try {
          if (/^vmess:\/\//i.test(line)) {
            const b64 = line.replace(/^vmess:\/\//i, "");
            const json = Buffer.from(b64, "base64").toString("utf-8");
            const obj = JSON.parse(json);
            return { raw: line, protocol: "vmess", parsed: obj };
          }

          // vless/trojan 格式: scheme://id@host:port?...#name
          const schemeMatch = line.match(/^([a-z0-9]+):\/\//i);
          if (schemeMatch) {
            const scheme = schemeMatch[1];
            // 尝试提取 id/password
            const idMatch = line.match(/\/\/([^@]+)@/);
            const hostPortMatch = line.match(/@([^:\/?#]+):(\d+)/);
            const paramsMatch = line.match(/\?([^#]*)/);
            const nameMatch = line.match(/#(.*)$/);

            const parsedNode = {
              raw: line,
              protocol: scheme,
              id: idMatch ? idMatch[1] : null,
              host: hostPortMatch ? hostPortMatch[1] : null,
              port: hostPortMatch ? hostPortMatch[2] : null,
              params: paramsMatch ? paramsMatch[1] : null,
              name: nameMatch ? decodeURIComponent(nameMatch[1]) : null,
            };

            return { raw: line, protocol: scheme, parsed: parsedNode };
          }

          return { raw: line, protocol: "unknown", parsed: null };
        } catch (err) {
          return { raw: line, protocol: "error", error: err.message };
        }
      });

      res.json({ base64: encodedSubscription, decoded, nodes: parsed });
    });
  }

  async waitForTunnelDomain(maxAttempts = 5) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 3000));

      const foundDomain = SubscriptionComposer.extractDomainFromBootLog(
        this.pathMapping.launchLog,
        this.storage
      );
      if (foundDomain) {
        return foundDomain;
      }

      console.log(`⏳ 等待隧道域名... (${attempt + 1}/${maxAttempts})`);
    }

    // 重启隧道应用以重新生成域名
    console.log("🔄 正在重启隧道应用...");
    await ProcessExecutor.terminateProcess(
      path.parse(this.pathMapping.cloudflareApp).name,
      this.isWindowsOS
    );
    await new Promise((resolve) => setTimeout(resolve, 3000));

    if (this.storage.hasFile(this.pathMapping.launchLog)) {
      this.storage.removeFiles([this.pathMapping.launchLog]);
    }

    await this.startTunnelApplication();
    return this.waitForTunnelDomain(3);
  }

  async registerAutomaticKeepAlive() {
    if (!this.sysConfig.enableAutoKeepAlive || !this.sysConfig.projectBaseUrl) {
      return;
    }

    try {
      await axios.post(
        "https://oooo.serv00.net/add-url",
        { url: this.sysConfig.projectBaseUrl },
        { headers: { "Content-Type": "application/json" } }
      );
      console.log("✓ 自动保活任务已注册\n");
    } catch (err) {
      console.error("保活任务注册失败:", err.message);
    }
  }

  scheduleCleanupTasks() {
    setTimeout(() => {
      const filesToClean = [
        this.pathMapping.launchLog,
        this.pathMapping.proxyConfiguration,
        this.pathMapping.proxyApp,
        this.pathMapping.cloudflareApp,
      ];

      if (this.sysConfig.monitorServerPort) {
        filesToClean.push(this.pathMapping.monitoringAgent);
      } else if (
        this.sysConfig.monitorServerHost &&
        this.sysConfig.monitorClientKey
      ) {
        filesToClean.push(this.pathMapping.legacyMonitoringApp);
      }

      this.storage.removeFiles(filesToClean);
      console.clear();
      console.log("✨ 应用正在运行");
      console.log("感谢使用此脚本，祝您使用愉快！");
    }, 90000);
  }

  startHttpServer() {
    this.setupHttpRoutes();
    this.httpServer.listen(this.sysConfig.httpPort, () => {
      console.log(`\n🌐 HTTP服务已启动，监听端口: ${this.sysConfig.httpPort}`);
    });
  }

  async start() {
    await this.bootstrapApplication();
  }
}

// ==================== 启动应用程序 ====================
const launcher = new LaunchEngine();
launcher.start().catch((err) => {
  console.error("致命错误:", err);
  process.exit(1);
});
