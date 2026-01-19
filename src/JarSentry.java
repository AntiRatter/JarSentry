import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

public class JarSentry {

    // -------------------- PATTERNS --------------------

    private static final Pattern DISCORD_TOKEN =
            Pattern.compile("[MN][A-Za-z\\d]{23}\\.[\\w-]{6}\\.[\\w-]{27}");

    private static final Pattern WEBHOOK =
            Pattern.compile("https://(discord(app)?\\.com/api/webhooks|pastebin\\.com|raw\\.githubusercontent\\.com)");

    private static final String[] SUSPICIOUS_STRINGS = {
            "java/net/Socket",
            "java/lang/reflect",
            "javax/crypto",
            "ProcessBuilder",
            "ClassLoader",
            "getRuntime().exec",
            "AES",
            "Base64",
            "defineClass",
            "URLClassLoader",
            "loadClass",
            "Class.forName"
    };

    private static final String[] CREDENTIAL_PATHS = {
            "launcher_accounts.json",
            "Login Data",
            "Cookies",
            "AppData",
            ".minecraft"
    };

    // User-defined high-risk GitHub intelligence indicators
    private static final String[] HIGH_RISK_GITHUB_USERS = {
            "github.com/bigratjr",
            "raw.githubusercontent.com/bigratjr"
    };

    // -------------------- MAIN --------------------

    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            System.out.println("Usage: java JarRATScanner <file.jar>");
            return;
        }

        File target = new File(args[0]);

        if (!target.exists() || !target.getName().endsWith(".jar")) {
            System.out.println("Invalid JAR file.");
            return;
        }

        int score = scanJar(target);

        System.out.println("Final score: " + score);

        if (score >= 6) {
            System.out.println("⚠️  HIGH RISK: Likely malware / RAT");
        } else if (score >= 3) {
            System.out.println("⚠️  SUSPICIOUS: Strong malware indicators");
        } else {
            System.out.println("✅ No strong indicators detected");
        }
    }

    // -------------------- SCANNER --------------------

    private static int scanJar(File jar) throws IOException {

        int score = 0;
        int obfuscationScore = 0;
        int highEntropyClasses = 0;
        StringBuilder reasons = new StringBuilder();

        try (JarFile jarFile = new JarFile(jar)) {

            Enumeration<JarEntry> entries = jarFile.entries();

            while (entries.hasMoreElements()) {

                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }

                try (InputStream is = jarFile.getInputStream(entry)) {

                    byte[] data = is.readAllBytes();
                    String content = new String(data);
                    String lower = content.toLowerCase();

                    if (DISCORD_TOKEN.matcher(content).find()) {
                        score += 3;
                        reasons.append("Discord token pattern detected\n");
                    }

                    if (WEBHOOK.matcher(content).find()) {
                        score += 2;
                        reasons.append("Webhook or raw payload URL detected\n");
                    }

                    for (String s : SUSPICIOUS_STRINGS) {
                        if (content.contains(s)) {
                            score++;
                            reasons.append("Suspicious API usage: ").append(s).append("\n");
                        }
                    }

                    for (String path : CREDENTIAL_PATHS) {
                        if (content.contains(path)) {
                            score += 2;
                            reasons.append("Credential path reference: ").append(path).append("\n");
                        }
                    }

                    if (looksLikeStringDecryptor(content)) {
                        score += 3;
                        reasons.append("Encrypted string decryptor detected\n");
                    }

                    if (content.contains("HttpURLConnection")
                            || content.contains("URL.openStream")
                            || content.contains("getInputStream")) {
                        score += 3;
                        reasons.append("Remote payload loading detected\n");
                    }

                    if (content.contains("defineClass")
                            || content.contains("Unsafe.defineClass")) {
                        score += 4;
                        reasons.append("Runtime class injection detected\n");
                    }

                    if (lower.contains("minecraft") && lower.contains("session")) {
                        score += 2;
                        reasons.append("Minecraft session access detected\n");
                    }

                    for (String gh : HIGH_RISK_GITHUB_USERS) {
                        if (lower.contains(gh)) {
                            score += 5;
                            reasons.append("Matched high-risk GitHub source: ")
                                   .append(gh).append("\n");
                        }
                    }

                    if (isObfuscatedClassName(entry.getName())) {
                        obfuscationScore++;
                        reasons.append("Obfuscated class name: ")
                               .append(entry.getName()).append("\n");
                    }

                    if (calculateEntropy(data) > 7.5) {
                        highEntropyClasses++;
                        reasons.append("High entropy class: ")
                               .append(entry.getName()).append("\n");
                    }
                }
            }
        }

        if (obfuscationScore >= 2 && score >= 2) {
            score += 3;
            reasons.append("Obfuscation correlated with malicious logic\n");
        }

        if (highEntropyClasses >= 3) {
            score += 3;
            reasons.append("Multiple high-entropy classes detected\n");
        }

        if (reasons.length() > 0) {
            System.out.println("\n--- Detection Reasons ---");
            System.out.print(reasons);
            System.out.println("-------------------------\n");
        }

        return score;
    }

    // -------------------- HELPERS --------------------

    private static boolean looksLikeStringDecryptor(String content) {
        return content.contains("SecretKeySpec")
                && content.contains("Cipher.getInstance")
                && content.contains("doFinal");
    }

    private static boolean isObfuscatedClassName(String name) {
        return name.matches(".*/[a-zA-Z]{1,2}\\.class");
    }

    private static double calculateEntropy(byte[] data) {

        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }

        double entropy = 0.0;
        for (int f : freq) {
            if (f == 0) continue;
            double p = (double) f / data.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy;
    }
}
