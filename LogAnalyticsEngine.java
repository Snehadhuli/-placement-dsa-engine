import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LogAnalyticsEngine {

    // Simulating streaming raw log lines from a live cloud server
    private static List<String> fetchRawCloudLogs() {
        List<String> rawLogs = new ArrayList<>();
        rawLogs.add("2026-06-27 14:05:12 [INFO] Server started successfully on port 8080.");
        rawLogs.add("2026-06-27 14:06:45 [WARNING] High memory utilization detected above 85%.");
        rawLogs.add("2026-06-27 14:08:22 [ERROR] Database connection timeout on node-03.");
        rawLogs.add("2026-06-27 14:09:01 [SECURITY] Unauthorized root access attempt blocked from IP 192.168.1.105.");
        rawLogs.add("2026-06-27 14:11:59 [ERROR] NullPointerException in UserAuthService execution pipeline.");
        return rawLogs;
    }

    public static void main(String[] args) {
        System.out.println("--- Launching Cloud Log Analytics & Monitoring Engine ---");
        List<String> liveStream = fetchRawCloudLogs();

        // Architectural Setup: Categorizing raw telemetry lines by their severity levels
        Map<String, List<String>> categorizedLogs = new HashMap<>();

        // Ingestion & Processing Pipeline
        for (String log : liveStream) {
            String severity = "UNKNOWN";
            
            if (log.contains("[INFO]")) severity = "INFO";
            else if (log.contains("[WARNING]")) severity = "WARNING";
            else if (log.contains("[ERROR]")) severity = "ERROR";
            else if (log.contains("[SECURITY]")) severity = "SECURITY";

            // High performance alternative to basic arrays: Dynamic map collections insertion
            categorizedLogs.computeIfAbsent(severity, k -> new ArrayList<>()).add(log);
        }

        // Automated Threat Alert Check
        System.out.println("\n>> Running Real-Time Threat Diagnostic Scanning:");
        if (categorizedLogs.containsKey("SECURITY")) {
            System.out.println("[ALERT] Critical Security Vulnerability Incidents Identified!");
            categorizedLogs.get("SECURITY").forEach(log -> System.out.println(" -> " + log));
        }

        System.out.println("\n>> Aggregated Operational Metrics Summary:");
        categorizedLogs.forEach((level, logsList) -> {
            System.out.println("Category [" + level + "] -> Count: " + logsList.size() + " active metrics.");
        });
    }
}