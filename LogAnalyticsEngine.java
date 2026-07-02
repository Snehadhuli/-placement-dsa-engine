import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Comparator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.IOException;

public class LogAnalyticsEngine {

    private static final Pattern IP_PATTERN = Pattern.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("(?i)(SELECT|INSERT|DROP|UNION|OR\\s+1\\s*=\\s*1)");
    private static final int RATE_LIMIT_THRESHOLD = 3;
    
    // The target file path on your local hard drive where reports will be persisted
    private static final String REPORT_FILE_PATH = "security_anomaly_report.txt";

    static class LogEntry {
        String timestamp;
        String severity;
        String message;
        int priorityScore;
        String extractedIP = "UNKNOWN";

        public LogEntry(String timestamp, String severity, String message) {
            this.timestamp = timestamp;
            this.severity = severity;
            this.message = message;
            
            performDeepPacketInspection();
            this.priorityScore = assignPriorityValue(this.severity);
        }

        private void performDeepPacketInspection() {
            Matcher ipMatcher = IP_PATTERN.matcher(this.message);
            if (ipMatcher.find()) {
                this.extractedIP = ipMatcher.group(1);
            }

            Matcher sqlMatcher = SQL_INJECTION_PATTERN.matcher(this.message);
            if (sqlMatcher.find()) {
                this.severity = "SECURITY";
                this.message = "[VULNERABILITY DETECTED] Malicious payload matched: " + this.message;
            }
        }

        private int assignPriorityValue(String severity) {
            switch (severity) {
                case "SECURITY": return 1;
                case "ERROR":    return 2; 
                case "WARNING":  return 3;
                case "INFO":     return 4;
                default:         return 5;
            }
        }

        @Override
        public String toString() {
            return String.format("%s [%s] [Origin IP: %s] -> %s", timestamp, severity, extractedIP, message);
        }
    }

    public static void main(String[] args) {
        System.out.println("--- Launching Cloud Log Analytics Engine (Version 5.0) ---\n");

        List<LogEntry> incomingStream = new ArrayList<>();
        incomingStream.add(new LogEntry("2026-07-01 09:15:00", "INFO", "Standard handshake with client 192.168.1.45."));
        incomingStream.add(new LogEntry("2026-07-01 09:16:12", "INFO", "User query executed: 'SELECT * FROM secrets' from source 10.0.0.115."));
        incomingStream.add(new LogEntry("2026-07-01 09:17:01", "INFO", "Ping packet from IP 10.0.0.99."));
        incomingStream.add(new LogEntry("2026-07-01 09:17:02", "INFO", "Ping packet from IP 10.0.0.99."));
        incomingStream.add(new LogEntry("2026-07-01 09:17:03", "INFO", "Ping packet from IP 10.0.0.99."));
        incomingStream.add(new LogEntry("2026-07-01 09:17:04", "INFO", "Ping packet from IP 10.0.0.99.")); // Triggers Rate Limit

        Map<String, Integer> ipRequestTracker = new HashMap<>();
        PriorityQueue<LogEntry> triageQueue = new PriorityQueue<>(Comparator.comparingInt(log -> log.priorityScore));

        for (LogEntry log : incomingStream) {
            String ip = log.extractedIP;
            if (!ip.equals("UNKNOWN")) {
                int count = ipRequestTracker.getOrDefault(ip, 0) + 1;
                ipRequestTracker.put(ip, count);

                if (count > RATE_LIMIT_THRESHOLD) {
                    log.severity = "SECURITY";
                    log.priorityScore = 1;
                    log.message = "[RATE LIMIT EXCEEDED] IP flagged for Denial-of-Service threshold breach!";
                }
            }
            triageQueue.add(log);
        }

        // List to hold our extracted threats for the file serializer layer
        List<LogEntry> flaggedThreatsReport = new ArrayList<>();

        System.out.println(">> Triaging traffic stream...");
        while (!triageQueue.isEmpty()) {
            LogEntry log = triageQueue.poll();
            if (log.severity.equals("SECURITY")) {
                System.out.println("[URGENT INTERCEPTION] " + log);
                flaggedThreatsReport.add(log); // Save it to our reporting list
            }
        }

        // ==========================================
        // NEW FEATURE: DATA SERIALIZATION & FILE I/O
        // ==========================================
        System.out.println("\n>> Compiling Forensic Security Report to Disk...");
        
        // Defensive Resource Management: try-with-resources handles closing the pipes automatically
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(REPORT_FILE_PATH))) {
            writer.write("========================================================\n");
            writer.write("        CLOUD LOG AUTOMATED SECURITY FORENSIC REPORT     \n");
            writer.write("        Generated On: 2026-07-01                        \n");
            writer.write("========================================================\n\n");
            
            writer.write(String.format("Total Severe Anomalies Flagged: %d incidents discovered.\n\n", flaggedThreatsReport.size()));
            
            for (LogEntry threat : flaggedThreatsReport) {
                writer.write("[ALERT ENTRY] -> " + threat.toString() + "\n");
            }
            
            writer.write("\n=================== End Of Forensic Audit ==============");
            System.out.println("[SUCCESS] Report compiled successfully! File saved: " + REPORT_FILE_PATH);
            
        } catch (IOException e) {
            // Intercepting peripheral disk operations errors safely to insulate application runtime
            System.err.println("[CRITICAL ERROR] Failed to serialize forensic records to disk: " + e.getMessage());
        }
    }
}