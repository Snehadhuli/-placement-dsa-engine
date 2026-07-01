import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Comparator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class LogAnalyticsEngine {

    private static final Pattern IP_PATTERN = Pattern.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("(?i)(SELECT|INSERT|DROP|UNION|OR\\s+1\\s*=\\s*1)");
    
    // Architectural Limit: Maximum allowable logs from a single IP before blocking
    private static final int RATE_LIMIT_THRESHOLD = 3;

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
        System.out.println("--- Launching Cloud Log Analytics Engine (Version 4.0) ---\n");

        // Simulating a Denial of Service (DoS) flood attack stream from a malicious IP (10.0.0.99)
        List<LogEntry> incomingStream = new ArrayList<>();
        incomingStream.add(new LogEntry("2026-06-30 18:01:00", "INFO", "Request from IP 192.168.1.45 to load dashboard."));
        
        // Attack Stream starts here
        incomingStream.add(new LogEntry("2026-06-30 18:01:01", "INFO", "Ping packet received from IP 10.0.0.99."));
        incomingStream.add(new LogEntry("2026-06-30 18:01:02", "INFO", "Ping packet received from IP 10.0.0.99."));
        incomingStream.add(new LogEntry("2026-06-30 18:01:03", "INFO", "Ping packet received from IP 10.0.0.99."));
        
        // This 4th request from 10.0.0.99 breaks our safety threshold limit!
        incomingStream.add(new LogEntry("2026-06-30 18:01:04", "INFO", "Ping packet received from IP 10.0.0.99."));
        incomingStream.add(new LogEntry("2026-06-30 18:01:05", "WARNING", "Standard system health update."));

        // State Tracking Map: Keeps an in-memory counter of log frequencies per IP address
        Map<String, Integer> ipRequestTracker = new HashMap<>();
        
        // Final triage queue
        PriorityQueue<LogEntry> triageQueue = new PriorityQueue<>(Comparator.comparingInt(log -> log.priorityScore));

        System.out.println(">> Processing data stream through Rate-Limiter Gatekeeper...");
        
        for (LogEntry log : incomingStream) {
            String ip = log.extractedIP;

            if (!ip.equals("UNKNOWN")) {
                // High-performance state tracking: Increment the count or set to 1 if it's the first time
                int currentRequestCount = ipRequestTracker.getOrDefault(ip, 0) + 1;
                ipRequestTracker.put(ip, currentRequestCount);

                // If an IP breaches our threshold, dynamically reclassify it as a threat
                if (currentRequestCount > RATE_LIMIT_THRESHOLD) {
                    log.severity = "SECURITY";
                    log.priorityScore = 1; // Drop it straight to priority 1
                    log.message = "[RATE LIMIT EXCEEDED] IP flagged for Denial-of-Service threshold breach! Block dropped.";
                }
            }
            triageQueue.add(log);
        }

        

        System.out.println("\n>> Executing Real-Time Ingestion and Security Assessment:");
        while (!triageQueue.isEmpty()) {
            LogEntry log = triageQueue.poll();
            if (log.severity.equals("SECURITY")) {
                System.out.println("[CRITICAL ALERT] " + log);
            } else {
                System.out.println("[Processed Safe]  " + log);
            }
        }
    }
}