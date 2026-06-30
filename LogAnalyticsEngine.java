import java.util.ArrayList;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Comparator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class LogAnalyticsEngine {

    // Pre-compiling the Regular Expressions at the class level for maximum runtime performance
    // Pattern 1: Detects any IPv4 address (4 number blocks separated by periods)
    private static final Pattern IP_PATTERN = Pattern.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
    
    // Pattern 2: Detects classic malicious SQL Injection signatures (e.g., SELECT statements or OR 1=1 structures)
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("(?i)(SELECT|INSERT|DROP|UNION|OR\\s+1\\s*=\\s*1)");

    static class LogEntry {
        String timestamp;
        String severity;
        String message;
        int priorityScore;
        String extractedIP = "UNKNOWN"; // Will be populated dynamically by our Regex engine

        public LogEntry(String timestamp, String severity, String message) {
            this.timestamp = timestamp;
            this.severity = severity;
            this.message = message;
            
            // Execute deep packet inspection using Regex before assigning priority
            performDeepPacketInspection();
            this.priorityScore = assignPriorityValue(this.severity);
        }

        // Deep Text Examination Subsystem
        private void performDeepPacketInspection() {
            // 1. Scan for hidden IP Addresses within the log text string
            Matcher ipMatcher = IP_PATTERN.matcher(this.message);
            if (ipMatcher.find()) {
                this.extractedIP = ipMatcher.group(1); // Extract the matched IP string
            }

            // 2. Scan for malicious SQL Injection payloads hiding inside standard logs
            Matcher sqlMatcher = SQL_INJECTION_PATTERN.matcher(this.message);
            if (sqlMatcher.find()) {
                // Instantly escalate severity to SECURITY, even if it arrived labeled as INFO!
                this.severity = "SECURITY";
                this.message = "[VULNERABILITY DETECTED] Malicious payload matched: " + this.message;
            }
        }

        private int assignPriorityValue(String severity) {
            switch (severity) {
                case "SECURITY": return 1; // Top priority
                case "ERROR":    return 2; 
                case "WARNING":  return 3;
                case "INFO":     return 4; // Bottom priority
                default:         return 5;
            }
        }

        @Override
        public String toString() {
            return String.format("%s [%s] [Origin IP: %s] -> %s", timestamp, severity, extractedIP, message);
        }
    }

    public static void main(String[] args) {
        System.out.println("--- Launching Cloud Log Analytics Engine (Version 3.0) ---\n");

        List<LogEntry> incomingStream = new ArrayList<>();
        incomingStream.add(new LogEntry("2026-06-29 10:05:00", "INFO", "User standard query for item 'laptop' executed from source 192.168.1.45."));
        
        // HACK ATTEMPT: Masked as a safe INFO log, but contains a dangerous SQL command to leak data
        incomingStream.add(new LogEntry("2026-06-29 10:06:12", "INFO", "User login query executed: 'SELECT * FROM users WHERE admin = 1' from source 10.0.0.115."));
        
        incomingStream.add(new LogEntry("2026-06-29 10:07:45", "WARNING", "Disk capacity alert triggered on storage cluster."));

        // Setup triage system using Priority Queue
        PriorityQueue<LogEntry> triageQueue = new PriorityQueue<>(Comparator.comparingInt(log -> log.priorityScore));

        System.out.println(">> Streaming telemetries into deep matching matrix...");
        for (LogEntry log : incomingStream) {
            triageQueue.add(log);
        }

        System.out.println("\n>> Executing Automated Forensic Alert Inspection System:");
        while (!triageQueue.isEmpty()) {
            LogEntry log = triageQueue.poll();
            if (log.severity.equals("SECURITY")) {
                System.out.println("[CRITICAL ALARM] " + log);
            } else {
                System.out.println("[Processed Safe] " + log);
            }
        }
    }
}