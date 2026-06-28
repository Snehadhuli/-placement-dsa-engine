import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Comparator;

public class LogAnalyticsEngine {

    // A structural blueprint representing a single rich cloud telemetry event
    static class LogEntry {
        String timestamp;
        String severity;
        String message;
        int priorityScore; // Lower number = Higher emergency level (like priority 1)

        public LogEntry(String timestamp, String severity, String message) {
            this.timestamp = timestamp;
            this.severity = severity;
            this.message = message;
            this.priorityScore = assignPriorityValue(severity);
        }

        // Triage mapping: Converting text severity tags into concrete urgency numbers
        private int assignPriorityValue(String severity) {
            switch (severity) {
                case "SECURITY": return 1; // Top priority! Treat immediately.
                case "ERROR":    return 2; 
                case "WARNING":  return 3;
                case "INFO":     return 4; // Bottom priority. Safe to delay.
                default:         return 5;
            }
        }

        @Override
        public String toString() {
            return String.format("%s [%s] Priority-%d: %s", timestamp, severity, priorityScore, message);
        }
    }

    public static void main(String[] args) {
        System.out.println("--- Launching Cloud Log Analytics Engine (Version 2.0) ---\n");

        // 1. Simulating a massive chaotic stream of live server traffic
        List<LogEntry> incomingStream = new ArrayList<>();
        incomingStream.add(new LogEntry("2026-06-28 14:05:12", "INFO", "User standard login successful."));
        incomingStream.add(new LogEntry("2026-06-28 14:06:01", "INFO", "Assets loaded cleanly from CDN."));
        incomingStream.add(new LogEntry("2026-06-28 14:06:45", "WARNING", "Server memory allocation at 86%."));
        incomingStream.add(new LogEntry("2026-06-28 14:08:22", "ERROR", "Database connection pool exhausted."));
        
        // DANGER: This high-priority attack log arrives LATE in the traffic stream
        incomingStream.add(new LogEntry("2026-06-28 14:09:01", "SECURITY", "Brute-force root exploit attempt blocked from IP 192.168.1.105."));
        incomingStream.add(new LogEntry("2026-06-28 14:11:59", "INFO", "Background cleanup task executed."));

        // 2. Initializing the Emergency Priority Queue Subsystem
        // We pass a custom Comparator telling Java to arrange items based on the lowest priorityScore value
        PriorityQueue<LogEntry> emergencyTriageQueue = new PriorityQueue<>(Comparator.comparingInt(log -> log.priorityScore));

        // 3. Streaming Ingestion: Pushing raw data lines into our priority matrix
        System.out.println(">> Ingesting raw cloud telemetry streams into memory...");
        for (LogEntry log : incomingStream) {
            emergencyTriageQueue.add(log);
        }

        // 4. Processing Phase: Watch how the engine pulls data out!
        // No matter when the log arrived, the priority queue forces security to surface first.
        System.out.println("\n>> Executing Real-Time Alert Triage Processing:");
        while (!emergencyTriageQueue.isEmpty()) {
            LogEntry urgentLog = emergencyTriageQueue.poll(); // Pulls the highest priority item out
            
            if (urgentLog.severity.equals("SECURITY")) {
                System.out.println("[CRITICAL ALERT - SEV 1] " + urgentLog);
            } else if (urgentLog.severity.equals("ERROR")) {
                System.out.println("[SYSTEM ALERT - SEV 2] " + urgentLog);
            } else {
                System.out.println("[Standard Processing]   " + urgentLog);
            }
        }
    }
}
