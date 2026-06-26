import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PlacementEngine {

    // Domain model representing a Candidate profile
    static class Candidate {
        String name;
        String department;
        double cgpa;

        public Candidate(String name, String department, double cgpa) {
            this.name = name;
            this.department = department;
            this.cgpa = cgpa;
        }

        @Override
        public String toString() {
            return name + " (" + department + ") - CGPA: " + cgpa;
        }
    }

    public static void main(String[] args) {
        // Industry-grade standard: Utilizing List framework instead of fixed primitive arrays
        List<Candidate> candidatePool = new ArrayList<>();
        
        // Mocking database records dynamically
        candidatePool.add(new Candidate("Sneha Dhuli", "Information Technology", 8.51));
        candidatePool.add(new Candidate("Rahul Sharma", "Computer Science", 7.90));
        candidatePool.add(new Candidate("Priya Rao", "Information Technology", 8.20));
        candidatePool.add(new Candidate("Amit Kumar", "Electronics", 9.10));

        System.out.println("--- Bootstrapping Placement Candidate Records ---");
        
        // Dynamic Filtering: Find candidates eligible for premium tech drives (CGPA >= 8.0)
        double eligibilityThreshold = 8.0;
        List<Candidate> premiumShortlist = new ArrayList<>();
        
        for (Candidate candidate : candidatePool) {
            if (candidate.cgpa >= eligibilityThreshold) {
                premiumShortlist.add(candidate);
            }
        }

        System.out.println("\nFiltered Shortlist (CGPA >= " + eligibilityThreshold + "):");
        premiumShortlist.forEach(System.out::println);

        // Advanced Mapping: Grouping candidates by their target technology department
        Map<String, List<Candidate>> departmentMap = new HashMap<>();
        for (Candidate candidate : candidatePool) {
            departmentMap.computeIfAbsent(candidate.department, k -> new ArrayList<>()).add(candidate);
        }

        System.out.println("\nRegistered Profiles by Academic Department:");
        departmentMap.forEach((dept, list) -> {
            System.out.println("[" + dept + "]: " + list);
        });
    }
}