import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SearchEngine {

    // Domain model representing a target item in an inventory system
    static class Product implements Comparable<Product> {
        int id;
        String name;

        public Product(int id, String name) {
            this.id = id;
            this.name = name;
        }

        @Override
        public int compareTo(Product other) {
            return Integer.compare(this.id, other.id); // Sorting by ID
        }

        @Override
        public String toString() {
            return "[ID: " + id + ", Name: " + name + "]";
        }
    }

    public static void main(String[] args) {
        // Utilizing List collection interface instead of basic primitive arrays
        List<Product> inventory = new ArrayList<>();
        
        inventory.add(new Product(105, "Wireless Mouse"));
        inventory.add(new Product(101, "Mechanical Keyboard"));
        inventory.add(new Product(108, "Gaming Monitor"));
        inventory.add(new Product(103, "USB-C Hub"));

        System.out.println("--- Unsorted Inventory Collection ---");
        inventory.forEach(System.out::println);

        // Sorting the collection using Collections utility framework
        Collections.sort(inventory);
        System.out.println("\n--- Sorted Inventory (Required for Binary Search) ---");
        inventory.forEach(System.out::println);

        // Performing binary search on the object collection using a target key
        Product target = new Product(103, ""); 
        int resultIndex = Collections.binarySearch(inventory, target);

        System.out.println("\n--- Executing Binary Search Engine ---");
        if (resultIndex >= 0) {
            System.out.println("Success! Found product at index " + resultIndex + ": " + inventory.get(resultIndex));
        } else {
            System.out.println("Product ID " + target.id + " not found in system storage.");
        }
    }
}
