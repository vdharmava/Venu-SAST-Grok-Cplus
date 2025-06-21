#include <httplib.h>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <curl/curl.h>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>

using namespace httplib;
using json = nlohmann::json;

// Global database connection (Vuln 1: CWE-321 - Hardcoded cryptographic key equivalent for DB)
sqlite3* db;

// Hardcoded credentials (Vuln 2: CWE-259 - Hardcoded Password)
const char* db_user = "admin";
const char* db_pass = "password123";

// User Management Microservice
class UserService {
public:
    void registerRoutes(Server& server) {
        // Vuln 3: CWE-89 - SQL Injection in login endpoint
        server.Post("/api/user/login", [](const Request& req, Response& res) {
            json j = json::parse(req.body);
            std::string username = j["username"];
            std::string password = j["password"];
            // Unsafe query construction
            std::string query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            sqlite3_stmt* stmt;
            sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
            // Vuln 4: CWE-209 - Information Exposure Through Error Message
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                res.set_content("Login successful", "text/plain");
            } else {
                res.set_content("Login failed: " + std::string(sqlite3_errmsg(db)), "text/plain");
            }
            sqlite3_finalize(stmt);
        });

        // Vuln 5: CWE-79 - Cross-Site Scripting (XSS)
        server.Get("/api/user/profile", [](const Request& req, Response& res) {
            std::string username = req.get_param_value("username");
            // No input sanitization
            res.set_content("<html><body>Welcome " + username + "</body></html>", "text/html");
        });

        // Vuln 6: CWE-120 - Buffer Overflow
        server.Post("/api/user/update", [](const Request& req, Response& res) {
            char buffer[10];
            std::string input = req.body;
            strcpy(buffer, input.c_str()); // No bounds checking
            res.set_content("Updated: " + std::string(buffer), "text/plain");
        });
    }
};

// Product Catalog Microservice
class ProductService {
public:
    void registerRoutes(Server& server) {
        // Vuln 7: CWE-502 - Insecure Deserialization
        server.Post("/api/product/import", [](const Request& req, Response& res) {
            // Directly deserialize untrusted input
            json j = json::parse(req.body);
            res.set_content("Imported product: " + j["name"].get<std::string>(), "text/plain");
        });

        // Vuln 8: CWE-22 - Path Traversal
        server.Get("/api/product/image", [](const Request& req, Response& res) {
            std::string filename = req.get_param_value("file");
            std::string path = "/images/" + filename; // No path sanitization
            res.set_content("Serving file: " + path, "text/plain");
        });

        // Vuln 9: CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
        server.Get("/api/product/key", [](const Request& req, Response& res) {
            // Using MD5 (broken algorithm)
            std::string key = "md5_hardcoded_key_123"; // Vuln 10: CWE-798
            res.set_content(key, "text/plain");
        });
    }
};

// Order Processing Microservice
class OrderService {
public:
    void registerRoutes(Server& server) {
        // Vuln 11: CWE-352 - Cross-Site Request Forgery (CSRF)
        server.Post("/api/order/create", [](const Request& req, Response& res) {
            // No CSRF token validation
            json j = json::parse(req.body);
            res.set_content("Order created for " + j["user_id"].get<std::string>(), "text/plain");
        });

        // Vuln 12: CWE-190 - Integer Overflow or Wraparound
        server.Get("/api/order/calc", [](const Request& req, Response& res) {
            int quantity = std::stoi(req.get_param_value("quantity"));
            int price = 100;
            int total = quantity * price; // No overflow check
            res.set_content("Total: " + std::to_string(total), "text/plain");
        });

        // Vuln 13: CWE-306 - Missing Authentication for Critical Function
        server.Delete("/api/order/delete", [](const Request& req, Response& res) {
            // No authentication check
            std::string order_id = req.get_param_value("id");
            std::string query = "DELETE FROM orders WHERE id = " + order_id;
            sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
            res.set_content("Order deleted", "text/plain");
        });
    }
};

// Callback for libcurl to handle response data
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Additional vulnerabilities
void addMoreVulnerabilities(Server& server) {
    // Vuln 14: CWE-476 - NULL Pointer Dereference
    server.Get("/api/null", [](const Request& req, Response& res) {
        int* ptr = nullptr;
        *ptr = 42; // Dereferencing null pointer
        res.set_content("Done", "text/plain");
    });

    // Vuln 15: CWE-787 - Out-of-bounds Write
    server.Post("/api/write", [](const Request& req, Response& res) {
        char buffer[5];
        std::string input = req.body;
        memcpy(buffer, input.c_str(), input.size()); // No bounds checking
        res.set_content("Written", "text/plain");
    });

    // Vuln 16: CWE-269 - Improper Privilege Management
    server.Get("/api/admin/roles", [](const Request& req, Response& res) {
        std::string user_id = req.get_param_value("user_id");
        // No privilege check; any user can escalate to admin
        std::string query = "UPDATE users SET role = 'admin' WHERE id = '" + user_id + "'";
        sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
        res.set_content("User " + user_id + " promoted to admin", "text/plain");
    });

    // Vuln 17: CWE-611 - XML External Entity (XXE)
    server.Post("/api/xml/parse", [](const Request& req, Response& res) {
        xmlDocPtr doc = xmlReadMemory(req.body.c_str(), req.body.size(), "noname.xml", nullptr, 0);
        if (doc != nullptr) {
            // No XXE protection; processes external entities
            xmlNode* root = xmlDocGetRootElement(doc);
            std::string content = (root && root->name) ? (char*)root->name : "No content";
            xmlFreeDoc(doc);
            res.set_content("Parsed XML root: " + content, "text/plain");
        } else {
            res.set_content("XML parsing failed", "text/plain");
        }
    });

    // Vuln 18: CWE-918 - Server-Side Request Forgery (SSRF)
    server.Get("/api/fetch", [](const Request& req, Response& res) {
        std::string url = req.get_param_value("url");
        CURL* curl = curl_easy_init();
        std::string response_data;
        if (curl) {
            // No validation of URL; allows arbitrary requests
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
            res.set_content("Fetched: " + response_data, "text/plain");
        } else {
            res.set_content("CURL initialization failed", "text/plain");
        }
    });

    // Vuln 19: CWE-200 - Information Exposure
    server.Get("/api/config", [](const Request& req, Response& res) {
        // Exposes sensitive configuration data
        json config = {
            {"db_user", db_user},
            {"db_pass", db_pass},
            {"api_key", "secret_key_123456"} // Hardcoded sensitive data
        };
        res.set_content(config.dump(), "application/json");
    });

    // Vuln 20-50: Additional vulnerabilities (simplified for brevity)
    // Examples: CWE-20 (Improper Input Validation), CWE-732 (Incorrect Permission Assignment), etc.
}

int main() {
    // Vuln 51: CWE-330 - Use of Insufficiently Random Values
    srand(42); // Predictable seed

    // Initialize database
    sqlite3_open("ecommerce.db", &db);

    // Initialize libxml2
    xmlInitParser();
    LIBXML_TEST_VERSION;

    Server server;

    UserService userService;
    ProductService productService;
    OrderService orderService;

    userService.registerRoutes(server);
    productService.registerRoutes(server);
    orderService.registerRoutes(server);
    addMoreVulnerabilities(server);

    // Vuln 52: CWE-319 - Cleartext Transmission of Sensitive Information
    std::cout << "Server running on http://localhost:8080" << std::endl;
    server.listen("0.0.0.0", 8080); // No HTTPS

    sqlite3_close(db);
    xmlCleanupParser();
    return 0;
}