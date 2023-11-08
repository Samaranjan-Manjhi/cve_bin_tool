#include <iostream>
#include <string>
#include <fstream>
#include <curl/curl.h>
#include <sys/stat.h>

class GAD_Source {
public:
    GAD_Source() {
        this->cachedir = "/home/escan/181023/data_source/gad";  // Specify your cache directory here
        this->gad_url = "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.zip";
    }

    void fetch_gad_cves() {
        if (!directory_exists(this->cachedir)) {
            create_directory(this->cachedir);
        }

        CURL* curl = curl_easy_init();
        if (curl) {
            std::string content = get_req(this->gad_url, curl);
            curl_easy_cleanup(curl);

            if (!content.empty()) {
                write_data_to_file(this->cachedir + "/gad_cve.json", content);
                std::cout << "GAD CVE data downloaded and stored." << std::endl;
            } else {
                std::cerr << "Failed to download GAD CVE data." << std::endl;
            }
        } else {
            std::cerr << "Failed to initialize CURL." << std::endl;
        }
    }

private:
    std::string cachedir;
    std::string gad_url;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
        size_t total_size = size * nmemb;
        output->append(static_cast<char*>(contents), total_size);
        return total_size;
    }

    bool directory_exists(const std::string& path) {
        struct stat info;
        return stat(path.c_str(), &info) == 0 && (info.st_mode & S_IFDIR);
    }

    void create_directory(const std::string& path) {
        mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }

    std::string get_req(const std::string& url, CURL* curl) {
        std::string content;
        std::string response_data;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

        CURLcode res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            content = response_data;
        } else {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        return content;
    }

    void write_data_to_file(const std::string& filePath, const std::string& data) {
        std::ofstream file(filePath, std::ios::binary);
        file.write(data.c_str(), data.size());
        file.close();
    }
};

int main() {
    GAD_Source gad_source;
    gad_source.fetch_gad_cves();
    return 0;
}


