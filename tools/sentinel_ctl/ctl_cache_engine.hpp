#pragma once

#include "common_ctl.hpp"

// --- FUNCTION PROTOTYPES ---
int cmd_cache_list()
{
    fs::path root = get_cache_root();
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m        SENTINEL CONTENT-ADDRESSABLE CACHE: " << root.string() << "\033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";

    if (!fs::exists(root))
    {
        std::cout << "  (Cache directory is currently empty)\n";
        return 0;
    }

    size_t total_size = 0;
    size_t total_files = 0;

    for (const auto &entry : fs::recursive_directory_iterator(root))
    {
        if (entry.is_regular_file())
        {
            auto sz = fs::file_size(entry);
            total_size += sz;
            total_files++;
            std::cout << "  [" << entry.path().parent_path().filename().string() << "] "
                      << std::left << std::setw(36) << entry.path().filename().string()
                      << " (" << sz << " bytes)\n";
        }
    }
    std::cout << "--------------------------------------------------------------------------------\n";
    std::cout << "Total Cached Assets: " << total_files << " files | " << total_size / 1024 << " KB\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    return 0;
}

int cmd_cache_search(const std::string &query, const std::string &type_filter = "")
{
    fs::path root = get_cache_root();
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m        SEARCHING LOCAL CACHE: \"" << query << "\" (Type: " << (type_filter.empty() ? "all" : type_filter) << ")\033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";

    if (!fs::exists(root))
    {
        std::cout << "  (Cache is empty)\n";
        return 0;
    }

    size_t matches = 0;
    for (const auto &entry : fs::recursive_directory_iterator(root))
    {
        if (entry.is_regular_file())
        {
            std::string fname = entry.path().filename().string();
            std::string cat = entry.path().parent_path().filename().string();

            bool match_q = query.empty() || fname.find(query) != std::string::npos;
            bool match_t = type_filter.empty() || cat.find(type_filter) != std::string::npos;

            if (match_q && match_t)
            {
                std::cout << "  \033[1;32m[FOUND]\033[0m [" << std::setw(10) << cat << "] "
                          << std::left << std::setw(36) << fname
                          << " (" << fs::file_size(entry) << " bytes)\n";
                matches++;
            }
        }
    }
    std::cout << "--------------------------------------------------------------------------------\n";
    std::cout << "Matches: " << matches << " cached file(s).\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    return 0;
}
int cmd_cache_clean()
{
    fs::path root = get_cache_root();
    if (fs::exists(root))
    {
        fs::remove_all(root);
        std::cout << "[+] Cleared cache directory: " << root.string() << std::endl;
    }
    return 0;
}
int cmd_cache_export(const std::string &out_tar)
{
    fs::path root = get_cache_root();
    if (!fs::exists(root))
    {
        std::cerr << "[-] Error: Cache is empty. Nothing to export." << std::endl;
        return 1;
    }
    std::string cmd = "tar -czf \"" + out_tar + "\" -C \"" + root.string() + "\" .";
    int ret = std::system(cmd.c_str());
    if (ret == 0)
    {
        std::cout << "\033[1;32m[+] Successfully exported air-gapped cache bundle: " << out_tar << "\033[0m\n"
                  << "    Ready for USB Sneakernet transfer to isolated facilities.\n";
        return 0;
    }
    return 1;
}

int cmd_cache_import(const std::string &in_tar)
{
    if (!fs::exists(in_tar))
    {
        std::cerr << "[-] Error: Archive not found: " << in_tar << std::endl;
        return 1;
    }
    fs::path root = get_cache_root();
    fs::create_directories(root);
    std::string cmd = "tar -xzf \"" + in_tar + "\" -C \"" + root.string() + "\"";
    int ret = std::system(cmd.c_str());
    if (ret == 0)
    {
        std::cout << "\033[1;32m[+] Successfully imported offline cache bundle into: " << root.string() << "\033[0m\n";
        return 0;
    }
    return 1;
}

// [PLACEHOLDER: Full implementations of cmd_cache_* go here]