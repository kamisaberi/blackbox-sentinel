#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>

namespace sentinel::modules::fdp {

struct TransactionEdge {
    std::string destination_id;
    double amount;
    std::chrono::system_clock::time_point timestamp;
};

class TransactionGraph {
public:
    TransactionGraph() = default;
    ~TransactionGraph() = default;

    void add_edge(const std::string& src, const std::string& dst, double amount);
    bool detect_circular_muling(const std::string& start_node, size_t max_depth = 4);
    double get_node_velocity_1hr(const std::string& node_id);

private:
    std::unordered_map<std::string, std::vector<TransactionEdge>> adjacency_list_;
    std::mutex graph_mutex_;
};

} // namespace sentinel::modules::fdp