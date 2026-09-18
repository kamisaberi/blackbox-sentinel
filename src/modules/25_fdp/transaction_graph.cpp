#include "transaction_graph.hpp"
#include <unordered_set>

namespace sentinel::modules::fdp {

void TransactionGraph::add_edge(const std::string& src, const std::string& dst, double amount) {
    std::lock_guard<std::mutex> lock(graph_mutex_);
    adjacency_list_[src].push_back({dst, amount, std::chrono::system_clock::now()});
}

bool TransactionGraph::detect_circular_muling(const std::string& start_node, size_t max_depth) {
    std::lock_guard<std::mutex> lock(graph_mutex_);

    std::unordered_set<std::string> visited;
    std::vector<std::pair<std::string, size_t>> queue;
    queue.push_back({start_node, 0});

    while (!queue.empty()) {
        auto [current_node, depth] = queue.back();
        queue.pop_back();

        if (depth > max_depth) continue;

        auto it = adjacency_list_.find(current_node);
        if (it == adjacency_list_.end()) continue;

        for (const auto& edge : it->second) {
            // If money routes back to originator node within depth limit -> Circular Money Muling Ring
            if (edge.destination_id == start_node && depth >= 2) {
                return true;
            }
            if (visited.find(edge.destination_id) == visited.end()) {
                visited.insert(edge.destination_id);
                queue.push_back({edge.destination_id, depth + 1});
            }
        }
    }
    return false;
}

double TransactionGraph::get_node_velocity_1hr(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(graph_mutex_);
    auto it = adjacency_list_.find(node_id);
    if (it == adjacency_list_.end()) return 0.0;

    auto now = std::chrono::system_clock::now();
    double sum = 0.0;
    for (const auto& edge : it->second) {
        if ((now - edge.timestamp) <= std::chrono::hours(1)) {
            sum += edge.amount;
        }
    }
    return sum;
}

} // namespace sentinel::modules::fdp