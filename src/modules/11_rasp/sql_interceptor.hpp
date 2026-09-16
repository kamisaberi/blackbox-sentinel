#pragma once

#include <string>

namespace sentinel::modules::rasp {

class SQLInterceptor {
public:
    SQLInterceptor() = default;
    ~SQLInterceptor() = default;

    // Evaluates in-process query execution context
    bool is_query_parameterized(const std::string& raw_sql, std::string& out_violation);
};

} // namespace sentinel::modules::rasp