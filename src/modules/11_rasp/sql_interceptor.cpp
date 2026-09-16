#include "sql_interceptor.hpp"
#include <algorithm>

namespace sentinel::modules::rasp {

bool SQLInterceptor::is_query_parameterized(const std::string& raw_sql, std::string& out_violation) {
    if (raw_sql.empty()) return true;

    // Detect non-parameterized dynamic string concatenations inside runtime queries
    if (raw_sql.find("WHERE id = ") != std::string::npos && raw_sql.find("?") == std::string::npos) {
        if (raw_sql.find("'") != std::string::npos || raw_sql.find("OR") != std::string::npos) {
            out_violation = "Non-parameterized query execution with raw concatenation detected";
            return false;
        }
    }

    if (raw_sql.find("EXEC(") != std::string::npos || raw_sql.find("sp_executesql") != std::string::npos) {
        out_violation = "Dynamic stored procedure execution detected in runtime memory";
        return false;
    }

    return true;
}

} // namespace sentinel::modules::rasp