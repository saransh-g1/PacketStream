#include <round_robin.hpp>
#include <vector>

round_robin::round_robin::round_robin( const uint32_t server_id
): current_server(server_id)
{}

round_robin::round_robin::~round_robin() = default;

