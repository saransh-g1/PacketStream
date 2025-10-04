#include <weighted_robin.hpp>
#include <vector>

weighted_round_robin::weighted_round_robin::weighted_round_robin(std::vector<server_pool::pool> servers 
): m_weighted_server{},
   previously_send{0}
{
    for(auto &i : servers){
        weighted_server  server_with_weights = {
            i,
            static_cast<uint32_t>(100/servers.size()),
        };

        m_weighted_server.push_back(server_with_weights);
    }
}

weighted_round_robin::weighted_round_robin::~weighted_round_robin() = default;
