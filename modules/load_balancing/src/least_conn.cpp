#include <least_conn.hpp>
#include <vector>

least_conn::least_conn::least_conn(std::vector<server_pool::pool> servers 
): m_conn{}
{
    for(auto &i : servers){
        active_conn server_conn = {
            i,
            static_cast<uint32_t>(0),
        };

        m_conn.push_back(server_conn);
    }
}

least_conn::least_conn::~least_conn() = default;

