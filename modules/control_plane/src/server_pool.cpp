#include <include/server_pool.hpp>
#include <vector>

server_pool::server_pool::server_pool(std::vector<pool> &server)
: m_server_pool(server)
{}

server_pool::server_pool::~server_pool()= default;

void server_pool::server_pool::add_server(struct pool &server){
    m_server_pool.push_back(server);
}

void server_pool::server_pool::remove_server(struct pool &server){
    std::vector<pool> temp_servers;
    temp_servers.reserve(m_server_pool.size() - 1);

    for (auto&& s : m_server_pool) {
        if (s.id != server.id)
            temp_servers.emplace_back(std::move(s)); // move, not copy
    }

    m_server_pool.swap(temp_servers); 
}

server_pool::pool server_pool::server_pool::find_server(uint32_t id){
    for(auto&& s : m_server_pool){
        if(id==s.id) return s;
    }
}

