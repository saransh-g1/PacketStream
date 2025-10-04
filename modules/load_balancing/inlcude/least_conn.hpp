#include <server_pool.hpp>
#include <vector>
#include <memory>

namespace least_conn{

    struct active_conn : public server_pool::pool{
        uint32_t active_connections;
    };

    class least_conn{
        public:
            least_conn(std::vector<server_pool::pool> servers);
            ~least_conn();
        
        private:
            void increment_conn(uint32_t server_id);
            void decrement_conn(uint32_t server_id);
            active_conn *find_least_conn();

        private:
            std::vector<active_conn> m_conn;

    };
}