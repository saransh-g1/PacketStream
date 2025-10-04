#include <server_pool.hpp>

namespace weighted_round_robin{

    struct weighted_server: public server_pool::pool{
        uint8_t weight_percent;
    };

    class weighted_round_robin{
        public:
            weighted_round_robin(std::vector<server_pool::pool> servers);
           ~weighted_round_robin();
        
        private:
            void update_weights(uint32_t server_id, uint8_t weight);
            //had to think upon the routing algo            

        private:
            std::vector<weighted_server> m_weighted_server;
            const uint16_t previously_send;
    };
}