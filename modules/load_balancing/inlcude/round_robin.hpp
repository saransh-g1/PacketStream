#include <stdint.h>

namespace round_robin{

    class round_robin{
        public:
            round_robin(const uint32_t server_id);
            ~round_robin();
        
        private:
            void next_server();

        public:
            uint32_t current_server;        
    };
}