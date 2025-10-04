#include <stdint.h>
#include <vector>


namespace server_pool{

    struct pool{
      uint32_t id;
      char *ipv4;
      char *mac_address;
      bool healthy;  
    };

    class server_pool{
        public:
          server_pool(std::vector<pool> &server);
         ~server_pool();

        private:
          void add_server(struct pool &server);
          void remove_server(struct pool &server);
          pool find_server(uint32_t id);

        private:
          std::vector<pool> m_server_pool;            
    };
}