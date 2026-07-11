#include <stdint.h>
#include <string>

class CPCAP
{
public:

    // This returns the number of packets written to the file
    uint32_t dump_to_file
    (
        std::string filename,
        uint32_t ts_clock,
        uint8_t* ram,
        uint32_t packets
    );
    
};