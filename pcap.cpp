#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include "pcap.h"

using std::string;

// This signature marks a valid packet header in RAM
const uint64_t SIGNATURE = 0x00666C6F57202E44;

// This signature marks "end of packets" in RAM
const uint64_t SENTINEL  = 0xDEADBEEFDEADBEEF;

//=============================================================================
// The header of a packet in RAM.  This is always 64 bytes long
//=============================================================================
#pragma pack(push, 1)
struct ram_header_t
{
    uint64_t    magic;
    uint64_t    timestamp;
    uint16_t    packet_length;
    char        filler[46];
};
#pragma pack(push, 1)
//=============================================================================

//=============================================================================
// This is the header of a PCAP file
//=============================================================================
#pragma pack(push, 1)
struct pcap_header_t
{
    uint32_t    magic_number;
    uint16_t    major_version;
    uint16_t    minor_version;
    uint32_t    reserved1;
    uint32_t    reserved2;
    uint32_t    snaplen;
    uint32_t    link_type;
} pcap_header;
#pragma pack(pop)
//=============================================================================




//=============================================================================
// This is a PCAP packet
//=============================================================================
#pragma pack(push, 1)
struct pcap_packet_t
{
    uint32_t    ts_seconds;
    uint32_t    ts_nanoseconds;
    uint32_t    length1;
    uint32_t    length2;
    uint8_t     data[10000];
};
#pragma pack(pop)
//=============================================================================

//=============================================================================
// dump_to_file() - Interprets the data in RAM and writes it to a file in
//                  traditiona 'pcap' format
//=============================================================================
uint32_t CPCAP::dump_to_file
(
    string      fn,
    uint32_t    ts_frequency,
    uint8_t*    ram,
    uint32_t    packets
)
{

    pcap_packet_t packet;
    pcap_header_t header;
    ram_header_t  ram_header;
    uint32_t      packets_written = 0;
 
    // Get a pointer to the filename
    const char* filename = fn.c_str();
   
    // Create the PCAP header
    header.magic_number  = 0xA1B23C4D;
    header.major_version = 2;
    header.minor_version = 4;
    header.reserved1     = 0;
    header.reserved2     = 0;
    header.snaplen       = 65535;
    header.link_type     = 1;

    // Create the output file and complain if we can't
    FILE* ofile = fopen(filename, "w");
    if (ofile == nullptr)
    {
        fprintf(stderr, "Can't create file %s\n", filename);
        exit(1);        
    }

    // Write the PCAP header
    fwrite(&header, sizeof(header), 1, ofile);
    
    // Fetch packets one at a time and write them to the file
    for (uint32_t i=0; i<packets; ++i)
    {
        // Fetch the packet header from RAM
        memcpy(&ram_header, ram, sizeof(ram_header));
        ram += 64;

        // If we've detected the sentinel value where a packet header should
        // be, it means we've reached the end of the packets in RAM
        if (ram_header.magic == SENTINEL) break;

        // Check for the correct magic number
        if (ram_header.magic != SIGNATURE)
        {
            fprintf(stderr, "Packet %u doesn't exist.  Quitting\n", i+ 1); 
            break;
        }

        // Fetch the packet length from the RAM header
        uint32_t packet_length = ram_header.packet_length;


        // Check for a rational packet length
        if (packet_length < 1 || packet_length >= 10000)
        {
            fprintf(stderr, "Packet %u has illegal size %u!.  Quitting\n", i+1, packet_length); 
            break;
        }
        
        // Fetch the timestamp from the block header
        uint64_t timestamp_clocks = ram_header.timestamp;

        // Convert the timestamp to nanoseconds
        uint64_t timestamp_ns = timestamp_clocks * 1000000000 / ts_frequency;

        // Fill in the packet header
        packet.ts_seconds     = timestamp_ns / 1000000000;
        packet.ts_nanoseconds = timestamp_ns % 1000000000;
        packet.length1        = packet_length;
        packet.length2        = packet_length;

        // Compute the number of 64-byte records we need to skip over
        uint32_t records = packet_length / 64;
        if (packet_length % 64) ++records;

        // Write the packet to the pcap file
        memcpy(packet.data, ram, packet_length);
        fwrite(&packet, 16 + packet_length, 1, ofile);
        ++packets_written;

        // Skip over the packet in RAM
        ram += (records * 64);
    }

    // Close the file, we're done!
    fclose(ofile);

    // Tell the caller how many packets we wrote
    return packets_written;
}
//=============================================================================
