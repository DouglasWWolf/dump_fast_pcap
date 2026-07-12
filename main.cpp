//=============================================================================
// dump_fast_pcap - A tool for dumping a fast_pcap capture from RAM to a file
//                  in traditional pcap format.
//
// Author: D. Wolf
//
//
//  Ver    Date     Who  What
//-----------------------------------------------------------------------------
//  1.0  11-Jul-26  DWW  Initial creation
//=============================================================================
#define SOFTWARE_REV "1.0"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include "PhysMem.h"
#include "pcap.h"

using namespace std;
PhysMem  RAM;
CPCAP    PCAP;

const uint64_t HBM_SIZE   = 0x200000000;
const uint64_t BLOCK_SIZE = 0x1000;
const uint64_t MAX_BLOCKS = HBM_SIZE / BLOCK_SIZE;


struct 
{
    uint32_t    max_packets = 1000;    
    uint32_t    max_blocks  = 0;
    uint32_t    tsfreq      = 322625265;
    uint64_t    addr        = 0x100000000;
    string      filename    = "";
} config;


void execute();
void parseCommandLine(const char** argv);


//=============================================================================
// main() - Execution starts here
//=============================================================================
int main(int argc, const char** argv)
{

    parseCommandLine(argv);

    try
    {
        execute();
    }
    catch(const std::exception& e)
    {
        printf("%s\n", e.what());
        exit(1);
    }
}
//=============================================================================



//=============================================================================
// showHelp() - Displays some help-text and exits the program
//=============================================================================
void showHelp()
{
    printf("dump_fast_pcap v%s\n", SOFTWARE_REV);
    printf("dump_fast_pcap [options] <filename>\n");
    printf("  [options] are:\n");
    printf("    -packets <n>\n");
    printf("    -blocks <n>\n");
    printf("    -addr <n>\n");
    printf("    -tsfreq <n>\n");

    exit(1);
}
//=============================================================================



//=============================================================================
// parseCommandLine() - Parses the command line parameters
//=============================================================================
void parseCommandLine(const char** argv)
{
    int i=1;
    const char* ptr;

    while (argv[i])
    {
        // Fetch the next token from the command line
        string token = argv[i++];

        if (token == "-packets")
        {
            ptr = argv[i++];
            if (ptr == nullptr) showHelp();
            config.max_packets = strtoul(ptr, 0, 0);
            if (config.max_packets == 0) showHelp();
            continue;
        }

        else if (token == "-blocks")
        {
            ptr = argv[i++];
            if (ptr == nullptr) showHelp();
            config.max_blocks = strtoul(ptr, 0, 0);
            if (config.max_blocks < 1) showHelp();
            continue;
        }

        else if (token == "-addr")
        {
            ptr = argv[i++];
            if (ptr == nullptr) showHelp();
            config.addr = strtoul(ptr, 0, 0);
            if (config.addr < 0x100000000) showHelp();
            continue;
        }

        else if (token == "-tsfreq")
        {
            ptr = argv[i++];
            if (ptr == nullptr) showHelp();
            config.tsfreq = strtoul(ptr, 0, 0);
            if (config.tsfreq == 0) showHelp();
            continue;
        }

        else if (token == "-help")
        {
            showHelp();
        }


        // If this is an unrecognized command-line switch, complain
        else if (token[0] == '-')
        {
            printf("invalid command line switch.\n");
            showHelp();            
        }

        // Store the filename 
        if (config.filename == "") 
        {
            config.filename = token;
            continue;
        }

        // We had an unexpected parameter on the command line
        showHelp();
    }

    // If the user didn't give us a filename, show the help
    if (config.filename == "") showHelp();
}
//=============================================================================



//=============================================================================
// execute() - Creates a PCAP file from a bank of RAM on the FPGA board
//=============================================================================
void execute()
{
    // It's not possible for 'n' packets to require more than
    // n*3 4KB blocks of RAM.
    int block_count = config.max_packets * 3;

    // Make sure we don't try to map more blocks than we were told to
    if (config.max_blocks && block_count > config.max_blocks)
        block_count = config.max_blocks;

    // Don't map more blocks that exist!
    if (block_count > MAX_BLOCKS) block_count = MAX_BLOCKS;

    // Always map 4 blocks so that we have at least one packet present
    if (block_count < 4) block_count = 4;

    // Map our RAM into userspace
    RAM.map(config.addr, block_count * BLOCK_SIZE);

    // Dump our packets to a file in PCAP format
    uint32_t written = PCAP.dump_to_file
    (
        config.filename, 
        config.tsfreq,
        RAM.bptr(),
        config.max_packets
    );

    // Tell the world what we just did
    printf("%8u packets written to %s\n", written, config.filename.c_str());

}
//=================================================================================================
