#include <cstring>
#include <iostream> // cerr
#include <fstream>  // ofstream
#include <sstream>  // stringstream

#include "mod/hashpreimage.cpp"
#include "sha256/utils.cpp" // hex_to_bytes


using std::cerr;
using std::cout;
using std::ofstream;
using std::ifstream;
using std::stringstream;


static int main_prove( int argc, char **argv )
{
    uint8_t input_buffer[64];
    const char *out_filename = NULL;

    if( argc < 4 )
    {
        cerr << "Usage: " << argv[0] << " prove <pk.raw> <0x...64_bytes_as_hex> [proof.json]\n";
        cerr << "Without [proof.json] it will be echo'd to stdout\n";
        return 1;
    }

    auto pk_filename = argv[2];
    auto input_hex = argv[3];

    if( argc > 3 )
    {
        out_filename = argv[4];
    }

    if( ! hex_to_bytes(input_hex, input_buffer, 64) )
    {
        cerr << "Error: couldn't parse `input_buffer` from: " << argv[1] << "\n";
        return 2;
    }

    auto json = hashpreimage_prove(pk_filename, input_buffer);

    if( ! out_filename )
    {
        cout << json << "\n";
    }
    else {
        ofstream fh;
        fh.open(out_filename, std::ios::binary);
        fh << json;
        fh.flush();
        fh.close();
    }

    return 0;
}


static int main_genkeys( int argc, char **argv )
{
    if( argc < 4 )
    {
        cerr << "Usage: " << argv[0] << " genkeys <pk-output.raw> <vk-output.json>\n";
        return 1;
    }

    auto pk_file = argv[2];
    auto vk_file = argv[3];

    if( 0 != hashpreimage_genkeys( pk_file, vk_file ) )
    {
        cerr << "Error: failed to generate proving and verifying keys\n";
        return 1;
    }

    return 0;
}


static int main_verify( int argc, char **argv )
{
    if( argc < 4 )
    {
        cerr << "Usage: " << argv[0] << " verify <vk.json> <proof.json>\n";
        return 1;
    }

    auto vk_json_file = argv[2];
    auto proof_json_file = argv[3];

    // Read verifying key file
    stringstream vk_stream;
    ifstream vk_input(vk_json_file);
    if( ! vk_input ) {
        cerr << "Error: cannot open " << vk_json_file << "\n";
        return 2;
    }
    vk_stream << vk_input.rdbuf();
    vk_input.close();

    // Read proof file
    stringstream proof_stream;
    ifstream proof_input(proof_json_file);
    if( ! proof_input ) {
        cerr << "Error: cannot open " << proof_json_file << "\n";
        return 2;
    }
    proof_stream << proof_input.rdbuf();
    proof_input.close();

    // Then verify if proof is correct
    auto vk_str = vk_stream.str();
    auto proof_str = proof_stream.str();
    if( hashpreimage_verify( vk_str.c_str(), proof_str.c_str() ) )
    {
        return 0;
    }

    cerr << "Error: failed to verify proof!\n";

    return 1;
}


int main( int argc, char **argv )
{
    if( argc < 2 )
    {
        cerr << "Usage: " << argv[0] << " <genkeys|prove|verify> [...]\n";
        return 1;
    }

    if( 0 == ::strcmp(argv[1], "prove") )
    {
        return main_prove(argc, argv);
    }
    else if( 0 == ::strcmp(argv[1], "genkeys") )
    {
        return main_genkeys(argc, argv);
    }
    else if( 0 == ::strcmp(argv[1], "verify") )
    {
        return main_verify(argc, argv);
    }

    cerr << "Error: unknown sub-command " << argv[1] << "\n";
    return 2;
}
