pragma solidity ^0.4.24;

library SnarkUtils
{
    /**
    * Given N input words of 256 bits each, output N words of 253 bits each
    * This works similarly to `libff::pack_int_vector_into_field_element_vector`
    *
    * Input:
    *   - D294F6E585874FE640BE4CE636E6EF9E3ADC27620AA3221FDCF5C0A7C11C6F67
    *    (1101001010010100111101101110010110000101100001110100111111100110
          0100000010111110010011001110011000110110111001101110111110011110
          0011101011011100001001110110001000001010101000110010001000011111
          1101110011110101110000001010011111000001000111000110111101100111)
    *
    * Output:
    *   - 3148911523101545054735209199478325155464765444384556179543606818372573931851
    *    (1101111011000111000100000111110010100000011101011110011101111111
          0000100010011000101010100000100011011100100001110110101110001111
          0011111011101100111011011000110011100110010011111010000001001100
          11111110010111000011010000110100111011011110010100101001011)
    *   - 7
    *    (111)
    */
    function PackWords (uint256[] in_words, uint256[] out_words)
        internal
    {
        uint i;
        uint o = 0;
        uint256 leftover = 0;
        uint leftover_bits = 0;

        for( i = 0; i < in_words.length; i++ )
        {
            uint extra = in_words[i] & 15;      // lowest 4 bits (on right) are saved
            uint256 item = ReverseBits(in_words[i]);
            uint extra_bits = 4;
            item = (item & (~uint(0) >> extra_bits));

            if( leftover_bits > 0 ) {
                //    item >> leftover_bits
                //    item |= leftover
                require( false );
                leftover = 0;
                leftover_bits = 0;
            }
            else {
                out_words[o++] = item;
                leftover = extra;
                leftover_bits = extra_bits;
            }
        }

        if( leftover_bits > 0 ) {
            out_words[o++] = leftover;
        }
    }

    /**
    * Reverse an N-bit quantity in parallel with 5 * lg(N) operations
    * Taken from http://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
    */
    function ReverseBits( uint256 v )
        internal pure returns (uint256)
    {
        uint256 s = 256;
        uint256 mask = ~uint(0);

        while( (s >>= 1) > 0 )
        {
            mask ^= (mask << s);
            v = ((v >> s) & mask) | ((v << s) & ~mask);
        }

        return v;
    }
}
