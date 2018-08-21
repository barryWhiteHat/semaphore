/*    
    copyright 2018 to the Semaphore Authors

    This file is part of Semaphore.

    Semaphore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Semaphore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Semaphore.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

char* prove(bool path[][256], bool _signal[256], bool _signal_variables[256] , bool _external_nullifier[256], int address, bool _address_bits[], int tree_depth, int fee, char* pk);
void genKeys(int tree_depth, char* pkOutput, char* vkOuput );


/**
* @param vk_json: Verify key, as JSON string
* @param proof_json: Proof, as JSON string
*/
bool verify( const char* vk_json, const char *proof_json );



#ifdef __cplusplus
} // extern "C"
#endif
