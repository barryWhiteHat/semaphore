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

char* _sha256Constraints();
char* _sha256Witness();
char* prove(bool path[][256], bool _signal[256], bool _signal_variables[256] , bool _external_nullifier[256], int address, bool _address_bits[], int tree_depth, int fee, char* pk, bool isInt);
void genKeys(int tree_depth, char* pkOutput, char* vkOuput );


bool verify( char* vk, char* _g_A_0, char* _g_A_1, char* _g_A_2 ,  char* _g_A_P_0, char* _g_A_P_1, char* _g_A_P_2,
             char* _g_B_1, char* _g_B_0, char* _g_B_3, char* _g_B_2, char* _g_B_5 , char* _g_B_4, char* _g_B_P_0, char* _g_B_P_1, char* _g_B_P_2,
             char* _g_C_0, char* _g_C_1, char* _g_C_2, char* _g_C_P_0, char* _g_C_P_1, char* _g_C_P_2,
             char* _g_H_0, char* _g_H_1, char* _g_H_2, char* _g_K_0, char* _g_K_1, char* _g_K_2, char* _input0 , char* _input1 , char* _input2, char* _input3,
             char* _input4, char* _input5
             ) ;



#ifdef __cplusplus
} // extern "C"
#endif
