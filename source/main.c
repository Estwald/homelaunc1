/* 
    (c) 2012 Estwald <www.elotrolado.net>

    "Homelaunc1" is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    "Homelaunc1" is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with HMANAGER4.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <math.h>

#include "syscall8.h"

char * LoadFile(char *path, int *file_size)
{
    FILE *fp;
    char *mem = NULL;
    
    *file_size = 0;

    fp = fopen(path, "rb");

	if (fp != NULL) {
        
        fseek(fp, 0, SEEK_END);
		
        *file_size = ftell(fp);
        
        mem = malloc(*file_size);

		if(!mem) {fclose(fp);return NULL;}
        
        fseek(fp, 0, SEEK_SET);

		fread((void *) mem, 1, *file_size, fp);

		fclose(fp);

    }

    return mem;
}

/*******************************************************************************************************************************************************/
/* Payload                                                                                                                               */
/*******************************************************************************************************************************************************/

static u64 peekq(u64 addr)
{
    lv2syscall1(6, addr);
    return_to_user_prog(u64);
}

static void pokeq(u64 addr, u64 data)
{
    lv2syscall2(7, addr, data);
}

u64 restore_syscall8[2]= {0,0};

int is_payload_loaded(void)
{
    u64 addr = peekq(0x80000000000004f0ULL);

    if((addr>>32) == 0x534B3145) {
        addr&= 0xffffffff;
        if(addr && peekq(0x80000000000004f8ULL)) {
            restore_syscall8[0]= peekq(0x80000000000004f8ULL); // (8*8)
            restore_syscall8[1]= peekq(restore_syscall8[0]);
            pokeq(restore_syscall8[0], 0x8000000000000000ULL + (u64) (addr + 0x20));
            return 2;
        }
        
        return 1;
    }
   
    return 0;
}

/*******************************************************************************************************************************************************/
/* sys8 path table                                                                                                                                     */
/*******************************************************************************************************************************************************/


static char *table_compare[17];
static char *table_replace[17];

static int ntable = 0;

void reset_sys8_path_table()
{
    while(ntable > 0) {

        if(table_compare[ntable - 1]) free(table_compare[ntable - 1]);
        if(table_replace[ntable - 1]) free(table_replace[ntable - 1]);

        ntable --;
    }
}

void add_sys8_path_table(char * compare, char * replace)
{
    if(ntable >= 16) return;

    table_compare[ntable] = malloc(strlen(compare) + 1);
    if(!table_compare[ntable]) return;
    strncpy(table_compare[ntable], compare, strlen(compare) + 1);
    
    table_replace[ntable] = malloc(strlen(replace) + 1);
    if(!table_replace[ntable]) return;
    strncpy(table_replace[ntable], replace, strlen(replace) + 1);

    ntable++;

    table_compare[ntable] = NULL;
}


void build_sys8_path_table()
{

    path_open_entry *pentries;

    int entries = 0;

    int arena_size = 0;

    int n, m;

    sys8_path_table(0LL);

    if(ntable <= 0) return;

    while(table_compare[entries] != NULL) {
        int l = strlen(table_compare[entries]);

        arena_size += 0x420;
        for(m = 0x80; m <= 0x420; m += 0x20)
            if(l < m) {arena_size += m;break;}

    entries++;
    }

    if(!entries) return;

    char * datas = memalign(16, arena_size + sizeof(path_open_entry) * (entries + 1));
    
    if(!datas) return;

    u64 dest_table_addr = 0x80000000007FF000ULL - (u64)((arena_size + sizeof(path_open_entry) * (entries + 1) + 15) & ~15);

    u32 arena_offset = (sizeof(path_open_entry) * (entries + 1));

    pentries = (path_open_entry *) datas;

    for(n = 0; n < entries; n++) {
    
        int l = strlen(table_compare[n]);

        int size = 0;
        for(m = 0x80; m <= 0x420; m += 0x20)
            if(l < m) {size += m; break;}

        pentries->compare_addr = dest_table_addr + (u64) (arena_offset);

        pentries->replace_addr = dest_table_addr + (u64) (arena_offset + size);
        

        strncpy(&datas[arena_offset], table_compare[n], size);
        strncpy(&datas[arena_offset + size], table_replace[n], 0x420);

        pentries->compare_len = strlen(&datas[arena_offset]);
        pentries->replace_len = strlen(&datas[arena_offset + size]);

        arena_offset += size + 0x420;
        pentries ++;
       
    }
    
    pentries->compare_addr = 0ULL;

    sys8_memcpy(dest_table_addr, (u64) datas, (u64) (arena_size + sizeof(path_open_entry) * (entries + 1)));

    free(datas);

    reset_sys8_path_table();

    // set the path table
    sys8_path_table( dest_table_addr);
}

s32 main(s32 argc, const char* argv[])
{
	
    int size;

    if(!is_payload_loaded()) return 0;

    if(sys8_enable(0ULL)<0) return 0;
    // try to load virtual file
    char *mem = LoadFile("/dev_hdd0/game/HOMELAUN1/path.bin", &size);

    if(mem) {
    
    sys8_path_table(0LL);
    reset_sys8_path_table();

    // set the path table
   
    add_sys8_path_table("/dev_hdd0/game/HOMELAUN1/ICON0.PNG", "//dev_hdd0/game/HOMELAUN1/GICON0.PNG");
    add_sys8_path_table("/dev_hdd0/game/HOMELAUN1/PARAM.SFO", "//dev_hdd0/game/HOMELAUN1/PARAMX.SFO");

    

    add_sys8_path_table("/dev_hdd0/game/HOMELAUN1/path.bin", mem + 1024);
    add_sys8_path_table("/dev_hdd0/game/HOMELAUN1/path2.bin", mem + 1024);
    
    add_sys8_path_table("/dev_hdd0/game/HOMELAUN1", mem);
    
    sprintf(mem + 1024, "/dev_hdd0/game/%s", mem);
    
    // if not HDD
    if(memcmp(mem, "/dev_hdd", 7))
        add_sys8_path_table(mem + 1024, mem);

    add_sys8_path_table("/app_home", "/dev_kk");

    build_sys8_path_table();

    free(mem);

    }

    if(restore_syscall8[0]) sys8_pokeinstr(restore_syscall8[0], restore_syscall8[1]);

	return 0;
}

