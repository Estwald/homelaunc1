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

#define NEW_POKE_SYSCALL                813

#define SYSCALL_BASE_341                    0x80000000002EB128ULL
#define NEW_POKE_SYSCALL_ADDR_341           0x80000000001BB93CULL   // where above syscall is in lv2
#define SYSCALL_BASE_355                    0x8000000000346570ULL
#define NEW_POKE_SYSCALL_ADDR_355           0x8000000000195A68ULL   // where above syscall is in lv2
#define SYSCALL_BASE_355DEX                 0x8000000000361578ULL
#define NEW_POKE_SYSCALL_ADDR_355DEX        0x800000000019be24ULL   // where above syscall is in lv2
#define SYSCALL_BASE_421                    0x800000000035BCA8ULL
#define NEW_POKE_SYSCALL_ADDR_421           0x80000000001B65C8ULL   // where above syscall is in lv2
#define SYSCALL_BASE_421DEX                 0x800000000037A1B0ULL
#define NEW_POKE_SYSCALL_ADDR_421DEX        0x80000000001BC9B8ULL   // where above syscall is in lv2
#define SYSCALL_BASE_430                    0x800000000035DBE0ULL
#define NEW_POKE_SYSCALL_ADDR_430           0x80000000001B6950ULL   // where above syscall is in lv2
#define SYSCALL_BASE_431                    0x800000000035DBE0ULL
#define NEW_POKE_SYSCALL_ADDR_431           0x80000000001B6958ULL   // where above syscall is in lv2

u64 SYSCALL_BASE;

int is_firm_341(void)
{
    u64 addr = peekq((SYSCALL_BASE_341 + NEW_POKE_SYSCALL * 8));
    if(addr < 0x8000000000000000ULL || addr > 0x80000000007FFFFFULL || (addr & 3)!=0) return 0;
    addr = peekq(addr);

    SYSCALL_BASE = SYSCALL_BASE_341;
    if(addr == NEW_POKE_SYSCALL_ADDR_341) return 1;
    

    return 0;
}

int is_firm_355(void)
{
    u64 addr = peekq((SYSCALL_BASE_355 + NEW_POKE_SYSCALL * 8));
    if(addr < 0x8000000000000000ULL || addr > 0x80000000007FFFFFULL || (addr & 3)!=0) return 0;
    addr = peekq(addr);

    SYSCALL_BASE = SYSCALL_BASE_355;
    if(addr == NEW_POKE_SYSCALL_ADDR_355) return 1;
    

    return 0;
}

int is_firm_355DEX(void)
{
    u64 addr = peekq((SYSCALL_BASE_355DEX + NEW_POKE_SYSCALL * 8));
    if(addr < 0x8000000000000000ULL || addr > 0x80000000007FFFFFULL || (addr & 3)!=0) return 0;
    addr = peekq(addr);

    SYSCALL_BASE = SYSCALL_BASE_355DEX;
    if(addr == NEW_POKE_SYSCALL_ADDR_355DEX) return 1;
    

    return 0;
}

int is_firm_421(void)
{
    u64 addr = peekq((SYSCALL_BASE_421 + NEW_POKE_SYSCALL * 8));
    // check address first
    if(addr < 0x8000000000000000ULL || addr > 0x80000000007FFFFFULL || (addr & 3)!=0)
        return 0;
    addr = peekq(addr);
    
    SYSCALL_BASE = SYSCALL_BASE_421;
    if(addr == NEW_POKE_SYSCALL_ADDR_421) return 1;

    return 0;
}

int is_firm_421DEX(void)
{
    u64 addr = peekq((SYSCALL_BASE_421DEX + NEW_POKE_SYSCALL * 8));
    // check address first
    if(addr < 0x8000000000000000ULL || addr > 0x80000000007FFFFFULL || (addr & 3)!=0)
        return 0;
    addr = peekq(addr);
    
    SYSCALL_BASE = SYSCALL_BASE_421DEX;
    if(addr == NEW_POKE_SYSCALL_ADDR_421DEX) return 1;

    return 0;
}

int is_firm_430(void)
{
    u64 addr = peekq((SYSCALL_BASE_430 + NEW_POKE_SYSCALL * 8));
    if(addr < 0x8000000000000000ULL || addr > 0x80000000007FFFFFULL || (addr & 3)!=0) return 0;
    addr = peekq(addr);

    SYSCALL_BASE = SYSCALL_BASE_430;
    if(addr == NEW_POKE_SYSCALL_ADDR_430) return 1;
   
    return 0;
}

int is_firm_431(void)
{
    u64 addr = peekq((SYSCALL_BASE_431 + NEW_POKE_SYSCALL * 8));
    if(addr < 0x8000000000000000ULL || addr > 0x80000000007FFFFFULL || (addr & 3)!=0) return 0;
    addr = peekq(addr);

    SYSCALL_BASE = SYSCALL_BASE_431;
    if(addr == NEW_POKE_SYSCALL_ADDR_431) return 1;
   
    return 0;
}

int is_payload_loaded(void)
{
    if(!is_firm_341() && !is_firm_355() && !is_firm_355DEX() && !is_firm_421() && !is_firm_421DEX() && !is_firm_430() && !is_firm_431()) 
        return 0;

    u64 addr = peekq((SYSCALL_BASE + 36 * 8));
    addr = peekq(addr);
    
    if(SYSCALL_BASE == SYSCALL_BASE_341 && peekq(0x8000000000017CD0ULL)!=0x4E8000203C608001ULL) return 1;
    if(peekq(addr - 0x20) == 0x534B313000000000ULL) //SK10 HEADER
        return 1;

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

    build_sys8_path_table();

    free(mem);

    }


	return 0;
}

