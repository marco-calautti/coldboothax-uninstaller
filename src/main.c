/*
 * Copyright (C) 2016 Phoenix (original source code by FIX94)
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/gx2_functions.h"
#include "dynamic_libs/sys_functions.h"
#include "dynamic_libs/vpad_functions.h"
#include "system/memory.h"
#include "common/common.h"
#include "main.h"
#include "exploit.h"
#include "iosuhax.h"

//just to be able to call async
void someFunc(void *arg)
{
    (void)arg;
}

static int mcp_hook_fd = -1;
int MCPHookOpen()
{
    //take over mcp thread
    mcp_hook_fd = MCP_Open();
    if(mcp_hook_fd < 0)
        return -1;
    IOS_IoctlAsync(mcp_hook_fd, 0x62, (void*)0, 0, (void*)0, 0, someFunc, (void*)0);
    //let wupserver start up
    sleep(1);
    if(IOSUHAX_Open("/dev/mcp") < 0)
        return -1;
    return 0;
}

void MCPHookClose()
{
    if(mcp_hook_fd < 0)
        return;
    //close down wupserver, return control to mcp
    IOSUHAX_Close();
    //wait for mcp to return
    sleep(1);
    MCP_Close(mcp_hook_fd);
    mcp_hook_fd = -1;
}

void println_noflip(int line, const char *msg)
{
    OSScreenPutFontEx(0,0,line,msg);
    OSScreenPutFontEx(1,0,line,msg);
}

void println(int line, const char *msg)
{
    int i;
    for(i = 0; i < 2; i++)
    {	//double-buffered font write
        println_noflip(line,msg);
        OSScreenFlipBuffersEx(0);
        OSScreenFlipBuffersEx(1);
    }
}

typedef struct _parsedList_t {
    uint32_t tid;
    char name[64];
    char path[64];
    u8 *romPtr;
    u32 romSize;
} parsedList_t;

int fsa_read(int fsa_fd, int fd, void *buf, int len)
{
    int done = 0;
    uint8_t *buf_u8 = (uint8_t*)buf;
    while(done < len)
    {
        size_t read_size = len - done;
        int result = IOSUHAX_FSA_ReadFile(fsa_fd, buf_u8 + done, 0x01, read_size, fd, 0);
        if(result < 0)
            return result;
        else
            done += result;
    }
    return done;
}

int fsa_write(int fsa_fd, int fd, void *buf, int len)
{
    int done = 0;
    uint8_t *buf_u8 = (uint8_t*)buf;
    while(done < len)
    {
        size_t write_size = len - done;
        int result = IOSUHAX_FSA_WriteFile(fsa_fd, buf_u8 + done, 0x01, write_size, fd, 0);
        if(result < 0)
            return result;
        else
            done += result;
    }
    return done;
}

int availSort(const void *c1, const void *c2)
{
    return strcmp(((parsedList_t*)c1)->name,((parsedList_t*)c2)->name);
}

void printhdr_noflip()
{
    println_noflip(0,"Codboothax uninstaller 0.1 (based on FIX94's Haxchi installer)");
    println_noflip(1,"Credits to smea, plutoo, yellows8, naehrwert, derrek, dimok, FIX94");
}

int Menu_Main(void)
{
    InitOSFunctionPointers();
    InitSysFunctionPointers();
    InitVPadFunctionPointers();
    VPADInit();
    
    // Init screen
    OSScreenInit();
    int screen_buf0_size = OSScreenGetBufferSizeEx(0);
    int screen_buf1_size = OSScreenGetBufferSizeEx(1);
    uint8_t *screenBuffer = memalign(0x100, screen_buf0_size+screen_buf1_size);
    OSScreenSetBufferEx(0, screenBuffer);
    OSScreenSetBufferEx(1, (screenBuffer + screen_buf0_size));
    OSScreenEnableEx(0, 1);
    OSScreenEnableEx(1, 1);
    OSScreenClearBufferEx(0, 0);
    OSScreenClearBufferEx(1, 0);
    
    int mcp_handle = MCP_Open();
    int count = MCP_TitleCount(mcp_handle);
    int listSize = count*0x61;
    char *tList = memalign(32, listSize);
    memset(tList, 0, listSize);
    int recievedCount = count;
    MCP_TitleList(mcp_handle, &recievedCount, tList, listSize);
    MCP_Close(mcp_handle);
    
    int i, j;
    uint32_t menu_id=0;
    
    for(i = 0; i < recievedCount; i++)
    {
        char *cListElm = tList+(i*0x61);
        if(memcmp(cListElm+0x56,"mlc",4) != 0)
            continue;
        
        //let's find the system menu id;
        if(*(uint32_t*)(cListElm) == 0x00050010)
        {
            if( *(uint32_t*)(cListElm+4) == 0x10040200 || //EUR
                *(uint32_t*)(cListElm+4) == 0x10040100 || //USA
                *(uint32_t*)(cListElm+4) == 0x10040000)   //JAP  
            {
                menu_id = *(uint32_t*)(cListElm+4);
                break;
            }
        }
    }
    
    int vpadError = -1;
    VPADData vpad;
    
    if(!menu_id)
    {
        printhdr_noflip();
        println(3,"Could not retrieve system menu id, exiting...");
        OSScreenFlipBuffersEx(0);
        OSScreenFlipBuffersEx(1);
        
        sleep(1);
        OSScreenEnableEx(0, 0);
        OSScreenEnableEx(1, 0);
        free(screenBuffer);
        return EXIT_SUCCESS;
    }
    
    for(j = 0; j < 2; j++)
    {
        OSScreenClearBufferEx(0, 0);
        OSScreenClearBufferEx(1, 0);
        printhdr_noflip();
        println_noflip(3,"Coldboothax will be uninstalled...");
        println_noflip(5,"Are sure you want to proceed? (press A to confirm, HOME to exit)");
        OSScreenFlipBuffersEx(0);
        OSScreenFlipBuffersEx(1);
        usleep(25000);
    }
    
    while(1)
    {
        usleep(25000);
        VPADRead(0, &vpad, 1, &vpadError);
        if(vpadError != 0)
            continue;
        //user aborted
        if((vpad.btns_d | vpad.btns_h) & VPAD_BUTTON_HOME)
        {
            OSScreenEnableEx(0, 0);
            OSScreenEnableEx(1, 0);
            free(screenBuffer);
            return EXIT_SUCCESS;
        }
        //lets go!
        if(vpad.btns_d & VPAD_BUTTON_A)
            break;
    }
    
    for(j = 0; j < 2; j++)
    {
        OSScreenClearBufferEx(0, 0);
        OSScreenClearBufferEx(1, 0);
        printhdr_noflip();
        OSScreenFlipBuffersEx(0);
        OSScreenFlipBuffersEx(1);
        usleep(25000);
    }
    
    int line=3;        
    println(line++,"Doing IOSU Exploit...");
    IOSUExploit();
    
    int fsaFd = -1;
    int slcFd = -1;
    
    //done with iosu exploit, take over mcp
    if(MCPHookOpen() < 0)
    {
        println(line++,"MCP hook could not be opened!");
        goto prgEnd;
    }
    
    //mount with full permissions
    fsaFd = IOSUHAX_FSA_Open();
    if(fsaFd < 0)
    {
        println(line++,"FSA could not be opened!");
        goto prgEnd;
    }
    
    
    println(line++,"Checking system.xml integrity...");
    sleep(2);
    
    if(IOSUHAX_FSA_OpenFile(fsaFd, "/vol/system/config/system.xml", "rb", &slcFd) < 0)
    {
        println(line++,"Could not open system.xml, exiting...");
        goto prgEnd;
    }else
    {
        fileStat_s stats;
        IOSUHAX_FSA_StatFile(fsaFd, slcFd, &stats);
        size_t systemSize = stats.size;
        char* systemBuf = malloc(systemSize);
        fsa_read(fsaFd, slcFd, systemBuf, systemSize);
        IOSUHAX_FSA_CloseFile(fsaFd, slcFd);
        slcFd = -1;
        
        if(!systemBuf)
        {
            println(line++,"Could not read system.xml, exiting...");
            goto prgEnd;
        }
        
        //Apart from CDATA (which is very unlikely), I don't see any other way for
        //the system.xml to properly store the EXACT title id in string form other than
        //via an xml node written in one row and without spaces in its content.
        //So, let's keep the xml change simple, without relying on libxml2.
        char* tagPtr = strstr(systemBuf,"<default_title_id type=\"hexBinary\" length=\"8\">");
        if(!tagPtr)
        {
            println(line++,"Could not find default_title_id tag, exiting...");
            goto prgEnd;
        }
        
        tagPtr+=46;
        
        if(memcmp(tagPtr+16,"</default_title_id>",19) != 0)
        {
            println(line++,"File system.xml not properly formatted, exiting...");
            goto prgEnd;
        }
        
        println(line++,"system.xml integrity... OK!");
        sleep(1);
        
        println(line++,"Installing original default id into system.xml...");
        sleep(2);
        
        if(IOSUHAX_FSA_OpenFile(fsaFd, "/vol/system/config/system.xml", "wb", &slcFd) < 0)
        {
            println(line++,"Could not open system.xml for writing, exiting...");
            goto prgEnd;
        }
        
        //set current console system menu id in xml.
        char tagStr[20];
        sprintf(tagStr,"00050010%08X",menu_id);
        memcpy(tagPtr,tagStr,16);
        fsa_write(fsaFd,slcFd,systemBuf,systemSize);
        IOSUHAX_FSA_CloseFile(fsaFd, slcFd);
        slcFd=-1;
        
        println(line++,"Default title id installation... OK!");
        sleep(1);
        
        println(line++,"Coldboothax uninstalled succesfully.");
        sleep(1);
        
        println(line++, "Exiting... Remember to shutdown and reboot Wii U!");
        free(systemBuf);
    }
    
prgEnd:
    if(tList)
        free(tList);
    
    //close down everything fsa related
    if(fsaFd >= 0)
    {
        if(slcFd >= 0)
            IOSUHAX_FSA_CloseFile(fsaFd, slcFd);
        IOSUHAX_FSA_Close(fsaFd);
    }
    //close out old mcp instance
    MCPHookClose();
    sleep(5);
    //will do IOSU reboot
    OSForceFullRelaunch();
    SYSLaunchMenu();
    OSScreenEnableEx(0, 0);
    OSScreenEnableEx(1, 0);
    free(screenBuffer);
    return EXIT_RELAUNCH_ON_LOAD;
}
