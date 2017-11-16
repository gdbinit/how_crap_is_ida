/*
 *   ___ ___
 *  /   |   \  ______  _  __   ________________  ______
 * /    ~    \/  _ \ \/ \/ / _/ ___\_  __ \__  \ \____ \
 * \    Y    (  <_> )     /  \  \___|  | \// __ \|  |_> >
 *  \___|_  / \____/ \/\_/    \___  >__|  (____  /   __/
 *        \/                      \/           \/|__|
 * .__         .___________      ______________
 * |__| ______ |   \______ \    /  _  \_____   \
 * |  |/  ___/ |   ||    |  \  /  /_\  \ /   __/
 * |  |\___ \  |   ||    `   \/    |    \   |
 * |__/____  > |___/_______  /\____|__  /___|
 *         \/              \/         \/<___>
 *
 * Created by fG! on 16/11/2017.
 * (c) fG!, 2017 - reverser@put.as - https://reverse.put.as
 * All rights reserved.
 *
 * An IDA plugin to compare IDA detected functions output versus LC_FUNCTION_STARTS information
 *
 * analyser.cpp
 *
 */

#include "analyser.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <search.hpp>
#include <allins.hpp>
#include <segment.hpp>
#include <limits.h>
#include <auto.hpp>
#include <name.hpp>
#include <frame.hpp>
#include <struct.hpp>
#include <funcs.hpp>
#include <range.hpp>
#include <ua.hpp>
#include <mach-o/loader.h>

#include "logging.h"

/**
 * @brief   Verify if loaded binary in IDA is a Mach-O
 *
 * @return  Returns 1 target appears to be Mach-O, 0 otherwise.
 */
int
is_target_macho(void)
{
    segment_t *textSeg = get_segm_by_name("HEADER");
    uint32 magicValue = get_dword(textSeg->start_ea);
    switch (magicValue)
    {
        case MH_MAGIC:
        case MH_MAGIC_64:
        case MH_CIGAM_64:
        case MH_CIGAM:
        {
            return 1;
        }
        default:
        {
            return 0;
        }
    }
}

 /**
 * @brief   Locate LC_FUNCTION_STARTS information.
 *
 * @param   fs_array    Will contain a heap allocated array with LC_FUNCTION_STARTS addresses
 * @param   fs_array_size   The array size
 *
 * @return  Returns -1 in case of error, 0 otherwise.
 */
int
find_lc_function_starts(ea_t **fs_array, uint32_t *fs_array_size)
{
    segment_t *textSeg = get_segm_by_name("HEADER");
    struct mach_header_64 mh = {0};
    int header_size = sizeof(struct mach_header_64);
    if (get_bytes(&mh, sizeof(struct mach_header_64),textSeg->start_ea) <= 0)
    {
        ERROR_MSG("Failed to read Mach-O header.");
        return -1;
    }
    
    if (mh.magic == MH_MAGIC)
    {
        header_size = sizeof(struct mach_header);
    }
    
    if (mh.filetype != MH_EXECUTE)
    {
        ERROR_MSG("Target is not Mach-O MH_EXECUTE type.");
        return -1;
    }
    
    /* we need to read the commands */
    /* XXX: no validation of sizeofcmds */
    uint8_t *loadcmds_buf = (uint8_t*)qcalloc(1, mh.sizeofcmds);
    if (loadcmds_buf == NULL)
    {
        ERROR_MSG("Failed to allocate memory.");
        return -1;
    }
    if (get_bytes(loadcmds_buf, mh.sizeofcmds, textSeg->start_ea + header_size) <= 0)
    {
        ERROR_MSG("Failed to read load commands.");
        qfree(loadcmds_buf);
        return -1;
    }
    
    struct load_command *lc = (struct load_command*)loadcmds_buf;
    
    struct load_command *lc_function = NULL;
    
    ea_t linkedit_addr = 0;
    ea_t text_addr = 0;
    uint64_t linkedit_offset = 0;
    
    for (uint32_t i = 0; i < mh.ncmds; i++)
    {
        if (lc->cmd == LC_SEGMENT)
        {
            struct segment_command *sg = (struct segment_command*)lc;
            if (strncmp(sg->segname, "__TEXT", 16) == 0)
            {
                text_addr = sg->vmaddr;
            }
            else if (strncmp(sg->segname, "__LINKEDIT", 16) == 0)
            {
                linkedit_addr = sg->vmaddr;
                linkedit_offset = sg->fileoff;
            }
        }
        else if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *sg64 = (struct segment_command_64*)lc;
            if (strncmp(sg64->segname, "__TEXT", 16) == 0)
            {
                text_addr = sg64->vmaddr;
            }
            else if (strncmp(sg64->segname, "__LINKEDIT", 16) == 0)
            {
                linkedit_addr = sg64->vmaddr;
                linkedit_offset = sg64->fileoff;
            }
        }
        else if (lc->cmd == LC_FUNCTION_STARTS)
        {
            lc_function = lc;
        }
        
        lc = (struct load_command*)((uint8_t*)lc + lc->cmdsize);
    }
    
    if (lc_function == NULL)
    {
        ERROR_MSG("No LC_FUNCTION_STARTS command found.");
        qfree(loadcmds_buf);
        return -1;
    }
    
    if (linkedit_addr == 0 || text_addr == 0 || linkedit_offset == 0)
    {
        ERROR_MSG("Missing commands to proceed with analysis.");
        qfree(loadcmds_buf);
        return -1;
    }
    
    struct linkedit_data_command *function_starts = (struct linkedit_data_command*)lc_function;
    
    ea_t function_starts_addr = linkedit_addr + (function_starts->dataoff - linkedit_offset);
    
    uint8_t *function_buf = (uint8_t*)qcalloc(1, function_starts->datasize);
    if (function_buf == NULL)
    {
        ERROR_MSG("Failed to allocate memory.");
        qfree(loadcmds_buf);
        return -1;
    }
    
    if (get_bytes(function_buf, function_starts->datasize, function_starts_addr) <= 0)
    {
        ERROR_MSG("Failed to get LC_FUNCTION_STARTS bytes.");
        qfree(loadcmds_buf);
        qfree(function_buf);
        return -1;
    }
    
    const uint8_t* infoStart = function_buf;
    const uint8_t* infoEnd = infoStart + function_starts->datasize;
    ea_t address = text_addr;
    
    uint32_t total_fs_functions = 0;
    /* count the number of entries in LC_FUNCTION_STARTS */
    for (const uint8_t* p = infoStart; (*p != 0) && (p < infoEnd); )
    {
        uint64_t delta = 0;
        uint32_t shift = 0;
        int more = 1;
        do
        {
            uint8_t byte = *p++;
            delta |= ((byte & 0x7F) << shift);
            shift += 7;
            if ( byte < 0x80 )
            {
                address += delta;
                total_fs_functions++;
                more = 0;
            }
        } while (more);
    }
    
    *fs_array_size = total_fs_functions;
    
    *fs_array = (ea_t*)qcalloc(total_fs_functions, sizeof(ea_t));
    if (*fs_array == NULL)
    {
        ERROR_MSG("Failed to allocate array.");
        qfree(loadcmds_buf);
        qfree(function_buf);
        return -1;
    }
    
    ea_t *fs_array_ptr = *fs_array;
    /* reset base address */
    address = text_addr;
    for (const uint8_t* p = infoStart; (*p != 0) && (p < infoEnd); )
    {
        uint64_t delta = 0;
        uint32_t shift = 0;
        int more = 1;
        do
        {
            uint8_t byte = *p++;
            delta |= ((byte & 0x7F) << shift);
            shift += 7;
            if ( byte < 0x80 )
            {
                address += delta;
                *fs_array_ptr = address;
                fs_array_ptr++;
                more = 0;
            }
        } while (more);
    }

end:
    qfree(loadcmds_buf);
    qfree(function_buf);
    return 0;
}

/**
 * @brief   Compare LC_FUNCTION_STARTS content against IDA functions output
 *
 * @param   fs_array    The array containing LC_FUNCTION_STARTS address info.
 * @param   fs_array_size   The array size
 *
 * @return  Returns -1 in case of error, 0 otherwise.
 */
int
compare_functions(ea_t *fs_array, uint32_t fs_array_size)
{
    uint32_t total_ida_functions = 0;
    
    /*
     * IDA's get_func_qty() count includes external library stubs
     * so we need to remove that
     */
    size_t total_functions = get_func_qty();
    for (size_t i = 0; i < total_functions; i++)
    {
        func_t *current_function = getn_func(i);
        if (current_function->flags & FUNC_THUNK)
        {
            continue;
        }
        total_ida_functions++;
    }
    
    ea_t *ida_array = (ea_t*)qcalloc(total_ida_functions, sizeof(ea_t));
    if (ida_array == NULL)
    {
        ERROR_MSG("Failed to allocate array.");
        return -1;
    }
    ea_t *ida_array_ptr = ida_array;
    
    /*
     * read again info this time to copy into our array
     */
    for (size_t i = 0; i < total_functions; i++)
    {
        func_t *current_function = getn_func(i);
        if (current_function->flags & FUNC_THUNK)
        {
            continue;
        }
        /* retrieve the start address of the function
         * it can have multiple ranges (incomplete disassembly)
         * but we only care about where IDA says it starts
         */
        rangeset_t current_range;
        if (get_func_ranges(&current_range, current_function) != BADADDR)
        {
            range_t a = current_range.getrange(0);
            *ida_array_ptr = a.start_ea;
            ida_array_ptr++;
        }
    }
    
    OUTPUT_MSG("Total functions identified by LC_FUNCTION_STARTS: %u", fs_array_size);
    OUTPUT_MSG("Total functions identified by IDA: %u", total_ida_functions);
    
    /*
     * ugly compare!
     * just a few thousand comparisons so not worth the time to implement something else
     */
    for (uint32_t i = 0; i < fs_array_size; i++)
    {
        int found = 0;
        for (uint32_t y = 0; y < total_ida_functions; y++)
        {
            if (fs_array[i] == ida_array[y])
            {
                found = 1;
                break;
            }
        }
        if (found == 0)
        {
            ERROR_MSG("LC_FUNCTION_STARTS function at address 0x%llx not found in IDA functions output.", fs_array[i]);
        }
    }
    
    qfree(ida_array);
    return 0;
}

/**
 * @brief   Entrypoint function
 *
 * @return  Returns -1 in case of error.
 */
int
do_initial_checks(void)
{
    if (is_target_macho() != 1)
    {
        ERROR_MSG("Target is not a Mach-O binary. Can't proceed.");
        return -1;
    }
    
    ea_t *fs_array = NULL;
    uint32_t fs_array_size = 0;
    if (find_lc_function_starts(&fs_array, &fs_array_size) != 0)
    {
        if (fs_array != NULL)
        {
            qfree(fs_array);
        }
        return -1;
    }
    
    compare_functions(fs_array, fs_array_size);
    
    qfree(fs_array);
    
    return 0;
}
