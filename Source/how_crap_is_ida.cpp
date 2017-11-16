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
 * how_crap_is_ida.cpp
 *
 */

//// IDA SDK includes
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include "analyser.hpp"
#include "logging.h"

#define VERSION "1.0"

int IDAP_init(void)
{
    msg("----------------------------------\n");
    msg("How crap is IDA? v%s\n", VERSION);
    msg("(c) fG!, 2017 - reverser@put.as\n");
    msg("----------------------------------\n");
    return PLUGIN_OK;
}

void IDAP_term(void)
{
    return;
}

/*
 * where all the fun starts!
 */
bool IDAP_run(size_t arg)
{
    extern plugin_t PLUGIN;
    PLUGIN.flags |= PLUGIN_UNL;
    
    do_initial_checks();
    
    return true;
}

char IDAP_comment[] = "Plugin to compare IDA detected functions output versus LC_FUNCTION_STARTS information";
char IDAP_help[]    = "How crap is IDA?";
char IDAP_name[]    = "How crap is IDA?";
char IDAP_hotkey[]  = "";

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    0,
    IDAP_init,
    IDAP_term,
    IDAP_run,
    IDAP_comment,
    IDAP_help,
    IDAP_name,
    IDAP_hotkey
};
