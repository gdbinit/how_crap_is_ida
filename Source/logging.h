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
 * logging.h
 *
 */

#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>

#define ERROR_MSG(fmt, ...) msg("[ERROR] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) msg(fmt " \n", ## __VA_ARGS__)
#if DEBUG == 0
#   define DEBUG_MSG(fmt, ...) do {} while (0)
#else
#   define DEBUG_MSG(fmt, ...) msg("[DEBUG] " fmt "\n", ## __VA_ARGS__)
#endif
