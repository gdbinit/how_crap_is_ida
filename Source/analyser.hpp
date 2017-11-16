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
 * analyser.hpp
 *
 */

#pragma once

#include <stdint.h>
#include <sys/mman.h>

int do_initial_checks(void);
