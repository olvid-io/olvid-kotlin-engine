/*
 *  Olvid Kotlin Engine
 *  Copyright © 2019-2026 Olvid SAS
 *
 *  This file is part of the Olvid Kotlin Engine.
 *
 *  The Olvid Kotlin Engine is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License, version 3,
 *  as published by the Free Software Foundation.
 *
 *  The Olvid Kotlin Engine is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with the Olvid Kotlin Engine.  If not, see <https://www.gnu.org/licenses/>.
 */
package io.olvid.engine.channel.datatypes

import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.SendChannelInfo
abstract class Channel {
    var obliviousEngineVersion: Int = 0
        protected set

    companion object {
        @Throws(Exception::class)
        fun post(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend,
            prng: PRNGService?
        ): UID? {
            when (message.sendChannelInfo!!.getChannelType()) {
                SendChannelInfo.OBLIVIOUS_CHANNEL_TYPE, SendChannelInfo.ALL_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_ON_SAME_SERVER_TYPE, SendChannelInfo.ASYMMETRIC_CHANNEL_TYPE, SendChannelInfo.ASYMMETRIC_BROADCAST_CHANNEL_TYPE, SendChannelInfo.ALL_OWNED_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_TYPE, SendChannelInfo.OBLIVIOUS_CHANNEL_OR_PRE_KEY_TYPE -> return NetworkChannel.post(
                    channelManagerSession,
                    message,
                    prng!!
                )

                SendChannelInfo.LOCAL_TYPE -> return LocalChannel.post(
                    channelManagerSession,
                    message,
                    prng!!
                )

                SendChannelInfo.USER_INTERFACE_TYPE -> return UserInterfaceChannel.post(
                    channelManagerSession,
                    message,
                    prng
                )

                SendChannelInfo.SERVER_QUERY_TYPE -> return ServerQueryChannel.post(
                    channelManagerSession,
                    message,
                    prng
                )
            }
            return null
        }
    }
}
