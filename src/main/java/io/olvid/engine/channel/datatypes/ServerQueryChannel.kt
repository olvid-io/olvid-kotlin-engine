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

import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ChannelServerQueryMessageToSend
import io.olvid.engine.datatypes.containers.MessageType
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.datatypes.containers.ServerQuery
import java.sql.SQLException

class ServerQueryChannel private constructor() : Channel() {
    @Throws(Exception::class)
    private fun doPost(
        channelManagerSession: ChannelManagerSession,
        message: ChannelMessageToSend,
        prng: PRNGService?
    ) {
        when (message.messageType) {
            MessageType.SERVER_QUERY_TYPE -> {
                val channelServerQueryMessageToSend = message as ChannelServerQueryMessageToSend
                val serverQuery = ServerQuery(
                    channelServerQueryMessageToSend.getEncodedElements(),
                    channelServerQueryMessageToSend.sendChannelInfo!!.getToIdentity(),
                    channelServerQueryMessageToSend.sendChannelInfo.getServerQueryType()!!
                )
                channelManagerSession.networkFetchDelegate!!.createPendingServerQuery(
                    channelManagerSession.session,
                    serverQuery
                )
            }

            else -> Logger.i("Trying to post a message of type " + message.messageType + " on a ServerQueryChannel.")
        }
    }

    companion object {
        @Throws(Exception::class)
        fun post(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend,
            prng: PRNGService?
        ): UID? {
            val serverQueryChannels: Array<ServerQueryChannel> =
                acceptableChannelsForPosting(channelManagerSession, message)
            if (serverQueryChannels.size == 0) {
                Logger.i("No acceptable channels were found for posting")
                throw NoAcceptableChannelException()
            }
            for (serverQueryChannel in serverQueryChannels) {
                serverQueryChannel.doPost(channelManagerSession, message, prng)
            }
            return null
        }

        @Throws(SQLException::class)
        private fun acceptableChannelsForPosting(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend
        ): Array<ServerQueryChannel> {
            when (message.sendChannelInfo!!.getChannelType()) {
                SendChannelInfo.SERVER_QUERY_TYPE ->                 // Check that the toIdentity is an OwnedIdentity
                    if (channelManagerSession.identityDelegate!!.isOwnedIdentity(
                            channelManagerSession.session,
                            message.sendChannelInfo!!.getToIdentity(),
                            false
                        )
                        || message.sendChannelInfo!!.getToIdentity()!!.server == Constants.EPHEMERAL_IDENTITY_SERVER
                    ) {
                        return arrayOf<ServerQueryChannel>(
                            ServerQueryChannel()
                        )
                    } else {
                        return arrayOf<ServerQueryChannel>()
                    }

                else -> return arrayOf<ServerQueryChannel>()
            }
        }
    }
}
