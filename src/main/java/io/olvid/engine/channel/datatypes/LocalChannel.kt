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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.NoAcceptableChannelException
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelDialogResponseMessageToSend
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.ChannelProtocolMessageToSend
import io.olvid.engine.datatypes.containers.ChannelServerResponseMessageToSend
import io.olvid.engine.datatypes.containers.MessageType
import io.olvid.engine.datatypes.containers.ProtocolReceivedDialogResponse
import io.olvid.engine.datatypes.containers.ProtocolReceivedMessage
import io.olvid.engine.datatypes.containers.ProtocolReceivedServerResponse
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import java.sql.SQLException


class LocalChannel private constructor(private val toIdentity: Identity?) : Channel() {
    @Throws(Exception::class)
    private fun doPost(
        channelManagerSession: ChannelManagerSession,
        message: ChannelMessageToSend,
        prng: PRNGService
    ) {
        when (message.messageType) {
            MessageType.PROTOCOL_MESSAGE_TYPE -> {
                val protocolMessageToSend = message as ChannelProtocolMessageToSend
                val messageUid = UID(prng)
                val receivedMessage = ProtocolReceivedMessage(
                    messageUid,
                    toIdentity,
                    protocolMessageToSend.getEncodedElements(),
                    ReceptionChannelInfo.createLocalChannelInfo(),
                    System.currentTimeMillis()
                )
                channelManagerSession.protocolDelegate!!.process(
                    channelManagerSession.session,
                    receivedMessage
                )
            }

            MessageType.DIALOG_RESPONSE_MESSAGE_TYPE -> {
                val dialogMessageToSend = message as ChannelDialogResponseMessageToSend
                val protocolReceivedDialogResponse = ProtocolReceivedDialogResponse(
                    dialogMessageToSend.getUuid(),
                    dialogMessageToSend.getEncodedUserDialogResponse(),
                    toIdentity,
                    dialogMessageToSend.getEncodedElements(),
                    ReceptionChannelInfo.createLocalChannelInfo(),
                    dialogMessageToSend.getUserDialogVersion()
                )
                channelManagerSession.protocolDelegate!!.process(
                    channelManagerSession.session,
                    protocolReceivedDialogResponse
                )
            }

            MessageType.SERVER_RESPONSE_TYPE -> {
                val serverResponseMessageToSend = message as ChannelServerResponseMessageToSend
                val protocolReceivedServerResponse = ProtocolReceivedServerResponse(
                    serverResponseMessageToSend.getEncodedServerResponse(),
                    toIdentity,
                    serverResponseMessageToSend.getEncodedElements(),
                    ReceptionChannelInfo.createLocalChannelInfo()
                )
                channelManagerSession.protocolDelegate!!.process(
                    channelManagerSession.session,
                    protocolReceivedServerResponse
                )
            }

            else -> Logger.i("Trying to post a message of type " + message.messageType + " on a LocalChannel.")
        }
    }


    companion object {
        @Throws(Exception::class)
        fun post(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend,
            prng: PRNGService
        ): UID? {
            val localChannels: Array<LocalChannel> =
                acceptableChannelsForPosting(channelManagerSession, message)
            if (localChannels.size == 0) {
                Logger.i("No acceptable channels were found for posting")
                throw NoAcceptableChannelException()
            }
            for (localChannel in localChannels) {
                localChannel.doPost(channelManagerSession, message, prng)
            }
            return null
        }


        @Throws(SQLException::class)
        private fun acceptableChannelsForPosting(
            channelManagerSession: ChannelManagerSession,
            message: ChannelMessageToSend
        ): Array<LocalChannel> {
            when (message.sendChannelInfo!!.getChannelType()) {
                SendChannelInfo.LOCAL_TYPE ->                 // Check that the toIdentity is an OwnedIdentity
                    if (channelManagerSession.identityDelegate!!.isOwnedIdentity(
                            channelManagerSession.session,
                            message.sendChannelInfo!!.getToIdentity(),
                            false
                        )
                        || message.sendChannelInfo!!.getToIdentity()!!.server == Constants.EPHEMERAL_IDENTITY_SERVER
                    ) {
                        return arrayOf<LocalChannel>(
                            LocalChannel(message.sendChannelInfo!!.getToIdentity())
                        )
                    } else {
                        return arrayOf<LocalChannel>()
                    }

                else -> return arrayOf<LocalChannel>()
            }
        }
    }
}
