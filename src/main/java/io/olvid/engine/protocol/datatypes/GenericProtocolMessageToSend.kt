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
package io.olvid.engine.protocol.datatypes

import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelDialogMessageToSend
import io.olvid.engine.datatypes.containers.ChannelProtocolMessageToSend
import io.olvid.engine.datatypes.containers.ChannelServerQueryMessageToSend
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.encoder.Encoded


class GenericProtocolMessageToSend(
    internal val sendChannelInfo: SendChannelInfo,
    protocolId: Int,
    protocolInstanceUid: UID,
    protocolMessageId: Int,
    inputs: Array<Encoded>,
    internal val hasUserContent: Boolean
) {
    internal val encodedElements: Encoded

    init {
        this.encodedElements = encode(protocolId, protocolInstanceUid, protocolMessageId, inputs)
    }

    fun generateChannelProtocolMessageToSend(): ChannelProtocolMessageToSend? {
        when (sendChannelInfo.getChannelType()) {
            SendChannelInfo.LOCAL_TYPE, SendChannelInfo.OBLIVIOUS_CHANNEL_TYPE, SendChannelInfo.ASYMMETRIC_CHANNEL_TYPE, SendChannelInfo.ALL_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_ON_SAME_SERVER_TYPE, SendChannelInfo.ASYMMETRIC_BROADCAST_CHANNEL_TYPE, SendChannelInfo.ALL_OWNED_CONFIRMED_OBLIVIOUS_CHANNELS_OR_PRE_KEY_TYPE, SendChannelInfo.OBLIVIOUS_CHANNEL_OR_PRE_KEY_TYPE -> return ChannelProtocolMessageToSend(
                sendChannelInfo,
                encodedElements,
                hasUserContent
            )

            else -> return null
        }
    }

    fun generateChannelDialogMessageToSend(): ChannelDialogMessageToSend? {
        when (sendChannelInfo.getChannelType()) {
            SendChannelInfo.USER_INTERFACE_TYPE -> {
                val uuid = sendChannelInfo.getDialogUuid() ?: return null
                val toIdentity = sendChannelInfo.getToIdentity() ?: return null
                val dialogType = sendChannelInfo.getDialogType() ?: return null
                return ChannelDialogMessageToSend(uuid, toIdentity, dialogType, encodedElements)
            }

            else -> return null
        }
    }

    fun generateChannelServerQueryMessageToSend(): ChannelServerQueryMessageToSend? {
        when (sendChannelInfo.getChannelType()) {
            SendChannelInfo.SERVER_QUERY_TYPE -> return ChannelServerQueryMessageToSend(
                sendChannelInfo.getToIdentity(),
                sendChannelInfo.getServerQueryType(),
                encodedElements
            )

            else -> return null
        }
    }

    companion object {
        private fun encode(
            protocolId: Int,
            protocolInstanceUid: UID,
            protocolMessageId: Int,
            inputs: Array<Encoded>
        ): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(protocolId.toLong()),
                    Encoded.of(protocolInstanceUid),
                    Encoded.of(protocolMessageId.toLong()),
                    Encoded.of(inputs)
                )
            )
        }
    }
}
