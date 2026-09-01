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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.AttachmentKeyAndMetadata
import io.olvid.engine.datatypes.containers.MessageType
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded


class ChannelReceivedApplicationMessage private constructor(
    @JvmField val message: ChannelReceivedMessage,
    @JvmField val attachmentsKeyAndMetadata: Array<AttachmentKeyAndMetadata?>,
    @JvmField val messagePayload: ByteArray
) {
    val ownedIdentity: Identity?
        get() = message.ownedIdentity

    val messageUid: UID?
        get() = message.messageUid

    companion object {
        @JvmStatic
        fun of(channelReceivedMessage: ChannelReceivedMessage): ChannelReceivedApplicationMessage? {
            if (channelReceivedMessage.messageType != MessageType.APPLICATION_MESSAGE_TYPE) {
                return null
            }
            val channelInfo = channelReceivedMessage.receptionChannelInfo
            if (channelInfo!!.getChannelType() != ReceptionChannelInfo.OBLIVIOUS_CHANNEL_TYPE
                && channelInfo.getChannelType() != ReceptionChannelInfo.PRE_KEY_CHANNEL_TYPE
            ) {
                return null
            }

            try {
                val listOfEncoded: Array<Encoded> =
                    channelReceivedMessage.encodedElements!!.decodeList()
                val attachmentsKeyAndMetadata =
                    arrayOfNulls<AttachmentKeyAndMetadata>(listOfEncoded.size - 1)

                for (i in 0..<listOfEncoded.size - 1) {
                    val encodedParts: Array<Encoded> = listOfEncoded[i].decodeList()
                    if (encodedParts.size != 2) {
                        throw DecodingException()
                    }
                    attachmentsKeyAndMetadata[i] = AttachmentKeyAndMetadata(
                        encodedParts[0].decodeSymmetricKey() as AuthEncKey?,
                        encodedParts[1].decodeBytes()
                    )
                }

                val messagePayload = listOfEncoded[listOfEncoded.size - 1].decodeBytes()

                return ChannelReceivedApplicationMessage(
                    channelReceivedMessage,
                    attachmentsKeyAndMetadata,
                    messagePayload
                )
            } catch (_: DecodingException) {
                return null
            } catch (_: ClassCastException) {
                return null
            }
        }
    }
}
