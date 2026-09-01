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
package io.olvid.engine.datatypes.containers

import io.olvid.engine.channel.datatypes.ChannelReceivedMessage
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.Encoded


class ProtocolReceivedMessage(
    @JvmField val messageUid: UID?,
    @JvmField val ownedIdentity: Identity?,
    @JvmField val encodedElements: Encoded?,
    @JvmField val receptionChannelInfo: ReceptionChannelInfo?,
    @JvmField val serverTimestamp: Long
) {
    companion object {
        @JvmStatic
        fun of(message: ChannelReceivedMessage): ProtocolReceivedMessage? {
            if (message.messageType != MessageType.PROTOCOL_MESSAGE_TYPE) {
                return null
            }
            return ProtocolReceivedMessage(
                message.messageUid,
                message.ownedIdentity,
                message.encodedElements,
                message.receptionChannelInfo,
                message.message.serverTimestamp
            )
        }
    }
    fun getMessageUid(): UID? = messageUid
    fun getOwnedIdentity(): Identity? = ownedIdentity
    fun getEncodedElements(): Encoded? = encodedElements
    fun getReceptionChannelInfo(): ReceptionChannelInfo? = receptionChannelInfo
    fun getServerTimestamp(): Long = serverTimestamp
}
