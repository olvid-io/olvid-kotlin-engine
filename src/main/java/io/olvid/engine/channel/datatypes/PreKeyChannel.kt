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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.AuthEncKeyAndChannelInfo
import io.olvid.engine.datatypes.containers.MessageToSend
import io.olvid.engine.datatypes.containers.NetworkReceivedMessage
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.metamanager.PreKeyEncryptionDelegate
import java.sql.SQLException


class PreKeyChannel(
    private val session: Session,
    private val fromIdentity: Identity?,
    private val toIdentity: Identity?,
    private val toDeviceUid: UID?,
    private val preKeyEncryptionDelegate: PreKeyEncryptionDelegate?
) : NetworkChannel() {
    override fun wrapMessageKey(
        messageKey: AuthEncKey?,
        prng: PRNGService?,
        partOfFullRatchetProtocol: Boolean
    ): MessageToSend.Header? {
        if (preKeyEncryptionDelegate == null) {
            return null
        }
        val wrappedKey = preKeyEncryptionDelegate.wrapWithPreKey(
            session,
            messageKey,
            fromIdentity,
            toIdentity,
            toDeviceUid,
            prng
        )
        return MessageToSend.Header(toDeviceUid, toIdentity, wrappedKey)
    }

    companion object {
        @Throws(SQLException::class)
        fun unwrapMessageKey(
            channelManagerSession: ChannelManagerSession,
            header: NetworkReceivedMessage.Header
        ): AuthEncKeyAndChannelInfo? {
            if (channelManagerSession.preKeyEncryptionDelegate == null) {
                return null
            }
            return channelManagerSession.preKeyEncryptionDelegate.unwrapWithPreKey(
                channelManagerSession.session,
                header.getWrappedKey(),
                header.getOwnedIdentity()
            )
        }
    }
}
