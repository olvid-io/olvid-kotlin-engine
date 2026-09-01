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

import io.olvid.engine.datatypes.Session
import io.olvid.engine.metamanager.EncryptionForIdentityDelegate
import io.olvid.engine.metamanager.FullRatchetProtocolStarterDelegate
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.NetworkFetchDelegate
import io.olvid.engine.metamanager.NetworkSendDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.metamanager.PreKeyEncryptionDelegate
import io.olvid.engine.metamanager.ProtocolDelegate
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import java.lang.AutoCloseable
import java.sql.SQLException


class ChannelManagerSession(
    @JvmField val session: Session,
    @JvmField val fullRatchetProtocolStarterDelegate: FullRatchetProtocolStarterDelegate?,
    @JvmField val networkFetchDelegate: NetworkFetchDelegate?,
    @JvmField val networkSendDelegate: NetworkSendDelegate?,
    @JvmField val protocolDelegate: ProtocolDelegate?,
    @JvmField val encryptionForIdentityDelegate: EncryptionForIdentityDelegate?,
    @JvmField val preKeyEncryptionDelegate: PreKeyEncryptionDelegate?,
    @JvmField val identityDelegate: IdentityDelegate?,
    @JvmField val notificationPostingDelegate: NotificationPostingDelegate?,
    @JvmField val protocolStarterDelegate: ProtocolStarterDelegate?
) : AutoCloseable {
    @Throws(SQLException::class)
    override fun close() {
        session.close()
    }
}
