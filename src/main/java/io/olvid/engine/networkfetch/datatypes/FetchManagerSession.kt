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
package io.olvid.engine.networkfetch.datatypes

import io.olvid.engine.datatypes.Session
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networkfetch.databases.InboxAttachment.InboxAttachmentListener
import io.olvid.engine.networkfetch.databases.InboxMessage.ExtendedPayloadListener
import io.olvid.engine.networkfetch.databases.InboxMessage.InboxMessageListener
import io.olvid.engine.networkfetch.databases.InboxMessage.MarkAsListedAndDeleteOnServerListener
import io.olvid.engine.networkfetch.databases.PendingServerQuery.PendingServerQueryListener
import io.olvid.engine.networkfetch.databases.PushNotificationConfiguration.NewPushNotificationConfigurationListener
import io.olvid.engine.storage.EngineFileIo
import java.lang.AutoCloseable
import java.sql.SQLException


class FetchManagerSession(
    @JvmField val session: Session,
    @JvmField val inboxMessageListener: InboxMessageListener?,
    @JvmField val extendedPayloadListener: ExtendedPayloadListener?,
    @JvmField val markAsListedAndDeleteOnServerListener: MarkAsListedAndDeleteOnServerListener?,
    @JvmField val inboxAttachmentListener: InboxAttachmentListener?,
    @JvmField val newPushNotificationConfigurationListener: NewPushNotificationConfigurationListener?,
    @JvmField val pendingServerQueryListener: PendingServerQueryListener?,
    @JvmField val identityDelegate: IdentityDelegate?,
    @JvmField val engineBaseDirectory: String?,
    @JvmField val fileIo: EngineFileIo,
    @JvmField val notificationPostingDelegate: NotificationPostingDelegate?,
    @JvmField val createServerSessionDelegate: CreateServerSessionDelegate?
) : AutoCloseable {
    @Throws(SQLException::class)
    override fun close() {
        session.close()
    }
}
