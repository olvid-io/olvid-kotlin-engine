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
package io.olvid.engine.networksend.datatypes

import io.olvid.engine.datatypes.Session
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.networksend.databases.OutboxAttachment.OutboxAttachmentCanBeSentListener
import io.olvid.engine.networksend.databases.OutboxAttachment.OutboxAttachmentCancelRequestedListener
import io.olvid.engine.networksend.databases.OutboxMessage.NewOutboxMessageListener
import io.olvid.engine.networksend.databases.ReturnReceipt.NewReturnReceiptListener
import io.olvid.engine.storage.EngineFileIo
import java.lang.AutoCloseable
import java.sql.SQLException


class SendManagerSession(
    @JvmField val session: Session,
    @JvmField val newOutboxMessageListener: NewOutboxMessageListener?,
    @JvmField val outboxAttachmentCanBeSentListener: OutboxAttachmentCanBeSentListener?,
    @JvmField val outboxAttachmentCancelRequestedListener: OutboxAttachmentCancelRequestedListener?,
    @JvmField val notificationPostingDelegate: NotificationPostingDelegate?,
    @JvmField val newReturnReceiptListener: NewReturnReceiptListener?,
    @JvmField val identityDelegate: IdentityDelegate?,
    @JvmField val engineBaseDirectory: String?,
    @JvmField val fileIo: EngineFileIo
) : AutoCloseable {
    @Throws(SQLException::class)
    override fun close() {
        session.close()
    }
}
