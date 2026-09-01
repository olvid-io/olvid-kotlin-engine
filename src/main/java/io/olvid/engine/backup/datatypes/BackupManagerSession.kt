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
package io.olvid.engine.backup.datatypes

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Session
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.metamanager.NotificationPostingDelegate
import java.lang.AutoCloseable
import java.sql.SQLException

class BackupManagerSession(
    @JvmField val session: Session,
    @JvmField val notificationPostingDelegate: NotificationPostingDelegate?,
    @JvmField val identityDelegate: IdentityDelegate?,
    @JvmField val appBackupAndSyncDelegate: ObvBackupAndSyncDelegate?,
    @JvmField val jsonObjectMapper: ObjectMapper?,
    @JvmField val prng: PRNGService?
) : AutoCloseable {
    @Throws(SQLException::class)
    override fun close() {
        session.close()
    }
}
