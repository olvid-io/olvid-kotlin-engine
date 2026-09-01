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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID

data class IdentityAndUidAndDeletedOrMarkAsListed(val ownedIdentity: Identity, val uid: UID, val deleteOrMarkAsListed: DeleteOrMarkAsListed)

data class UidAndDeletedOrMarkAsListed(val uid: UID, val deleteOrMarkAsListed: DeleteOrMarkAsListed) {
    fun isMarkAsListed(): Boolean {
        return deleteOrMarkAsListed == DeleteOrMarkAsListed.MARK_AS_LISTED
    }
}


enum class DeleteOrMarkAsListed {
    DELETE_EVERYWHERE,
    MARK_AS_LISTED,
    DELETE_FROM_SERVER_BUT_NOT_LOCALLY, // this is used for application messages without attachments to delete them from the server, but still keep the local InboxMessage
}