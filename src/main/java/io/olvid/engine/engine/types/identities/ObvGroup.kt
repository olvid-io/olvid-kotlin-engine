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
package io.olvid.engine.engine.types.identities

import io.olvid.engine.engine.types.JsonGroupDetails

class ObvGroup(
    @JvmField val bytesGroupOwnerAndUid: ByteArray?,
    @JvmField val groupDetails: JsonGroupDetails?,
    @JvmField val bytesOwnedIdentity: ByteArray?,
    @JvmField val bytesGroupMembersIdentities: Array<ByteArray?>?,
    @JvmField val pendingGroupMembers: Array<ObvIdentity?>?,
    @JvmField val bytesDeclinedPendingMembers: Array<ByteArray?>?, // NULL for groups where you are the owner
    @JvmField val bytesGroupOwnerIdentity: ByteArray?
) {
    fun getBytesGroupOwnerAndUid(): ByteArray? {
        return bytesGroupOwnerAndUid
    }

    fun getGroupDetails(): JsonGroupDetails? {
        return groupDetails
    }

    fun getBytesOwnedIdentity(): ByteArray? {
        return bytesOwnedIdentity
    }

    fun getBytesGroupMembersIdentities(): Array<ByteArray?>? {
        return bytesGroupMembersIdentities
    }

    fun getPendingGroupMembers(): Array<ObvIdentity?>? {
        return pendingGroupMembers
    }

    fun getBytesDeclinedPendingMembers(): Array<ByteArray?>? {
        return bytesDeclinedPendingMembers
    }

    fun getBytesGroupOwnerIdentity(): ByteArray? { // NULL for groups where you are the owner
        return bytesGroupOwnerIdentity
    }
}
