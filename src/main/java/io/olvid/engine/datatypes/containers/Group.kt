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

import io.olvid.engine.datatypes.Identity

open class Group(
    @JvmField val groupOwnerAndUid: ByteArray?,
    @JvmField val ownedIdentity: Identity?,
    @JvmField val groupMembers: Array<Identity>,
    @JvmField val pendingGroupMembers: Array<IdentityWithSerializedDetails>,
    @JvmField val declinedPendingMembers: Array<Identity>, // NULL for groups where you are the owner
    @JvmField val groupOwner: Identity?,
    @JvmField val groupMembersVersion: Long
) {
    fun isMember(contactIdentity: Identity?): Boolean {
        for (memberIdentity in groupMembers) {
            if (memberIdentity.equals(contactIdentity)) {
                return true
            }
        }
        return false
    }

    fun isPendingMember(contactIdentity: Identity?): Boolean {
        for (pendingMember in pendingGroupMembers) {
            if (pendingMember.identity.equals(contactIdentity)) {
                return true
            }
        }
        return false
    }

    fun isDeclinedPendingMember(contactIdentity: Identity?): Boolean {
        for (pendingMember in declinedPendingMembers) {
            if (pendingMember.equals(contactIdentity)) {
                return true
            }
        }
        return false
    }
    fun getGroupOwnerAndUid(): ByteArray? = groupOwnerAndUid
    fun getOwnedIdentity(): Identity? = ownedIdentity
    fun getGroupMembers(): Array<Identity> = groupMembers
    fun getPendingGroupMembers(): Array<IdentityWithSerializedDetails> = pendingGroupMembers
    fun getDeclinedPendingMembers(): Array<Identity> = declinedPendingMembers
    fun getGroupOwner(): Identity? = groupOwner
    fun getGroupMembersVersion(): Long = groupMembersVersion
}
