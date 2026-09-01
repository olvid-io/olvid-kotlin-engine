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
package io.olvid.engine.engine.types.sync

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.engine.types.identities.ObvIdentity

interface ObvBackupAndSyncDelegate {
    /**/// */ // Return a tag corresponding to this delegate
    val tag: String?
        /**/
        get

    /**/// */ // This method computes a snapshot of the data to sync
    fun getSyncSnapshot(ownedIdentity: Identity?): ObvSyncSnapshotNode?

    /**/// */ // This method allows each delegate to crate an owned identity base on the ObvIdentity the engine has restored
    @Throws(Exception::class)
    fun restoreOwnedIdentity(
        ownedIdentity: ObvIdentity?,
        node: ObvSyncSnapshotNode?
    ): RestoreFinishedCallback?

    /**/// */ // This method restores a Snapshot, assuming the owned identity already exists in db.
    // - it may return a callback that will only get called if the restore was successful for all delegates.
    // - this callback can be used to commit a transaction on app side, only if the engine restore is successful, and roll it back otherwise
    @Throws(Exception::class)
    fun restoreSyncSnapshot(node: ObvSyncSnapshotNode?): RestoreFinishedCallback?

    /**/// */ // Method used to serialize a snapshot node
    @Throws(Exception::class)
    fun serialize(
        serializationContext: SerializationContext?,
        snapshotNode: ObvSyncSnapshotNode?
    ): ByteArray?

    /**/// */ // Method used to deserialize a node that was serialized with ObvSyncSnapshotNode.serialize(ObjectMapper jsonObjectMapper)
    @Throws(Exception::class)
    fun deserialize(
        serializationContext: SerializationContext?,
        serializedSnapshotNode: ByteArray?
    ): ObvSyncSnapshotNode?


    /**/// */ // Method used to obtain a device snapshot, containing info about all profiles
    fun getDeviceSnapshot(): ObvSyncSnapshotNode?
    fun getAdditionalProfileInfo(ownedIdentity: Identity?): MutableMap<String?, String?>?


    interface RestoreFinishedCallback {
        fun onRestoreSuccess()
        fun onRestoreFailure()
    }

    enum class SerializationContext {
        DEVICE,
        PROFILE,
    }
}
