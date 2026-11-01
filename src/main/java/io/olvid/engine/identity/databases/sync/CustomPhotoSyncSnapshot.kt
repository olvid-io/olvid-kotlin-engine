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
package io.olvid.engine.identity.databases.sync

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncAtom.DiscussionIdentifier
import io.olvid.engine.identity.databases.CustomPhoto
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.SQLException

// The photo itself is downloaded after the restore, by downloadAllUserData
@JsonIgnoreProperties(ignoreUnknown = true)
class CustomPhotoSyncSnapshot {
    @JvmField var photo_server_label: ByteArray? = null
    @JvmField var photo_server_key: ByteArray? = null
    @JvmField var hidden: Boolean? = null // the published photo is hidden

    // a custom photo that cannot be restored must not fail the restore of its contact or group
    @JsonIgnore
    fun restore(identityManagerSession: IdentityManagerSession, ownedIdentity: Identity, target: DiscussionIdentifier) {
        try {
            if (hidden == true) {
                CustomPhoto.createHidden(identityManagerSession, ownedIdentity, target, false)
                return
            }
            val serverPhotoInfo = GroupV2.ServerPhotoInfo(
                ownedIdentity,
                UID(photo_server_label!!),
                Encoded(photo_server_key!!).decodeSymmetricKey() as AuthEncKey
            )
            CustomPhoto.createToDownload(identityManagerSession, ownedIdentity, target, serverPhotoInfo)
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    companion object {
        @Throws(SQLException::class)
        fun of(identityManagerSession: IdentityManagerSession, ownedIdentity: Identity, target: DiscussionIdentifier): CustomPhotoSyncSnapshot? {
            val customPhoto = CustomPhoto.get(identityManagerSession, ownedIdentity, target) ?: return null
            val snapshot = CustomPhotoSyncSnapshot()
            val serverPhotoInfo = customPhoto.serverPhotoInfo
            if (serverPhotoInfo == null) {
                snapshot.hidden = true
            } else {
                snapshot.photo_server_label = serverPhotoInfo.serverPhotoLabel.bytes
                snapshot.photo_server_key = Encoded.of(serverPhotoInfo.serverPhotoKey).bytes
            }
            return snapshot
        }
    }
}
