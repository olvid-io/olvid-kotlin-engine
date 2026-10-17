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
package io.olvid.engine.metamanager

import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.KeyId
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.AuthEncKeyAndChannelInfo
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey


interface PreKeyEncryptionDelegate {
    fun wrapWithPreKey(
        session: Session,
        messageKey: AuthEncKey?,
        ownedIdentity: Identity?,
        remoteIdentity: Identity?,
        remoteDeviceUid: UID?,
        prng: PRNGService?
    ): EncryptedBytes?

    fun unwrapWithPreKey(
        session: Session,
        wrappedKey: EncryptedBytes?,
        ownedIdentity: Identity?
    ): AuthEncKeyAndChannelInfo?

    // record the signature of a message received through a pre-key channel, once this message is actually processed,
    // so that any replay of this message gets rejected by unwrapWithPreKey(). Returns false if the signature could not
    // be recorded (typically, if it was already recorded).
    fun recordPreKeySignatureReceived(
        session: Session,
        preKeyId: KeyId,
        signature: ByteArray
    ): Boolean
}
