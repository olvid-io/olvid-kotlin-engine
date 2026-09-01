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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import java.sql.SQLException


interface ChannelDelegate {
    // post a channel message to send
    @Throws(Exception::class)
    fun post(
        session: Session,
        channelMessageToSend: ChannelMessageToSend?,
        prng: PRNGService?
    ): UID?


    // Oblivious Channels management
    @Throws(Exception::class)
    fun createObliviousChannel(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?,
        seed: Seed?,
        obliviousEngineVersion: Int
    )

    @Throws(Exception::class)
    fun confirmObliviousChannel(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    )

    @Throws(Exception::class)
    fun updateObliviousChannelSendSeed(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?,
        seed: Seed?,
        obliviousEngineVersion: Int
    )

    @Throws(Exception::class)
    fun updateObliviousChannelReceiveSeed(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?,
        seed: Seed?,
        obliviousEngineVersion: Int
    )


    @Throws(Exception::class)
    fun getConfirmedObliviousChannelDeviceUids(
        session: Session,
        ownedIdentity: Identity?,
        remoteIdentity: Identity?
    ): Array<UID?>

    @Throws(Exception::class)
    fun getConfirmedObliviousChannelOrPreKeyDeviceUids(
        session: Session,
        ownedIdentity: Identity?,
        remoteIdentity: Identity?
    ): Array<UID?>

    @Throws(Exception::class)
    fun deleteObliviousChannelsWithContact(
        session: Session,
        ownedIdentity: Identity?,
        remoteIdentity: Identity?
    )

    @Throws(Exception::class)
    fun deleteObliviousChannelIfItExists(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    )

    @Throws(SQLException::class)
    fun deleteAllChannelsForOwnedIdentity(session: Session, ownedIdentity: Identity?)

    @Throws(SQLException::class)
    fun checkIfObliviousChannelExists(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun checkIfObliviousChannelIsConfirmed(
        session: Session,
        ownedIdentity: Identity?,
        remoteDeviceUid: UID?,
        remoteIdentity: Identity?
    ): Boolean
}
