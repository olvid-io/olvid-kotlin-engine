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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.AttachmentKeyAndMetadata
import io.olvid.engine.datatypes.containers.DecryptedApplicationMessage
import io.olvid.engine.datatypes.containers.ReceivedAttachment
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.engine.types.JsonOsmStyle
import io.olvid.engine.engine.types.ObvMessage
import java.sql.SQLException
import java.util.UUID


interface NetworkFetchDelegate {
    fun downloadMessages(ownedIdentity: Identity?, deviceUid: UID?)
    fun getMessage(ownedIdentity: Identity?, messageUid: UID?): DecryptedApplicationMessage?

    @Throws(Exception::class)
    fun setAttachmentKeyAndMetadataAndMessagePayload(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        remoteIdentity: Identity?,
        remoteDeviceUid: UID?,
        attachmentKeyAndMetadata: Array<AttachmentKeyAndMetadata?>?,
        messagePayload: ByteArray?,
        extendedPayloadKey: AuthEncKey?
    )

    @Throws(Exception::class)
    fun setInboxMessageFromIdentityForMissingPreKeyContact(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        contactIdentity: Identity?
    )

    fun downloadAttachment(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int,
        priorityCategory: Int
    )

    fun pauseDownloadAttachment(ownedIdentity: Identity?, messageUid: UID?, attachmentNumber: Int)
    fun getAttachment(
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ): ReceivedAttachment?

    @Throws(Exception::class)
    fun isInboxAttachmentReceived(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ): Boolean

    fun messageCannotBeDecrypted(session: Session, ownedIdentity: Identity?, messageUid: UID?)
    fun deleteMessageAndAttachments(session: Session, ownedIdentity: Identity?, messageUid: UID?)
    fun deleteMessage(session: Session, ownedIdentity: Identity?, messageUid: UID?)

    @Throws(SQLException::class)
    fun deleteAttachment(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    )

    @Throws(SQLException::class)
    fun markMessageAsOnHold(session: Session, ownedIdentity: Identity?, messageUid: UID?)

    @Throws(Exception::class)
    fun resendAllDownloadedAttachmentNotifications()

    @Throws(Exception::class)
    fun getOnHoldMessage(session: Session, ownedIdentity: Identity?, messageUid: UID?): ObvMessage?

    @Throws(Exception::class)
    fun createPendingServerQuery(session: Session, serverQuery: ServerQuery?)
    fun deleteExistingServerSession(
        session: Session,
        ownedIdentity: Identity?,
        createNewSession: Boolean
    )

    fun connectWebsockets(
        relyOnWebsocketForNetworkDetection: Boolean,
        os: String?,
        osVersion: String?,
        appBuild: Int,
        appVersion: String?
    )

    fun disconnectWebsockets()
    fun pingWebsocket(ownedIdentity: Identity?)
    fun getServerAuthenticationToken(ownedIdentity: Identity?): ByteArray?

    fun retryScheduledNetworkTasks()
    fun getTurnCredentials(
        ownedIdentity: Identity?,
        callUuid: UUID?,
        username1: String?,
        username2: String?
    )

    fun getWellKnownTurnServers(ownedIdentity: Identity?): MutableList<String>?
    fun getWellKnownAltTurnServers(ownedIdentity: Identity?): MutableList<String>?
    fun queryApiKeyStatus(ownedIdentity: Identity?, apiKey: UUID?)
    fun queryFreeTrial(ownedIdentity: Identity?)
    fun startFreeTrial(ownedIdentity: Identity?)
    fun verifyReceipt(ownedIdentity: Identity?, storeToken: String?)
    fun queryServerWellKnown(server: String?)
    fun getOsmStyles(server: String?): MutableList<JsonOsmStyle>?
    fun getAddressServerUrl(server: String?): String?
}
