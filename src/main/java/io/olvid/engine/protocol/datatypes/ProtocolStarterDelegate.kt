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
package io.olvid.engine.protocol.datatypes

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissions
import io.olvid.engine.datatypes.containers.GroupV2.ServerPhotoInfo
import io.olvid.engine.datatypes.containers.IdentityWithSerializedDetails
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.engine.types.ObvDeviceManagementRequest
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2ChangeSet
import io.olvid.engine.engine.types.identities.ObvKeycloakState
import io.olvid.engine.engine.types.sync.ObvSyncAtom


interface ProtocolStarterDelegate {
    @Throws(Exception::class)
    fun startDeviceDiscoveryProtocol(ownedIdentity: Identity?, contactIdentity: Identity?)

    @Throws(Exception::class)
    fun startDeviceDiscoveryProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    )

    @Throws(Exception::class)
    fun startOwnedDeviceDiscoveryProtocol(ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun startOwnedDeviceDiscoveryProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?
    )

    @Throws(Exception::class)
    fun startChannelCreationProtocolWithOwnedDevice(
        session: Session,
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?
    )

    @Throws(Exception::class)
    fun startChannelCreationProtocolWithContactDevice(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    )

    @Throws(Exception::class)
    fun startTrustEstablishmentProtocol(
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDisplayName: String?
    )

    @Throws(Exception::class)
    fun startMutualScanTrustEstablishmentProtocol(
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        signature: ByteArray?
    )

    @Throws(Exception::class)
    fun startContactMutualIntroductionProtocol(
        ownedIdentity: Identity?,
        contactIdentityA: Identity?,
        contactIdentities: Array<Identity?>?
    )

    @Throws(Exception::class)
    fun startGroupCreationProtocol(
        ownedIdentity: Identity?,
        serializedGroupDetailsWithVersionAndPhoto: String?,
        absolutePhotoUrl: String?,
        groupMemberIdentitiesAndSerializedDetails: HashSet<IdentityWithSerializedDetails?>?
    )

    @Throws(Exception::class)
    fun startGroupV2CreationProtocol(
        ownedIdentity: Identity?,
        serializedGroupDetails: String?,
        absolutePhotoUrl: String?,
        ownPermissions: HashSet<GroupV2.Permission?>?,
        otherGroupMembers: HashSet<IdentityAndPermissions?>?,
        serializedGroupType: String?
    )

    @Throws(Exception::class)
    fun initiateGroupV2Update(
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        changeSet: ObvGroupV2ChangeSet?
    )

    @Throws(Exception::class)
    fun initiateGroupV2Leave(ownedIdentity: Identity?, groupIdentifier: GroupV2.Identifier?)

    @Throws(Exception::class)
    fun initiateGroupV2Disband(ownedIdentity: Identity?, groupIdentifier: GroupV2.Identifier?)

    @Throws(Exception::class)
    fun initiateGroupV2ReDownload(ownedIdentity: Identity?, groupIdentifier: GroupV2.Identifier?)

    @Throws(Exception::class)
    fun initiateGroupV2BatchKeysResend(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    )

    @Throws(Exception::class)
    fun createOrUpdateKeycloakGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serializedKeycloakGroupBlob: String?
    )

    @Throws(Exception::class)
    fun processDeviceManagementRequest(
        ownedIdentity: Identity?,
        deviceManagementRequest: ObvDeviceManagementRequest?
    )

    @Throws(Exception::class)
    fun processDeviceManagementRequest(
        session: Session,
        ownedIdentity: Identity?,
        deviceManagementRequest: ObvDeviceManagementRequest?
    )

    @Throws(Exception::class)
    fun startIdentityDetailsPublicationProtocol(
        session: Session,
        ownedIdentity: Identity?,
        version: Int
    )

    @Throws(Exception::class)
    fun startGroupDetailsPublicationProtocol(
        session: Session,
        ownedIdentity: Identity?,
        groupUid: ByteArray?
    )

    @Throws(Exception::class)
    fun startOneToOneInvitationProtocol(ownedIdentity: Identity?, contactIdentity: Identity?)

    @Throws(Exception::class)
    fun deleteContact(ownedIdentity: Identity?, contactIdentity: Identity?)

    @Throws(Exception::class)
    fun downgradeOneToOneContact(ownedIdentity: Identity?, contactIdentity: Identity?)

    @Throws(Exception::class)
    fun addKeycloakContact(
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        signedContactDetails: String?
    )

    @Throws(Exception::class)
    fun startProtocolForBindingOwnedIdentityToKeycloakWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        keycloakState: ObvKeycloakState?,
        keycloakUserId: String?
    )

    @Throws(Exception::class)
    fun updateCurrentDeviceCapabilitiesForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        newOwnCapabilities: MutableList<ObvCapability>?
    )

    @Throws(Exception::class)
    fun startProtocolForUnbindingOwnedIdentityFromKeycloak(ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun startOwnedIdentityDeletionProtocol(
        session: Session,
        ownedIdentity: Identity?,
        deleteEverywhere: Boolean
    )

    @Throws(Exception::class)
    fun inviteContactsToGroup(
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        newMembersIdentity: HashSet<Identity?>?
    )

    @Throws(Exception::class)
    fun reinvitePendingToGroup(
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        pendingMemberIdentity: Identity?
    )

    @Throws(Exception::class)
    fun removeContactsFromGroup(
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        removedMemberIdentities: HashSet<Identity?>?
    )

    @Throws(Exception::class)
    fun leaveGroup(groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun disbandGroup(groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun queryGroupMembers(groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun reinviteAndPushMembersToContact(
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    )

    @Throws(Exception::class)
    fun startDownloadIdentityPhotoProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?
    )

    @Throws(Exception::class)
    fun startDownloadGroupPhotoProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        jsonGroupDetailsWithVersionAndPhoto: JsonGroupDetailsWithVersionAndPhoto?
    )

    @Throws(Exception::class)
    fun startDownloadGroupV2PhotoProtocolWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serverPhotoInfo: ServerPhotoInfo?
    )

    @Throws(Exception::class)
    fun initiateGroupV2ReDownloadWithinTransaction(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    )

    @Throws(Exception::class)
    fun initiateKeycloakGroupV2TargetedPing(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        contactIdentity: Identity?
    )

    @Throws(Exception::class)
    fun initiateSingleItemSync(
        session: Session,
        ownedIdentity: Identity?,
        obvSyncAtom: ObvSyncAtom?
    )

    //    void triggerOwnedDevicesSync(Session session, Identity ownedIdentity);
    @Throws(Exception::class)
    fun initiateOwnedIdentityTransferProtocolOnSourceDevice(ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun initiateOwnedIdentityTransferProtocolOnTargetDevice(deviceName: String?)
}
