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
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Constants.SignatureContext
import io.olvid.engine.datatypes.GroupMembersChangedCallback
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PreKeyBlobOnServer
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.TrustLevel
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.EncodedOwnedPreKey
import io.olvid.engine.datatypes.containers.Group
import io.olvid.engine.datatypes.containers.GroupInformation
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.AdministratorsChain
import io.olvid.engine.datatypes.containers.GroupV2.BlobKeys
import io.olvid.engine.datatypes.containers.GroupV2.IdentifierAndAdminStatus
import io.olvid.engine.datatypes.containers.GroupV2.IdentifierVersionAndKeys
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissions
import io.olvid.engine.datatypes.containers.GroupV2.IdentityAndPermissionsAndDetails
import io.olvid.engine.datatypes.containers.GroupV2.ServerBlob
import io.olvid.engine.datatypes.containers.GroupV2.ServerPhotoInfo
import io.olvid.engine.datatypes.containers.GroupWithDetails
import io.olvid.engine.datatypes.containers.IdentityWithSerializedDetails
import io.olvid.engine.datatypes.containers.KeycloakGroupV2UpdateOutput
import io.olvid.engine.datatypes.containers.OwnedDeviceAndPreKey
import io.olvid.engine.datatypes.containers.TrustOrigin
import io.olvid.engine.datatypes.containers.UidAndPreKey
import io.olvid.engine.datatypes.containers.UserData
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonGroupDetails
import io.olvid.engine.engine.types.JsonGroupDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.engine.types.JsonKeycloakUserDetails
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.engine.types.ObvDeviceBackupForRestore.ObvDeviceBackupProfile
import io.olvid.engine.engine.types.identities.ObvContactActiveOrInactiveReason
import io.olvid.engine.engine.types.identities.ObvGroupV2
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2DetailsAndPhotos
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.identities.ObvKeycloakState
import io.olvid.engine.engine.types.identities.ObvOwnedDevice
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate
import io.olvid.engine.engine.types.sync.ObvSyncAtom
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.sync.IdentityManagerSyncSnapshot
import io.olvid.engine.identity.datatypes.KeycloakGroupBlob
import org.jose4j.jwk.JsonWebKey
import java.sql.SQLException
import java.util.EnumSet


interface IdentityDelegate {
    @Throws(SQLException::class)
    fun isOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        excludeMarkedForDeletionIdentities: Boolean
    ): Boolean

    @Throws(SQLException::class)
    fun isActiveOwnedIdentity(session: Session, ownedIdentity: Identity?): Boolean

    @Throws(SQLException::class)
    fun generateOwnedIdentity(
        session: Session,
        server: String?,
        jsonIdentityDetails: JsonIdentityDetails?,
        keycloakState: ObvKeycloakState?,
        deviceDisplayName: String?,
        prng: PRNGService?
    ): Identity?

    @Throws(SQLException::class)
    fun deleteOwnedIdentity(session: Session, ownedIdentity: Identity?)

    @Throws(SQLException::class)
    fun getOwnedIdentities(session: Session): Array<Identity>

    @Throws(Exception::class)
    fun updateLatestIdentityDetails(
        session: Session,
        ownedIdentity: Identity?,
        jsonIdentityDetails: JsonIdentityDetails?
    )

    @Throws(Exception::class)
    fun updateOwnedIdentityPhoto(
        session: Session,
        ownedIdentity: Identity?,
        absolutePhotoUrl: String?
    )

    @Throws(Exception::class)
    fun setOwnedDetailsDownloadedPhoto(
        session: Session,
        ownedIdentity: Identity?,
        version: Int,
        decryptedPhoto: ByteArray?
    )

    @Throws(Exception::class)
    fun setOwnedIdentityDetailsServerLabelAndKey(
        session: Session,
        ownedIdentity: Identity?,
        version: Int,
        photoServerLabel: UID?,
        photoServerKey: AuthEncKey?
    )

    @Throws(SQLException::class)
    fun createOwnedIdentityServerUserData(
        session: Session,
        ownedIdentity: Identity?,
        photoServerLabel: UID?
    )

    @Throws(SQLException::class)
    fun publishLatestIdentityDetails(session: Session, ownedIdentity: Identity?): Int

    @Throws(SQLException::class)
    fun discardLatestIdentityDetails(session: Session, ownedIdentity: Identity?)

    @Throws(SQLException::class)
    fun setOwnedIdentityDetailsFromOtherDevice(
        session: Session,
        ownedIdentity: Identity?,
        ownDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?
    ): Boolean

    @Throws(SQLException::class)
    fun getOwnedIdentityPublishedAndLatestDetails(
        session: Session,
        ownedIdentity: Identity?
    ): Array<JsonIdentityDetailsWithVersionAndPhoto?>?

    fun getSerializedPublishedDetailsOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): String?

    @Throws(SQLException::class)
    fun getOwnedIdentityPublishedDetails(
        session: Session,
        ownedIdentity: Identity?
    ): JsonIdentityDetailsWithVersionAndPhoto?

    @Throws(SQLException::class)
    fun isOwnedIdentityKeycloakManaged(session: Session, ownedIdentity: Identity?): Boolean

    @Throws(SQLException::class)
    fun getOwnedIdentitiesWithKeycloakPushTopic(
        session: Session,
        pushTopic: String?
    ): MutableCollection<ObvIdentity>

    @Throws(SQLException::class)
    fun getOwnedIdentityKeycloakState(
        session: Session,
        ownedIdentity: Identity?
    ): ObvKeycloakState?

    @Throws(SQLException::class)
    fun getOwnedIdentityKeycloakSignatureKey(
        session: Session,
        ownedIdentity: Identity?
    ): JsonWebKey?

    @Throws(SQLException::class)
    fun setOwnedIdentityKeycloakSignatureKey(
        session: Session,
        ownedIdentity: Identity?,
        signatureKey: JsonWebKey?
    )

    @Throws(SQLException::class)
    fun setOwnedIdentityKeycloakSupportsIdBasedAuth(
        session: Session,
        ownedIdentity: Identity?,
        supportsIdBasedAuth: Boolean
    )

    @Throws(SQLException::class)
    fun setKeycloakLatestRevocationListTimestamp(
        session: Session,
        ownedIdentity: Identity?,
        latestRevocationListTimestamp: Long
    )

    fun unCertifyExpiredSignedContactDetails(
        session: Session,
        ownedIdentity: Identity?,
        latestRevocationListTimestamp: Long
    )

    @Throws(SQLException::class)
    fun getKeycloakPushTopics(session: Session, ownedIdentity: Identity?): MutableList<String>

    @Throws(Exception::class)
    fun verifyAndAddRevocationList(
        session: Session,
        ownedIdentity: Identity?,
        signedRevocations: MutableList<String?>?
    )

    fun verifyKeycloakSignature(
        session: Session,
        ownedIdentity: Identity?,
        signature: String?
    ): String?

    fun verifyKeycloakIdentitySignature(
        session: Session,
        ownedIdentity: Identity?,
        signature: String?
    ): JsonKeycloakUserDetails?

    @Throws(SQLException::class)
    fun getOwnedIdentityKeycloakServerUrl(session: Session, ownedIdentity: Identity?): String?

    @Throws(SQLException::class)
    fun saveKeycloakAuthState(
        session: Session,
        ownedIdentity: Identity?,
        serializedAuthState: String?
    )

    @Throws(SQLException::class)
    fun saveKeycloakJwks(session: Session, ownedIdentity: Identity?, serializedJwks: String?)

    @Throws(SQLException::class)
    fun saveKeycloakApiKey(session: Session, ownedIdentity: Identity?, apiKey: String?)

    @Throws(SQLException::class)
    fun getOwnedIdentityKeycloakUserId(session: Session, ownedIdentity: Identity?): String?

    @Throws(SQLException::class)
    fun setOwnedIdentityKeycloakUserId(session: Session, ownedIdentity: Identity?, userId: String?)

    @Throws(Exception::class)
    fun bindOwnedIdentityToKeycloak(
        session: Session,
        ownedIdentity: Identity?,
        keycloakUserId: String?,
        keycloakState: ObvKeycloakState?
    )

    @Throws(Exception::class)
    fun unbindOwnedIdentityFromKeycloak(
        session: Session,
        ownedIdentity: Identity?
    ): Int // return the version of the new details to publish

    @Throws(SQLException::class)
    fun updateKeycloakTransferRestrictedIfNeeded(
        session: Session,
        ownedIdentity: Identity?,
        serverUrl: String?,
        transferRestricted: Boolean
    )

    @Throws(SQLException::class)
    fun updateKeycloakPushTopicsIfNeeded(
        session: Session,
        ownedIdentity: Identity?,
        serverUrl: String?,
        pushTopics: MutableList<String?>?
    ): Boolean

    @Throws(SQLException::class)
    fun setOwnedIdentityKeycloakSelfRevocationTestNonce(
        session: Session,
        ownedIdentity: Identity?,
        serverUrl: String?,
        nonce: String?
    )

    @Throws(SQLException::class)
    fun getOwnedIdentityKeycloakSelfRevocationTestNonce(
        session: Session,
        ownedIdentity: Identity?,
        serverUrl: String?
    ): String?

    @Throws(Exception::class)
    fun updateKeycloakGroups(
        session: Session,
        ownedIdentity: Identity?,
        signedGroupBlobs: MutableList<String?>?,
        signedGroupDeletions: MutableList<String?>?,
        signedGroupKicks: MutableList<String?>?,
        keycloakCurrentTimestamp: Long
    )

    @Throws(SQLException::class)
    fun reactivateOwnedIdentityIfNeeded(session: Session, ownedIdentity: Identity?)

    @Throws(SQLException::class)
    fun deactivateOwnedIdentity(session: Session, ownedIdentity: Identity?)

    @Throws(SQLException::class)
    fun markOwnedIdentityForDeletion(session: Session, ownedIdentity: Identity?)


    @Throws(SQLException::class)
    fun getDeviceUidsOfOwnedIdentity(session: Session, ownedIdentity: Identity?): Array<UID?>?

    @Throws(SQLException::class)
    fun getOtherDeviceUidsOfOwnedIdentity(session: Session, ownedIdentity: Identity?): Array<UID?>?

    @Throws(SQLException::class)
    fun getCurrentDeviceUidOfOwnedIdentity(session: Session, ownedIdentity: Identity?): UID?

    @Throws(SQLException::class)
    fun getOwnedIdentityForCurrentDeviceUid(session: Session, currentDeviceUid: UID?): Identity?

    @Throws(SQLException::class)
    fun addDeviceForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        deviceUid: UID?,
        displayName: String?,
        expirationTimestamp: Long?,
        lastRegistrationTimestamp: Long?,
        preKeyBlob: PreKeyBlobOnServer?,
        channelCreationAlreadyInProgress: Boolean
    )

    @Throws(SQLException::class)
    fun updateOwnedDevice(
        session: Session,
        ownedIdentity: Identity?,
        deviceUid: UID?,
        displayName: String?,
        expirationTimestamp: Long?,
        lastRegistrationTimestamp: Long?,
        preKeyBlob: PreKeyBlobOnServer?
    )

    @Throws(SQLException::class)
    fun removeDeviceForOwnedIdentity(session: Session, ownedIdentity: Identity?, deviceUid: UID?)

    @Throws(SQLException::class)
    fun getDevicesOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): MutableList<ObvOwnedDevice>

    @Throws(SQLException::class)
    fun getDevicesAndPreKeysOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): MutableList<OwnedDeviceAndPreKey?>?

    @Throws(SQLException::class)
    fun getCurrentDeviceDisplayName(session: Session, ownedIdentity: Identity?): String?

    @Throws(SQLException::class)
    fun getLatestPreKeyForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): EncodedOwnedPreKey?

    @Throws(SQLException::class)
    fun generateNewPreKey(
        session: Session,
        ownedIdentity: Identity?,
        expirationTimestamp: Long
    ): Encoded?

    @Throws(SQLException::class)
    fun expireContactAndOwnedPreKeys(
        session: Session,
        ownedIdentity: Identity?,
        server: String?,
        serverTimestamp: Long
    )

    @Throws(SQLException::class)
    fun expireCurrentDeviceOwnedPreKeys(
        session: Session,
        ownedIdentity: Identity?,
        currentServerTimestamp: Long
    )

    @Throws(SQLException::class)
    fun getLatestChannelCreationPingTimestampForOwnedDevice(
        session: Session,
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?
    ): Long

    @Throws(Exception::class)
    fun setLatestChannelCreationPingTimestampForOwnedDevice(
        session: Session,
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?,
        timestamp: Long
    )

    @Throws(SQLException::class)
    fun isCurrentDeviceNeverRegistered(session: Session, ownedIdentity: Identity?): Boolean


    @Throws(Exception::class)
    fun addContactIdentity(
        session: Session,
        contactIdentity: Identity?,
        serializedDetails: String?,
        ownedIdentity: Identity?,
        trustOrigin: TrustOrigin?,
        oneToOne: Boolean
    )

    @Throws(SQLException::class)
    fun addTrustOriginToContact(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?,
        trustOrigin: TrustOrigin?,
        markContactAsOneToOne: Boolean
    )

    fun getContactsOfOwnedIdentity(session: Session, ownedIdentity: Identity?): Array<Identity>?

    @Throws(SQLException::class)
    fun trustPublishedContactDetails(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?
    ): JsonIdentityDetailsWithVersionAndPhoto?

    @Throws(Exception::class)
    fun setContactPublishedDetails(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?,
        jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?,
        allowDowngrade: Boolean
    )

    @Throws(Exception::class)
    fun setContactDetailsDownloadedPhoto(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?,
        version: Int,
        photo: ByteArray?
    )

    fun getSerializedPublishedDetailsOfContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): String?

    @Throws(SQLException::class)
    fun getContactIdentityTrustedDetails(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): JsonIdentityDetails?

    @Throws(SQLException::class)
    fun getContactTrustedDetailsPhotoUrl(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): String?

    @Throws(SQLException::class)
    fun contactHasUntrustedPublishedDetails(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun getContactPublishedAndTrustedDetails(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<JsonIdentityDetailsWithVersionAndPhoto?>?

    @Throws(SQLException::class)
    fun isContactIdentityCertifiedByOwnKeycloak(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun unmarkAllCertifiedByOwnKeycloakContacts(session: Session, ownedIdentity: Identity?)

    @Throws(SQLException::class)
    fun reCheckAllCertifiedByOwnKeycloakContacts(session: Session, ownedIdentity: Identity?)
    fun getTrustOriginsOfContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<TrustOrigin?>?

    @Throws(Exception::class)
    fun getContactTrustLevel(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): TrustLevel?

    @Throws(Exception::class)
    fun deleteContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        failIfGroup: Boolean
    )

    @Throws(Exception::class)
    fun getGroupOwnerAndUidsOfGroupsOwnedByContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<ByteArray?>?

    @Throws(SQLException::class)
    fun isIdentityAnActiveContactOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun isIdentityAContactOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun isIdentityAOneToOneContactOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun isIdentityANotOneToOneContactOfOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun setContactOneToOne(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        oneToOne: Boolean
    )

    //    TrustLevel getContactIdentityTrustLevel(Session session, Identity ownedIdentity, Identity contactIdentity) throws SQLException;
    @Throws(SQLException::class)
    fun getContactActiveOrInactiveReasons(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): EnumSet<ObvContactActiveOrInactiveReason>?

    @Throws(SQLException::class)
    fun forcefullyUnblockContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun reBlockForcefullyUnblockedContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Boolean

    @Throws(SQLException::class)
    fun setContactRecentlyOnline(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        recentlyOnline: Boolean
    )

    // return true if a device was indeed added, false if the device already existed, and throws an exception if adding the device failed
    @Throws(SQLException::class)
    fun addDeviceForContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        deviceUid: UID?,
        preKeyBlob: PreKeyBlobOnServer?,
        channelCreationAlreadyInProgress: Boolean
    ): Boolean

    @Throws(SQLException::class)
    fun isContactDeviceKnown(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ): Boolean

    @Throws(SQLException::class)
    fun updateContactDevicePreKey(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        deviceUid: UID?,
        preKeyBlob: PreKeyBlobOnServer?
    )

    @Throws(SQLException::class)
    fun removeDeviceForContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        deviceUid: UID?
    )

    @Throws(SQLException::class)
    fun removeAllDevicesForContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    )

    @Throws(SQLException::class)
    fun getDeviceUidsOfContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<UID?>?

    @Throws(SQLException::class)
    fun getDeviceUidsAndPreKeysOfContactIdentity(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): MutableList<UidAndPreKey?>?

    @Throws(SQLException::class)
    fun getAllDeviceUidsOfAllContactsOfAllOwnedIdentities(session: Session): MutableMap<Identity?, MutableMap<Identity?, MutableSet<UID?>?>?>

    @Throws(SQLException::class)
    fun getLatestChannelCreationPingTimestampForContactDevice(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ): Long

    @Throws(Exception::class)
    fun setLatestChannelCreationPingTimestampForContactDevice(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?,
        timestamp: Long
    )

    @Throws(SQLException::class)
    fun getContactCapabilities(
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): MutableList<ObvCapability>?

    @Throws(SQLException::class)
    fun getContactDeviceCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ): Array<String>?

    @Throws(Exception::class)
    fun setContactDeviceCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?,
        rawDeviceCapabilities: Array<String>?
    )

    @Throws(SQLException::class)
    fun getOwnCapabilities(ownedIdentity: Identity?): MutableList<ObvCapability>?

    @Throws(Exception::class)
    fun getCurrentDevicePublishedCapabilities(
        session: Session,
        ownedIdentity: Identity?
    ): List<ObvCapability>

    @Throws(Exception::class)
    fun setCurrentDevicePublishedCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        capabilities: MutableList<ObvCapability>?
    )

    @Throws(Exception::class)
    fun getOtherOwnedDeviceCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        otherDeviceUid: UID?
    ): Array<String>?

    @Throws(Exception::class)
    fun setOtherOwnedDeviceCapabilities(
        session: Session,
        ownedIdentity: Identity?,
        otherOwnedDeviceUID: UID?,
        rawDeviceCapabilities: Array<String>?
    )

    enum class DeterministicSeedContext {
        COMPUTE_SAS,
        COMPUTE_TRANSFER_SAS,
        ENCRYPT_RETURN_RECEIPT
    }

    @Throws(Exception::class)
    fun getDeterministicSeedForOwnedIdentity(
        ownedIdentity: Identity?,
        diversificationTag: ByteArray?,
        context: DeterministicSeedContext?
    ): Seed?

    @Throws(Exception::class)
    fun signIdentities(
        session: Session,
        signatureContext: SignatureContext?,
        identities: Array<Identity?>?,
        ownedIdentity: Identity?,
        prng: PRNGService
    ): ByteArray?

    @Throws(Exception::class)
    fun signChannel(
        session: Session,
        signatureContext: SignatureContext?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?,
        ownedIdentity: Identity?,
        ownedDeviceUid: UID?,
        prng: PRNGService?
    ): ByteArray?

    @Throws(Exception::class)
    fun signBlock(
        session: Session,
        signatureContext: SignatureContext?,
        block: ByteArray?,
        ownedIdentity: Identity?,
        prng: PRNGService?
    ): ByteArray?

    @Throws(Exception::class)
    fun signGroupInvitationNonce(
        session: Session,
        signatureContext: SignatureContext?,
        groupIdentifier: GroupV2.Identifier?,
        nonce: ByteArray,
        contactIdentity: Identity?,
        ownedIdentity: Identity?,
        prng: PRNGService
    ): ByteArray?

    @Throws(Exception::class)
    fun createContactGroup(
        session: Session,
        ownedIdentity: Identity?,
        groupInformation: GroupInformation?,
        groupMembers: Array<Identity?>?,
        pendingGroupMembers: Array<IdentityWithSerializedDetails?>?,
        createdByMeOnOtherDevice: Boolean
    )

    @Throws(Exception::class)
    fun leaveGroup(session: Session, groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun addPendingMembersToGroup(
        session: Session,
        groupUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentities: Array<Identity?>?,
        groupMembersChangedCallback: GroupMembersChangedCallback?
    )

    @Throws(Exception::class)
    fun removeMembersAndPendingFromGroup(
        session: Session,
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentities: Array<Identity?>?,
        groupMembersChangedCallback: GroupMembersChangedCallback?
    )

    @Throws(Exception::class)
    fun addGroupMemberFromPendingMember(
        session: Session,
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        groupMembersChangedCallback: GroupMembersChangedCallback?
    )

    @Throws(Exception::class)
    fun demoteGroupMemberToDeclinedPendingMember(
        session: Session,
        groupOwnerAndUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        groupMembersChangedCallback: GroupMembersChangedCallback?
    )

    @Throws(Exception::class)
    fun setPendingMemberDeclined(
        session: Session,
        groupUid: ByteArray?,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        declined: Boolean
    )

    @Throws(Exception::class)
    fun updateGroupMembersAndDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupInformation: GroupInformation?,
        groupMembers: HashSet<IdentityWithSerializedDetails?>?,
        pendingMembers: HashSet<IdentityWithSerializedDetails?>?,
        membersVersion: Long
    )

    @Throws(Exception::class)
    fun deleteGroup(session: Session, groupOwnerAndUid: ByteArray?, ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun resetGroupMembersAndPublishedDetailsVersions(
        session: Session,
        ownedIdentity: Identity?,
        groupInformation: GroupInformation?
    )

    @Throws(SQLException::class)
    fun forcefullyRemoveMemberOrPendingFromJoinedGroup(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        contactIdentity: Identity?
    )

    @Throws(Exception::class)
    fun getGroupsForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): Array<GroupWithDetails>

    @Throws(Exception::class)
    fun getGroup(session: Session, ownedIdentity: Identity?, groupOwnerAndUid: ByteArray?): Group?

    @Throws(Exception::class)
    fun getGroupWithDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): GroupWithDetails?

    @Throws(Exception::class)
    fun getGroupInformation(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): GroupInformation?

    @Throws(SQLException::class)
    fun getGroupPublishedAndLatestOrTrustedDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): Array<JsonGroupDetailsWithVersionAndPhoto?>?

    @Throws(SQLException::class)
    fun getGroupPhotoUrl(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): String?

    @Throws(SQLException::class)
    fun trustPublishedGroupDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): JsonGroupDetailsWithVersionAndPhoto?

    @Throws(Exception::class)
    fun updateLatestGroupDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        jsonGroupDetails: JsonGroupDetails?
    )

    @Throws(Exception::class)
    fun setOwnedGroupDetailsServerLabelAndKey(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        version: Int,
        photoServerLabel: UID?,
        photoServerKey: AuthEncKey?
    )

    @Throws(SQLException::class)
    fun createGroupV1ServerUserData(
        session: Session,
        ownedIdentity: Identity?,
        photoServerLabel: UID?,
        groupOwnerAndUid: ByteArray?
    )

    @Throws(Exception::class)
    fun updateOwnedGroupPhoto(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        absolutePhotoUrl: String?,
        partOfGroupCreation: Boolean
    )

    @Throws(Exception::class)
    fun setContactGroupDownloadedPhoto(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?,
        version: Int,
        photo: ByteArray?
    )

    @Throws(SQLException::class)
    fun publishLatestGroupDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    ): Int

    @Throws(SQLException::class)
    fun discardLatestGroupDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupOwnerAndUid: ByteArray?
    )

    fun getGroupOwnerAndUidOfGroupsWhereContactIsPending(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?
    ): Array<ByteArray>

    @Throws(SQLException::class)
    fun getGroupOwnerAndUidsOfGroupsContainingContact(
        session: Session,
        contactIdentity: Identity?,
        ownedIdentity: Identity?
    ): Array<ByteArray>

    fun refreshMembersOfGroupsOwnedByGroupOwner(currentDeviceUid: UID?, groupOwner: Identity?)
    fun pushMembersOfOwnedGroupsToContact(currentDeviceUid: UID?, contactIdentity: Identity?)


    // region groups v2
    @Throws(Exception::class)
    fun createNewGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serializedGroupDetails: String?,
        absolutePhotoUrl: String?,
        serverPhotoInfo: ServerPhotoInfo?,
        verifiedAdministratorsChain: ByteArray?,
        blobKeys: BlobKeys?,
        ownGroupInvitationNonce: ByteArray?,
        ownPermissionStrings: MutableList<String?>?,
        otherGroupMembers: HashSet<IdentityAndPermissionsAndDetails?>?,
        serializedGroupType: String?
    )

    @Throws(Exception::class)
    fun createJoinedGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        blobKeys: BlobKeys?,
        serverBlob: ServerBlob?,
        createdByMeOnOtherDevice: Boolean,
        inviterIdentity: Identity?,
        groupUpdateTimestamp: Long?
    ): Boolean

    @Throws(SQLException::class)
    fun getGroupV2ServerBlob(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): ServerBlob?

    @Throws(SQLException::class)
    fun getGroupV2PhotoUrl(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): String?

    @Throws(SQLException::class)
    fun deleteGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        deletedBy: Identity?
    )

    @Throws(SQLException::class)
    fun freezeGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    )

    @Throws(SQLException::class)
    fun unfreezeGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    )

    @Throws(SQLException::class)
    fun getGroupV2Version(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Int?

    @Throws(SQLException::class)
    fun getGroupV2JsonGroupType(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): String?

    @Throws(SQLException::class)
    fun isGroupV2Frozen(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Boolean

    @Throws(SQLException::class)
    fun getGroupV2BlobKeys(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): BlobKeys?

    @Throws(Exception::class)
    fun getGroupV2OtherMembersAndPermissions(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): HashSet<IdentityAndPermissions?>?

    @Throws(Exception::class)
    fun getGroupV2HasOtherAdminMember(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Boolean

    @Throws(SQLException::class)
    fun updateGroupV2WithNewBlob(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serverBlob: ServerBlob?,
        blobKeys: BlobKeys?,
        updatedByMe: Boolean,
        updatedBy: Identity?,
        leavers: MutableList<Identity?>?,
        groupUpdateTimestamp: Long?
    ): MutableList<Identity?>?

    @Throws(Exception::class)
    fun getGroupV2MembersAndPendingMembersFromNonce(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        groupMemberInvitationNonce: ByteArray?
    ): MutableList<Identity?>?

    @Throws(SQLException::class)
    fun getGroupV2OwnGroupInvitationNonce(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): ByteArray?

    @Throws(Exception::class)
    fun moveGroupV2PendingMemberToMembers(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        groupMemberIdentity: Identity?
    )

    @Throws(Exception::class)
    fun setGroupV2DownloadedPhoto(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        serverPhotoInfo: ServerPhotoInfo?,
        photo: ByteArray?
    )

    @Throws(Exception::class)
    fun getObvGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): ObvGroupV2?

    @Throws(SQLException::class)
    fun trustGroupV2PublishedDetails(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Int

    fun getGroupV2PublishedServerPhotoInfo(
        session: Session,
        ownedIdentity: Identity?,
        bytesGroupIdentifier: ByteArray?
    ): ServerPhotoInfo?

    fun getGroupV2DetailsAndPhotos(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): ObvGroupV2DetailsAndPhotos?

    @Throws(Exception::class)
    fun setUpdatedGroupV2PhotoUrl(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        version: Int,
        absolutePhotoUrl: String?
    )

    @Throws(Exception::class)
    fun getGroupV2AdministratorsChain(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): AdministratorsChain?

    @Throws(Exception::class)
    fun getGroupV2AdminStatus(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Boolean

    @Throws(Exception::class)
    fun getObvGroupsV2ForOwnedIdentity(
        session: Session,
        ownedIdentity: Identity?
    ): MutableList<ObvGroupV2>

    @Throws(Exception::class)
    fun getServerGroupsV2IdentifierVersionAndKeysForContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<IdentifierVersionAndKeys?>

    @Throws(Exception::class)
    fun getAllServerGroupsV2IdentifierVersionAndKeys(
        session: Session,
        ownedIdentity: Identity?
    ): Array<IdentifierVersionAndKeys?>?

    @Throws(Exception::class)
    fun getServerGroupsV2IdentifierAndMyAdminStatusForContact(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?
    ): Array<IdentifierAndAdminStatus?>?

    fun initiateGroupV2BatchKeysResend(
        currentDeviceUid: UID?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    )

    @Throws(SQLException::class)
    fun forcefullyRemoveMemberOrPendingFromNonAdminGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        contactIdentity: Identity?
    )

    @Throws(SQLException::class)
    fun getGroupV2LastModificationTimestamp(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?
    ): Long?

    fun createKeycloakGroupV2(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        keycloakGroupBlob: KeycloakGroupBlob?
    ): ByteArray?

    @Throws(Exception::class)
    fun updateKeycloakGroupV2WithNewBlob(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        keycloakGroupBlob: KeycloakGroupBlob?
    ): KeycloakGroupV2UpdateOutput?

    @Throws(SQLException::class)
    fun rePingOrDemoteContactFromAllKeycloakGroups(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        certifiedByOwnKeycloak: Boolean,
        lastKnownSerializedCertifiedDetails: String?
    )

    @Throws(SQLException::class)
    fun isIdentityAPendingGroupV2Member(
        session: Session,
        ownedIdentity: Identity?,
        groupIdentifier: GroupV2.Identifier?,
        identity: Identity?
    ): Boolean


    // endregion
    fun initiateBackup(
        backupDelegate: BackupDelegate?,
        tag: String?,
        backupKeyUid: UID?,
        version: Int
    )

    fun restoreOwnedIdentitiesFromBackup(
        serializedJsonPojo: String?,
        deviceDisplayName: String?,
        prng: PRNGService?
    ): Array<ObvIdentity?>?

    fun restoreContactsAndGroupsFromBackup(
        serializedJsonPojo: String?,
        restoredOwnedIdentities: Array<ObvIdentity?>?,
        backupTimestamp: Long
    )

    @Throws(Exception::class)
    fun restoreTransferredOwnedIdentity(
        session: Session,
        deviceName: String?,
        node: IdentityManagerSyncSnapshot?
    ): ObvIdentity

    @Throws(SQLException::class)
    fun getOwnedIdentityBackupSeed(session: Session, ownedIdentity: Identity?): BackupSeed?

    @Throws(Exception::class)
    fun getDeviceBackupProfileListFromDeviceBackup(
        session: Session,
        snapshotNode: ObvSyncSnapshotNode?
    ): MutableList<ObvDeviceBackupProfile?>?

    // userData
    @Throws(Exception::class)
    fun getAllUserData(session: Session): Array<UserData?>?

    @Throws(Exception::class)
    fun getUserData(session: Session, ownedIdentity: Identity?, label: UID?): UserData?

    @Throws(Exception::class)
    fun deleteUserData(session: Session, ownedIdentity: Identity?, label: UID?)

    @Throws(Exception::class)
    fun updateUserDataNextRefreshTimestamp(session: Session, ownedIdentity: Identity?, label: UID?)

    // device sync
    @Throws(Exception::class)
    fun processSyncItem(session: Session, ownedIdentity: Identity?, obvSyncAtom: ObvSyncAtom?)

    val syncDelegate: ObvBackupAndSyncDelegate?
    fun getSyncDelegateWithinTransaction(session: Session): ObvBackupAndSyncDelegate


    @Throws(Exception::class)
    fun downloadAllUserData(session: Session)
}
