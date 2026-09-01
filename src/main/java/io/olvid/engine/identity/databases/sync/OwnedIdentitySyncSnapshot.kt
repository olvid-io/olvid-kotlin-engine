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
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvBytesKey
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.engine.types.ObvGroupOwnerAndUidKey
import io.olvid.engine.engine.types.identities.ObvIdentity
import io.olvid.engine.engine.types.sync.ObvSyncDiff
import io.olvid.engine.engine.types.sync.ObvSyncSnapshotNode
import io.olvid.engine.identity.databases.ContactGroup
import io.olvid.engine.identity.databases.ContactGroupV2
import io.olvid.engine.identity.databases.ContactIdentity
import io.olvid.engine.identity.databases.KeycloakServer
import io.olvid.engine.identity.databases.OwnedDevice
import io.olvid.engine.identity.databases.OwnedIdentity
import io.olvid.engine.identity.databases.OwnedIdentityDetails
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.protocol.datatypes.ProtocolStarterDelegate
import java.sql.SQLException
import java.util.Arrays

@JsonIgnoreProperties(ignoreUnknown = true)
class OwnedIdentitySyncSnapshot : ObvSyncSnapshotNode {
    @JvmField var private_identity: PrivateIdentity? = null
    @JvmField var published_details: IdentityDetailsSyncSnapshot? = null
    @JvmField var keycloak: KeycloakSyncSnapshot? = null
    @JvmField var backup_seed: ByteArray? = null

    @JsonSerialize(keyUsing = ObvBytesKey.KeySerializer::class)
    @JsonDeserialize(keyUsing = ObvBytesKey.KeyDeserializer::class)
    var contacts: HashMap<ObvBytesKey?, ContactSyncSnapshot?>? = null

    @JsonSerialize(keyUsing = ObvGroupOwnerAndUidKey.Serializer::class)
    @JsonDeserialize(keyUsing = ObvGroupOwnerAndUidKey.Deserializer::class)
    var groups: HashMap<ObvGroupOwnerAndUidKey?, GroupV1SyncSnapshot?>? = null

    @JsonSerialize(keyUsing = ObvBytesKey.KeySerializer::class)
    @JsonDeserialize(keyUsing = ObvBytesKey.KeyDeserializer::class)
    var groups2: HashMap<ObvBytesKey?, GroupV2SyncSnapshot?>? = null
    @JvmField var domain: HashSet<String>? = null


    @JsonIgnore
    @Throws(Exception::class)
    fun restoreOwnedIdentity(
        identityManagerSession: IdentityManagerSession,
        deviceName: String?,
        ownedIdentity: Identity
    ): ObvIdentity {
        if (!domain!!.contains(PRIVATE_IDENTITY) || !domain!!.contains(PUBLISHED_DETAILS)) {
            Logger.e("Trying to restore an incomplete OwnedIdentitySyncSnapshot. Domain: " + domain)
            throw Exception()
        }

        // restore the private key
        val serverAuthenticationPrivateKey =
            Encoded(private_identity!!.server_authentication_private_key!!).decodePrivateKey() as ServerAuthenticationPrivateKey?
        val encryptionPrivateKey =
            Encoded(private_identity!!.encryption_private_key!!).decodePrivateKey() as EncryptionPrivateKey?
        val macKey = Encoded(private_identity!!.mac_key!!).decodeSymmetricKey() as MACKey?
        val privateIdentity = io.olvid.engine.datatypes.PrivateIdentity(
            ownedIdentity,
            serverAuthenticationPrivateKey!!,
            encryptionPrivateKey!!,
            macKey!!
        )

        // restore published details
        val ownedIdentityDetails =
            published_details!!.restoreOwned(identityManagerSession, ownedIdentity)

        // restore a backup_seed if present, otherwise fallback to the deterministic seed for legacy identity
        var backupSeed: BackupSeed? = null
        if (domain!!.contains(BACKUP_SEED) && backup_seed != null) {
            try {
                backupSeed = BackupSeed(backup_seed!!)
            } catch (_: Exception) {
                backupSeed = privateIdentity.getDeterministicBackupSeedForLegacyIdentity()
            }
        } else {
            backupSeed = privateIdentity.getDeterministicBackupSeedForLegacyIdentity()
        }

        // create the owned identity in DB
        val ownedIdentityObject = OwnedIdentity(
            identityManagerSession,
            privateIdentity,
            backupSeed,
            ownedIdentityDetails.version
        )
        ownedIdentityObject.insert()

        // restore keycloak data (if any)
        if (domain!!.contains(KEYCLOAK) && keycloak != null) {
            val keycloakSnapshot = keycloak!!
            val keycloakServer = keycloakSnapshot.restore(identityManagerSession, ownedIdentity, keycloakSnapshot)
            if (keycloakServer != null) {
                ownedIdentityObject.setKeycloakServerUrl(keycloakServer.serverUrl)
            }
        }

        // create the current device with a random deviceUid
        val currentOwnedDevice: OwnedDevice? = OwnedDevice.createCurrentDevice(
            identityManagerSession,
            ownedIdentity,
            deviceName,
            identityManagerSession.prng!!
        )
        currentOwnedDevice?.rawDeviceCapabilities = ObvCapability.capabilityListToStringArray(
            ObvCapability.currentCapabilities
        )

        return ObvIdentity(
            ownedIdentity,
            ownedIdentityDetails.jsonIdentityDetails,
            ownedIdentityObject.isKeycloakManaged,
            true
        )
    }

    @JsonIgnore
    @Throws(Exception::class)
    fun restore(
        identityManagerSession: IdentityManagerSession?,
        protocolStarterDelegate: ProtocolStarterDelegate?,
        ownedIdentity: Identity
    ) {
        if (!domain!!.contains(PRIVATE_IDENTITY) || !domain!!.contains(PUBLISHED_DETAILS)) {
            Logger.e("Trying to restore an incomplete OwnedIdentitySyncSnapshot. Domain: " + domain)
            throw Exception()
        }

        // restore contacts
        if (domain!!.contains(CONTACTS) && contacts != null) {
            for (contactEntry in contacts!!.entries) {
                val contactIdentity = Identity.of(contactEntry.key!!.getBytes())
                contactEntry.value!!.restore(identityManagerSession!!, ownedIdentity, contactIdentity)
            }
        }

        // restore groups v1
        if (domain!!.contains(GROUPS) && groups != null) {
            for (groupEntry in groups!!.entries) {
                val groupOwnerIdentity = Identity.of(groupEntry.key!!.groupOwner)
                groupEntry.value!!.restore(
                    identityManagerSession,
                    ownedIdentity,
                    groupOwnerIdentity,
                    groupEntry.key!!.getGroupOwnerAndUid()
                )
            }
        }

        // restore groups v2
        if (domain!!.contains(GROUPS2) && groups2 != null) {
            for (group2Entry in groups2!!.entries) {
                val groupIdentifier = GroupV2.Identifier.of(Encoded(group2Entry.key!!.getBytes()))
                group2Entry.value!!.restore(
                    identityManagerSession!!,
                    protocolStarterDelegate!!,
                    ownedIdentity,
                    groupIdentifier
                )
            }
        }
    }

    override fun areContentsTheSame(otherSnapshotNode: ObvSyncSnapshotNode?): Boolean {
        // TODO areContentsTheSame
        return false
    }

    @Throws(Exception::class)
    override fun computeDiff(otherSnapshotNode: ObvSyncSnapshotNode?): MutableList<ObvSyncDiff?>? {
        // TODO computeDiff
        return null
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class PrivateIdentity {
        @JvmField var server_authentication_private_key: ByteArray? = null
        @JvmField var encryption_private_key: ByteArray? = null
        @JvmField var mac_key: ByteArray? = null

        companion object {
            fun of(privateIdentity: io.olvid.engine.datatypes.PrivateIdentity): PrivateIdentity {
                val pi = PrivateIdentity()
                pi.server_authentication_private_key =
                    Encoded.of(privateIdentity.serverAuthenticationPrivateKey).bytes
                pi.encryption_private_key = Encoded.of(privateIdentity.encryptionPrivateKey).bytes
                pi.mac_key = Encoded.of(privateIdentity.macKey).bytes
                return pi
            }
        }
    }

    companion object {
        const val PRIVATE_IDENTITY: String = "private_identity"
        const val PUBLISHED_DETAILS: String = "published_details"
        const val KEYCLOAK: String = "keycloak"
        const val BACKUP_SEED: String = "backup_seed"
        const val CONTACTS: String = "contacts"
        const val GROUPS: String = "groups"
        const val GROUPS2: String = "groups2"
        var DEFAULT_DOMAIN: HashSet<String> = HashSet(
            listOf(
                PRIVATE_IDENTITY,
                PUBLISHED_DETAILS,
                KEYCLOAK,
                BACKUP_SEED,
                CONTACTS,
                GROUPS,
                GROUPS2
            )
        )


        @JvmStatic
        @Throws(SQLException::class)
        fun of(
            identityManagerSession: IdentityManagerSession?,
            ownedIdentity: OwnedIdentity
        ): OwnedIdentitySyncSnapshot {
            val ownedIdentitySyncSnapshot = OwnedIdentitySyncSnapshot()

            ownedIdentitySyncSnapshot.private_identity =
                PrivateIdentity.of(ownedIdentity.getPrivateIdentity()!!)

            val publishedDetails: OwnedIdentityDetails? = OwnedIdentityDetails.get(
                identityManagerSession!!,
                ownedIdentity.ownedIdentity,
                ownedIdentity.publishedDetailsVersion
            )
            if (publishedDetails != null) {
                ownedIdentitySyncSnapshot.published_details =
                    IdentityDetailsSyncSnapshot.of(
                        identityManagerSession,
                        publishedDetails
                    )
            }

            if (ownedIdentity.isKeycloakManaged) {
                val keycloakServer: KeycloakServer? = KeycloakServer.get(
                    identityManagerSession,
                    ownedIdentity.getKeycloakServerUrl(),
                    ownedIdentity.ownedIdentity
                )
                if (keycloakServer != null) {
                    ownedIdentitySyncSnapshot.keycloak =
                        KeycloakSyncSnapshot.of(identityManagerSession, keycloakServer)
                }
            }

            ownedIdentitySyncSnapshot.backup_seed = ownedIdentity.getBackupSeed()?.backupSeedBytes

            ownedIdentitySyncSnapshot.contacts = HashMap()
            for (contact in ContactIdentity.getAll(
                identityManagerSession,
                ownedIdentity.ownedIdentity
            )) {
                ownedIdentitySyncSnapshot.contacts!![ObvBytesKey(contact.getContactIdentity().getBytes())] = ContactSyncSnapshot.of(identityManagerSession, contact)
            }

            ownedIdentitySyncSnapshot.groups = HashMap()
            for (group in ContactGroup.getAllForIdentity(
                identityManagerSession,
                ownedIdentity.ownedIdentity
            )) {
                val g = group
                ownedIdentitySyncSnapshot.groups!![ObvGroupOwnerAndUidKey(g.groupOwnerAndUid)] = GroupV1SyncSnapshot.of(identityManagerSession, g)
            }

            ownedIdentitySyncSnapshot.groups2 = HashMap()
            for (group2 in ContactGroupV2.getAllForIdentity(
                identityManagerSession,
                ownedIdentity.ownedIdentity
            )) {
                val g2 = group2 ?: continue
                ownedIdentitySyncSnapshot.groups2!![ObvBytesKey(g2.groupIdentifier.bytes)] = GroupV2SyncSnapshot.of(identityManagerSession, g2)
            }

            ownedIdentitySyncSnapshot.domain = DEFAULT_DOMAIN
            return ownedIdentitySyncSnapshot
        }
    }
}
