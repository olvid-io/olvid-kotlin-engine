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
package io.olvid.engine.identity.databases

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.TrustLevel
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.TrustOrigin
import io.olvid.engine.datatypes.containers.TrustOrigin.Companion.createKeycloakTrustOrigin
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.JsonIdentityDetails
import io.olvid.engine.engine.types.JsonIdentityDetailsWithVersionAndPhoto
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.storage.EngineFile
import java.io.File
import java.sql.ResultSet
import java.sql.SQLException
import java.sql.Types
import java.util.Arrays
import java.util.LinkedList
import java.util.Random

class ContactIdentity : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession

    private var contactIdentity: Identity
    private var ownedIdentity: Identity
    var trustedDetailsVersion: Int
        private set
    @JvmField var publishedDetailsVersion: Int
    private var trustLevel: TrustLevel
    var isCertifiedByOwnKeycloak: Boolean
        private set
    @JvmField var revokedAsCompromised: Boolean
    @JvmField var forcefullyTrustedByUser: Boolean
    private var oneToOne: Int
    private var lastNoDeviceContactDeviceDiscovery: Long
    private var recentlyOnline: Boolean
    fun getContactIdentity(): Identity {
        return contactIdentity
    }

    fun getOwnedIdentity(): Identity {
        return ownedIdentity
    }

    fun getTrustLevel(): TrustLevel {
        return trustLevel
    }

    fun isRevokedAsCompromised(): Boolean {
        return revokedAsCompromised
    }

    fun isForcefullyTrustedByUser(): Boolean {
        return forcefullyTrustedByUser
    }

    val isActive: Boolean
        get() = forcefullyTrustedByUser || !revokedAsCompromised

    fun isOneToOne(): Boolean {
        return oneToOne == ONE_TO_ONE_STATUS_TRUE
    }

    val isNotOneToOne: Boolean
        get() = oneToOne == ONE_TO_ONE_STATUS_FALSE

    @set:Throws(SQLException::class)
    var lastContactDeviceDiscoveryTimestamp: Long
        get() = lastNoDeviceContactDeviceDiscovery
        set(lastNoDeviceContactDeviceDiscovery) {
            identityManagerSession.session.prepareStatement(
                "ContactIdentity.setLastContactDeviceDiscoveryTimestamp",
                "UPDATE " + TABLE_NAME +
                        " SET " + LAST_CONTACT_DEVICE_DISCOVERY + " = ? " +
                        " WHERE " + CONTACT_IDENTITY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setLong(1, lastNoDeviceContactDeviceDiscovery)
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
                this.lastNoDeviceContactDeviceDiscovery = lastNoDeviceContactDeviceDiscovery
            }
        }

    fun isRecentlyOnline(): Boolean {
        return recentlyOnline
    }

    @get:Throws(SQLException::class)
    val publishedDetails: ContactIdentityDetails?
        // region computed properties
        get() = ContactIdentityDetails.get(
            identityManagerSession,
            contactIdentity,
            ownedIdentity,
            publishedDetailsVersion
        )

    @get:Throws(SQLException::class)
    val trustedDetails: ContactIdentityDetails?
        get() = ContactIdentityDetails.get(
            identityManagerSession,
            contactIdentity,
            ownedIdentity,
            trustedDetailsVersion
        )

    // endregion
    // region setters
    @Throws(Exception::class)
    fun updatePublishedDetails(
        jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?,
        allowDowngrade: Boolean
    ) {
        if (jsonIdentityDetailsWithVersionAndPhoto == null) {
            return
        }
        val newDetailsVersion = jsonIdentityDetailsWithVersionAndPhoto.getVersion()
        if (!allowDowngrade && jsonIdentityDetailsWithVersionAndPhoto.getVersion() <= publishedDetailsVersion) {
            return
        }

        var notifyNewDetails = true
        val lastKnownSerializedCertifiedDetails: String?

        if (allowDowngrade && newDetailsVersion <= publishedDetailsVersion) {
            // check whether anything changed
            val publishedDetails = this.publishedDetails
            lastKnownSerializedCertifiedDetails = publishedDetails!!.getSerializedJsonDetails()
            if (newDetailsVersion == publishedDetailsVersion) {
                if (publishedDetails.jsonIdentityDetails == jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails()) {
                    // details are the same, check photo labels
                    val newPhotoServerLabel =
                        if (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel() == null) null else UID(
                            jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerLabel()!!
                        )
                    if (newPhotoServerLabel == publishedDetails.photoServerLabel) {
                        // photo labels are the same, check keys
                        val newPhotoServerKey =
                            if (jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey() == null) null else Encoded(
                                jsonIdentityDetailsWithVersionAndPhoto.getPhotoServerKey()!!
                            ).decodeSymmetricKey() as AuthEncKey?
                        if (newPhotoServerKey == publishedDetails.photoServerKey) {
                            // nothing changed, do nothing !
                            return
                        }
                    }
                }
            }

            // something changed and we actually need to downgrade!
            // first, cleanup
            ContactIdentityDetails.cleanup(
                identityManagerSession,
                ownedIdentity,
                contactIdentity,
                publishedDetailsVersion,
                trustedDetailsVersion
            )
            // then move trusted details to number -1 if needed, and set trusted And published to -1 --> clean published details
            val trustedDetails = this.trustedDetails
            if (trustedDetailsVersion != -1) {
                ContactIdentityDetails.copy(
                    identityManagerSession,
                    ownedIdentity,
                    contactIdentity,
                    trustedDetailsVersion,
                    -1
                )
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.updatePublishedDetails",
                    "UPDATE " + TABLE_NAME +
                            " SET " + TRUSTED_DETAILS_VERSION + " = ?, " +
                            PUBLISHED_DETAILS_VERSION + " = ? " +
                            " WHERE " + CONTACT_IDENTITY + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, -1)
                    statement.setInt(2, -1)
                    statement.setBytes(3, contactIdentity.getBytes())
                    statement.setBytes(4, ownedIdentity.getBytes())
                    statement.executeUpdate()
                    this.trustedDetailsVersion = -1
                    this.publishedDetailsVersion = -1
                }
                trustedDetails!!.delete()
            } else {
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.updatePublishedDetails",
                    "UPDATE " + TABLE_NAME +
                            " SET " + TRUSTED_DETAILS_VERSION + " = ?, " +
                            PUBLISHED_DETAILS_VERSION + " = ? " +
                            " WHERE " + CONTACT_IDENTITY + " = ? " +
                            " AND " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setInt(1, -1)
                    statement.setInt(2, -1)
                    statement.setBytes(3, contactIdentity.getBytes())
                    statement.setBytes(4, ownedIdentity.getBytes())
                    statement.executeUpdate()
                    this.trustedDetailsVersion = -1
                    this.publishedDetailsVersion = -1
                }
            }
            // now that the published details are no longer linked, remove them from DB
            if (publishedDetails.version != trustedDetails!!.version) {
                publishedDetails.delete()
            }
            // insert the new details
            val newPublishedDetails: ContactIdentityDetails =
                ContactIdentityDetails.create(
                    identityManagerSession,
                    contactIdentity,
                    ownedIdentity,
                    jsonIdentityDetailsWithVersionAndPhoto
                ) ?: throw SQLException("Error creating new published details")
            if (newPublishedDetails.photoServerLabel != null &&
                newPublishedDetails.photoServerKey != null
            ) {
                val npsl = newPublishedDetails.photoServerLabel
                if (npsl != null && npsl.equals(publishedDetails.photoServerLabel) &&
                    newPublishedDetails.photoServerKey == publishedDetails.photoServerKey && publishedDetails.getPhotoUrl() != null
                ) {
                    // photo is the same, copy the photoUrl
                    newPublishedDetails.setPhotoUrl(publishedDetails.getPhotoUrl())
                }
            }
            identityManagerSession.session.prepareStatement(
                "ContactIdentity.updatePublishedDetails",
                "UPDATE " + TABLE_NAME +
                        " SET " + PUBLISHED_DETAILS_VERSION + " = ? " +
                        " WHERE " + CONTACT_IDENTITY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setInt(1, newPublishedDetails.version)
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
                this.publishedDetailsVersion = newPublishedDetails.version
            }
        } else {
            // not in downgrade mode and number is indeed bigger
            val newPublishedDetails: ContactIdentityDetails =
                ContactIdentityDetails.create(
                    identityManagerSession,
                    contactIdentity,
                    ownedIdentity,
                    jsonIdentityDetailsWithVersionAndPhoto
                ) ?: throw SQLException("Error creating new published details")
            val publishedDetails = this.publishedDetails
            lastKnownSerializedCertifiedDetails = publishedDetails!!.getSerializedJsonDetails()
            if (newPublishedDetails.photoServerLabel != null &&
                newPublishedDetails.photoServerKey != null
            ) {
                val npsl2 = newPublishedDetails.photoServerLabel
                if (npsl2 != null && npsl2.equals(publishedDetails.photoServerLabel) &&
                    newPublishedDetails.photoServerKey == publishedDetails.photoServerKey && publishedDetails.getPhotoUrl() != null
                ) {
                    // photo is the same, copy the photoUrl
                    newPublishedDetails.setPhotoUrl(publishedDetails.getPhotoUrl())
                }
            }
            try {
                // check if any detail actually changed
                if (publishedDetails.jsonIdentityDetails
                        ?.fieldsAreTheSame(newPublishedDetails.jsonIdentityDetails!!) == true
                    && publishedDetails.photoServerKey == newPublishedDetails.photoServerKey
                    && publishedDetails.photoServerLabel == newPublishedDetails.photoServerLabel
                ) {
                    // nothing user visible changed --> do not notify
                    notifyNewDetails = false
                }
            } catch (_: Exception) {
            }

            identityManagerSession.session.prepareStatement(
                "ContactIdentity.updatePublishedDetails",
                "UPDATE " + TABLE_NAME +
                        " SET " + PUBLISHED_DETAILS_VERSION + " = ? " +
                        " WHERE " + CONTACT_IDENTITY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setInt(1, newPublishedDetails.version)
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
                this.publishedDetailsVersion = newPublishedDetails.version
            }
        }

        if (notifyNewDetails) {
            commitHookBits = commitHookBits or HOOK_BIT_NEW_PUBLISHED_DETAILS
            identityManagerSession.session.addSessionCommitListener(this)
        }
        if (jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails()!!
                .getSignedUserDetails() != null
        ) {
            val jsonKeycloakUserDetails =
                identityManagerSession.identityDelegate?.verifyKeycloakIdentitySignature(
                    identityManagerSession.session,
                    ownedIdentity,
                    jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails()!!
                        .getSignedUserDetails()
                )
            if (jsonKeycloakUserDetails != null) {
                // the details are properly signed --> the call to markContactAsCertifiedByOwnKeycloak() will auto-trust the new details, so we can return
                val certifiedJsonIdentityDetails = jsonKeycloakUserDetails.getIdentityDetails(
                    jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails()!!
                        .getSignedUserDetails()
                )
                markContactAsCertifiedByOwnKeycloak(certifiedJsonIdentityDetails)
                return
            }
        }

        if (this.isCertifiedByOwnKeycloak) {
            // received non-signed (or with invalid signature) details for a keycloak certified contact --> no longer certified
            setCertifiedByOwnKeycloak(false, lastKnownSerializedCertifiedDetails)
        }

        /**//// */
        // compare the old (trusted) and the new published details
        // --> if only the signature/position/company changed, directly trust
        // note that for signed details, it is already auto-trusted in markContactAsCertifiedByOwnKeycloak()
        /**//// */
        if (trustedDetailsVersion != publishedDetailsVersion) {
            val trustedDetails = this.trustedDetails
            val publishedDetails = this.publishedDetails
            val td = trustedDetails!!
            var same = publishedDetails!!.jsonIdentityDetails
                ?.firstAndLastNamesAreTheSame(td.jsonIdentityDetails!!) == true
            if (same) {
                // check whether we are during the first channel creation --> in that case the trustedDetailsVersion is -1 and we auto trust even if the photo changed (it's always null for version 0)
                if (trustedDetailsVersion != -1) {
                    same =
                        td.photoServerLabel == publishedDetails.photoServerLabel
                                && td.photoServerKey == publishedDetails.photoServerKey
                }
            }
            if (same) {
                trustPublishedDetails()
            }
        }
    }

    // when certifiedByOwnKeycloak is false, if possible, try providing the last known certified details
    // this allows settings these details for the pending member after a keycloak group member is demoted
    @Throws(SQLException::class)
    fun setCertifiedByOwnKeycloak(
        certifiedByOwnKeycloak: Boolean,
        lastKnownSerializedCertifiedDetails: String?
    ) {
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.setCertifiedByOwnKeycloak",
            "UPDATE " + TABLE_NAME +
                    " SET " + CERTIFIED_BY_OWN_KEYCLOAK + " = ? " +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, certifiedByOwnKeycloak)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.isCertifiedByOwnKeycloak = certifiedByOwnKeycloak
            commitHookBits = commitHookBits or HOOK_BIT_KEYCLOAK_MANAGED_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
            identityManagerSession.identityDelegate?.rePingOrDemoteContactFromAllKeycloakGroups(
                identityManagerSession.session,
                ownedIdentity,
                contactIdentity,
                certifiedByOwnKeycloak,
                lastKnownSerializedCertifiedDetails
            )
        }
    }

    // this method always sets to ONE_TO_ONE_STATUS_TRUE or ONE_TO_ONE_STATUS_FALSE, but never leaves in ONE_TO_ONE_STATUS_UNKNOWN
    @Throws(SQLException::class)
    fun setOneToOne(oneToOne: Boolean) {
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.setOneToOne",
            "UPDATE " + TABLE_NAME +
                    " SET " + ONE_TO_ONE + " = ? " +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, if (oneToOne) ONE_TO_ONE_STATUS_TRUE else ONE_TO_ONE_STATUS_FALSE)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            // do not notify when changing from unknown to false (normally this setter is not called in that case, but let's make sure!)
            if (isOneToOne() != oneToOne) {
                commitHookBits = commitHookBits or HOOK_BIT_ONE_TO_ONE_CHANGED
                identityManagerSession.session.addSessionCommitListener(this)
            }
            this.oneToOne = if (oneToOne) ONE_TO_ONE_STATUS_TRUE else ONE_TO_ONE_STATUS_FALSE
        }
    }

    @Throws(SQLException::class)
    fun setRecentlyOnline(recentlyOnline: Boolean) {
        if (this.recentlyOnline != recentlyOnline) {
            identityManagerSession.session.prepareStatement(
                "ContactIdentity.setRecentlyOnline",
                "UPDATE " + TABLE_NAME +
                        " SET " + RECENTLY_ONLINE + " = ? " +
                        " WHERE " + CONTACT_IDENTITY + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBoolean(1, recentlyOnline)
                statement.setBytes(2, contactIdentity.getBytes())
                statement.setBytes(3, ownedIdentity.getBytes())
                statement.executeUpdate()
                this.recentlyOnline = recentlyOnline
                commitHookBits = commitHookBits or HOOK_BIT_RECENTLY_ONLINE_CHANGED
                identityManagerSession.session.addSessionCommitListener(this)
            }
        }
    }

    @Throws(SQLException::class)
    fun setRevokedAsCompromised(revokedAsCompromised: Boolean) {
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.setRevokedAsCompromised",
            "UPDATE " + TABLE_NAME +
                    " SET " + REVOKED_AS_COMPROMISED + " = ? " +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, revokedAsCompromised)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            if (!this.revokedAsCompromised && revokedAsCompromised) {
                commitHookBits = commitHookBits or HOOK_BIT_REVOKED
            }
            this.revokedAsCompromised = revokedAsCompromised
            commitHookBits = commitHookBits or HOOK_BIT_ACTIVE_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun setForcefullyTrustedByUser(forcefullyTrustedByUser: Boolean) {
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.setForcefullyTrustedByUser",
            "UPDATE " + TABLE_NAME +
                    " SET " + FORCEFULLY_TRUSTED_BY_USER + " = ? " +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBoolean(1, forcefullyTrustedByUser)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.forcefullyTrustedByUser = forcefullyTrustedByUser
            commitHookBits = commitHookBits or HOOK_BIT_ACTIVE_CHANGED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    fun markContactAsCertifiedByOwnKeycloak(certifiedJsonIdentityDetails: JsonIdentityDetails) {
        if (!identityManagerSession.session.isInTransaction) {
            throw SQLException("markContactAsCertifiedByOwnKeycloak can only be called from within a transaction")
        }

        // 1. mark contact as keycloakManaged and add a trust origin
        if (!this.isCertifiedByOwnKeycloak) {
            setCertifiedByOwnKeycloak(true, null)
        }
        // 2. auto-trust if published != trusted
        if (trustedDetailsVersion != publishedDetailsVersion) {
            try {
                trustPublishedDetails()
            } catch (_: Exception) {
                // do nothing, untrusted published details remain
            }
        }

        // 3. if needed, update details to match what is certified
        val publishedDetails = this.publishedDetails
        val contactIdentityDetails = publishedDetails!!.jsonIdentityDetails
        if (certifiedJsonIdentityDetails != contactIdentityDetails) {
            try {
                val serializedCertifiedIdentityDetails =
                    identityManagerSession.jsonObjectMapper!!.writeValueAsString(
                        certifiedJsonIdentityDetails
                    )
                publishedDetails.setSerializedJsonDetails(serializedCertifiedIdentityDetails)
                hookTrustedDetails = publishedDetails.jsonIdentityDetailsWithVersionAndPhoto
                commitHookBits = commitHookBits or HOOK_BIT_PUBLISHED_DETAILS_TRUSTED
                identityManagerSession.session.addSessionCommitListener(this)
            } catch (_: JsonProcessingException) {
                // skip update if json fails
            }
        }

        // 4. add trust origin (this already checks for duplicates)
        val keycloakServerUrl =
            identityManagerSession.identityDelegate?.getOwnedIdentityKeycloakServerUrl(
                identityManagerSession.session,
                ownedIdentity
            )
        if (keycloakServerUrl != null) {
            addTrustOrigin(createKeycloakTrustOrigin(System.currentTimeMillis(), keycloakServerUrl))
        }
    }


    @Throws(SQLException::class)
    fun trustPublishedDetails(): JsonIdentityDetailsWithVersionAndPhoto? {
        if (trustedDetailsVersion == publishedDetailsVersion) {
            return null
        }
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.trustPublishedDetails",
            "UPDATE " + TABLE_NAME +
                    " SET " + TRUSTED_DETAILS_VERSION + " = ? " +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setInt(1, publishedDetailsVersion)
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.trustedDetailsVersion = publishedDetailsVersion
        }
        hookTrustedDetails = this.trustedDetails!!.jsonIdentityDetailsWithVersionAndPhoto
        commitHookBits = commitHookBits or HOOK_BIT_PUBLISHED_DETAILS_TRUSTED
        identityManagerSession.session.addSessionCommitListener(this)
        return hookTrustedDetails
    }

    @Throws(Exception::class)
    fun setDetailsDownloadedPhotoUrl(version: Int, photo: ByteArray) {
        val contactIdentityDetails: ContactIdentityDetails? = ContactIdentityDetails.get(
            identityManagerSession,
            contactIdentity,
            ownedIdentity,
            version
        )

        if (contactIdentityDetails == null) {
            return
        }

        // find a non-existing fileName
        val fileName = Constants.IDENTITY_PHOTOS_DIRECTORY + File.separator + Logger.toHexString(
            contactIdentity.getBytes().copyOfRange(contactIdentity.getBytes().size - 32, contactIdentity.getBytes().size)
        )
        var randFileName: String? = null
        val random = Random()
        var dstPhotoFile: EngineFile? = null
        do {
            randFileName = fileName + "_" + random.nextInt(65536)
            dstPhotoFile = identityManagerSession.fileIo.file(identityManagerSession.engineBaseDirectory, randFileName)
        } while (dstPhotoFile.exists())

        dstPhotoFile.openOutput().use { os ->
            os.write(photo, 0, photo.size)
        }
        // update the details
        contactIdentityDetails.setPhotoUrl(randFileName)
        hookPhotoSetVersion = version
        commitHookBits = commitHookBits or HOOK_BIT_PHOTO_SET
        identityManagerSession.session.addSessionCommitListener(this)
    }

    @Throws(SQLException::class)
    fun addTrustOrigin(newTrustOrigin: TrustOrigin) {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("Calling ContactIdentity.addTrustOrigin() outside a transaction")
            throw SQLException()
        }

        /**/////// */
        // if newTrustOrigin is not DIRECT, check if it is not already there --> avoid pointless duplicates
        /**/////// */
        if (newTrustOrigin.getType() != TrustOrigin.TYPE.DIRECT) {
            val contactTrustOrigins: Array<ContactTrustOrigin?> =
                ContactTrustOrigin.getAll(
                    identityManagerSession,
                    contactIdentity,
                    ownedIdentity
                )
            for (contactTrustOrigin in contactTrustOrigins) {
                val other = contactTrustOrigin?.trustOrigin
                if (newTrustOrigin.equals(other)) {
                    // we have a duplicate --> do not add the newTrustOrigin
                    return
                }
            }
        }

        val contactTrustOrigin: ContactTrustOrigin? = ContactTrustOrigin.create(
            identityManagerSession,
            contactIdentity,
            ownedIdentity,
            newTrustOrigin
        )
        if (contactTrustOrigin == null) {
            Logger.e("Error create contactTrustOrigin in ContactIdentity.addTrustOrigin()")
            throw SQLException()
        }
        val newTrustLevel = contactTrustOrigin.trustLevel
        if (newTrustLevel != null && newTrustLevel.compareTo(trustLevel) > 0) {
            setTrustLevel(newTrustLevel)
        }
    }

    @Throws(SQLException::class)
    private fun setTrustLevel(trustLevel: TrustLevel) {
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.setTrustLevel",
            "UPDATE " + TABLE_NAME +
                    " SET " + TRUST_LEVEL + " = ? " +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setString(1, trustLevel.toString())
            statement.setBytes(2, contactIdentity.getBytes())
            statement.setBytes(3, ownedIdentity.getBytes())
            statement.executeUpdate()
            this.trustLevel = trustLevel
            commitHookBits = commitHookBits or HOOK_BIT_TRUST_LEVEL_INCREASED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    constructor(
        identityManagerSession: IdentityManagerSession,
        contactIdentity: Identity,
        ownedIdentity: Identity,
        version: Int,
        trustLevel: TrustLevel,
        oneToOne: Int
    ) {
        this.identityManagerSession = identityManagerSession
        this.contactIdentity = contactIdentity
        this.ownedIdentity = ownedIdentity
        this.trustedDetailsVersion = version
        this.publishedDetailsVersion = version
        this.trustLevel = trustLevel
        this.isCertifiedByOwnKeycloak = false // this will be set at a later time
        this.revokedAsCompromised = false
        this.forcefullyTrustedByUser = false
        this.oneToOne = oneToOne
        this.lastNoDeviceContactDeviceDiscovery = 0
        this.recentlyOnline = true
    }

    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        try {
            this.contactIdentity = Identity.of(res.getBytes(CONTACT_IDENTITY))
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.trustedDetailsVersion = res.getInt(TRUSTED_DETAILS_VERSION)
        this.publishedDetailsVersion = res.getInt(PUBLISHED_DETAILS_VERSION)
        this.trustLevel = TrustLevel.of(res.getString(TRUST_LEVEL))
        this.isCertifiedByOwnKeycloak = res.getBoolean(CERTIFIED_BY_OWN_KEYCLOAK)
        this.revokedAsCompromised = res.getBoolean(REVOKED_AS_COMPROMISED)
        this.forcefullyTrustedByUser = res.getBoolean(FORCEFULLY_TRUSTED_BY_USER)
        this.oneToOne = res.getInt(ONE_TO_ONE)
        this.lastNoDeviceContactDeviceDiscovery = res.getLong(LAST_CONTACT_DEVICE_DISCOVERY)
        this.recentlyOnline = res.getBoolean(RECENTLY_ONLINE)
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?, ?,?,?,?,?, ?);"
        ).use { statement ->
            statement.setBytes(1, contactIdentity.getBytes())
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.setInt(3, trustedDetailsVersion)
            statement.setInt(4, publishedDetailsVersion)
            statement.setString(5, trustLevel.toString())

            statement.setBoolean(6, this.isCertifiedByOwnKeycloak)
            statement.setBoolean(7, revokedAsCompromised)
            statement.setBoolean(8, forcefullyTrustedByUser)
            statement.setInt(9, oneToOne)
            statement.setLong(10, lastNoDeviceContactDeviceDiscovery)

            statement.setBoolean(11, recentlyOnline)
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_INSERTED
            identityManagerSession.session.addSessionCommitListener(this)
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        if (!identityManagerSession.session.isInTransaction) {
            Logger.e("Running ContactIdentity delete outside a transaction")
            throw SQLException()
        }
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.delete",
            "DELETE FROM " + TABLE_NAME +
                    " WHERE " + CONTACT_IDENTITY + " = ? " +
                    " AND " + OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, contactIdentity.getBytes())
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
            commitHookBits = commitHookBits or HOOK_BIT_DELETED
            identityManagerSession.session.addSessionCommitListener(this)
        }
        identityManagerSession.session.prepareStatement(
            "ContactIdentity.delete",
            "DELETE FROM " + ContactIdentityDetails.TABLE_NAME +
                    " WHERE " + ContactIdentityDetails.CONTACT_IDENTITY + " = ? " +
                    " AND " + ContactIdentityDetails.OWNED_IDENTITY + " = ?;"
        ).use { statement ->
            statement.setBytes(1, contactIdentity.getBytes())
            statement.setBytes(2, ownedIdentity.getBytes())
            statement.executeUpdate()
        }
    }

    // endregion
    // region hooks
    private var commitHookBits: Long = 0
    private var hookTrustedDetails: JsonIdentityDetailsWithVersionAndPhoto? = null
    private var hookPhotoSetVersion = 0
    override fun wasCommitted() {
        if ((commitHookBits and HOOK_BIT_INSERTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_CONTACT_IDENTITY_KEY] =
                contactIdentity
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_OWNED_IDENTITY_KEY] =
                ownedIdentity
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_KEYCLOAK_MANAGED_KEY] =
                this.isCertifiedByOwnKeycloak
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_ACTIVE_KEY] = this.isActive
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_ONE_TO_ONE_KEY] =
                isOneToOne()
            userInfo[IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY_TRUST_LEVEL_KEY] =
                trustLevel.major
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_NEW_CONTACT_IDENTITY,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_DELETED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_IDENTITY_DELETED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_NEW_PUBLISHED_DETAILS) != 0L && (commitHookBits and HOOK_BIT_PUBLISHED_DETAILS_TRUSTED) == 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_NEW_CONTACT_PUBLISHED_DETAILS_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_NEW_CONTACT_PUBLISHED_DETAILS_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_NEW_CONTACT_PUBLISHED_DETAILS,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_PUBLISHED_DETAILS_TRUSTED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED_IDENTITY_DETAILS_KEY,
                hookTrustedDetails!!
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_PUBLISHED_DETAILS_TRUSTED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_PHOTO_SET) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET_VERSION_KEY,
                hookPhotoSetVersion
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET_IS_TRUSTED_KEY,
                hookPhotoSetVersion == trustedDetailsVersion
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_PHOTO_SET,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_TRUST_LEVEL_INCREASED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED_TRUST_LEVEL_KEY,
                trustLevel
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_TRUST_LEVEL_INCREASED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_KEYCLOAK_MANAGED_CHANGED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED_KEYCLOAK_MANAGED_KEY,
                this.isCertifiedByOwnKeycloak
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_KEYCLOAK_MANAGED_CHANGED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_ACTIVE_CHANGED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED_ACTIVE_KEY,
                this.isActive
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_ACTIVE_CHANGED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_REVOKED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_REVOKED_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_REVOKED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_REVOKED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_ONE_TO_ONE_CHANGED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED_ONE_TO_ONE_KEY,
                isOneToOne()
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_ONE_TO_ONE_CHANGED,
                userInfo
            )
        }
        if ((commitHookBits and HOOK_BIT_RECENTLY_ONLINE_CHANGED) != 0L) {
            val userInfo = HashMap<String, Any>()
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED_CONTACT_IDENTITY_KEY,
                contactIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED_OWNED_IDENTITY_KEY,
                ownedIdentity
            )
            userInfo.put(
                IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED_RECENTLY_ONLINE_KEY,
                recentlyOnline
            )
            identityManagerSession.notificationPostingDelegate?.postNotification(
                IdentityNotifications.NOTIFICATION_CONTACT_RECENTLY_ONLINE_CHANGED,
                userInfo
            )
        }
        commitHookBits = 0
    }


    @Throws(SQLException::class)
    fun backup(): Pojo_0 {
        val pojo = Pojo_0()
        pojo.contact_identity = contactIdentity.getBytes()
        pojo.trusted_details = this.trustedDetails?.backup()
        if (publishedDetailsVersion != trustedDetailsVersion) {
            pojo.published_details = this.publishedDetails?.backup()
        }
        pojo.trust_level = trustLevel.toString()
        pojo.revoked = revokedAsCompromised
        pojo.forcefully_trusted = forcefullyTrustedByUser
        when (oneToOne) {
            ONE_TO_ONE_STATUS_TRUE -> {
                pojo.one_to_one = true
            }

            ONE_TO_ONE_STATUS_FALSE -> {
                pojo.one_to_one = false
            }

            ONE_TO_ONE_STATUS_UNKNOWN -> {
                pojo.one_to_one = null
            }

            else -> {
                pojo.one_to_one = null
            }
        }
        pojo.trust_origins = ContactTrustOrigin.backupAll(
            identityManagerSession,
            ownedIdentity,
            contactIdentity
        )
        pojo.contact_groups = ContactGroup.backupAllForOwner(
            identityManagerSession,
            ownedIdentity,
            contactIdentity
        )

        return pojo
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    class Pojo_0 {
        @JvmField var contact_identity: ByteArray? = null
        @JvmField var trusted_details: ContactIdentityDetails.Pojo_0? = null
        @JvmField var published_details: ContactIdentityDetails.Pojo_0? = null
        @JvmField var trust_level: String? = null
        @JvmField var revoked: Boolean = false
        @JvmField var forcefully_trusted: Boolean = false
        @JvmField var one_to_one: Boolean? = null
        @JvmField var trust_origins: Array<ContactTrustOrigin.Pojo_0?>? = null
        @JvmField var contact_groups: Array<ContactGroup.Pojo_0?>? = null
    } // endregion

    companion object {
        const val TABLE_NAME: String = "contact_identity"

        const val CONTACT_IDENTITY: String = "identity"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val TRUSTED_DETAILS_VERSION: String = "trusted_details_version"
        const val PUBLISHED_DETAILS_VERSION: String = "published_details_version"
        const val TRUST_LEVEL: String = "trust_level"
        const val CERTIFIED_BY_OWN_KEYCLOAK: String = "keycloak_managed"
        const val REVOKED_AS_COMPROMISED: String = "revoked_as_compromised"
        const val FORCEFULLY_TRUSTED_BY_USER: String = "forcefully_trusted_by_user"
        const val ONE_TO_ONE: String = "one_to_one"
        const val LAST_CONTACT_DEVICE_DISCOVERY: String = "last_no_device_contact_device_discovery"
        const val RECENTLY_ONLINE: String = "recently_online"


        const val ONE_TO_ONE_STATUS_FALSE: Int = 0
        const val ONE_TO_ONE_STATUS_TRUE: Int = 1
        const val ONE_TO_ONE_STATUS_UNKNOWN: Int = 2


        @Throws(SQLException::class)
        fun unmarkAllCertifiedByOwnKeycloakContacts(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ) {
            // get the list of all certified contacts
            val certifiedContacts: MutableList<ContactIdentity> = LinkedList<ContactIdentity>()
            identityManagerSession.session.prepareStatement(
                "ContactIdentity.unmarkAllCertifiedByOwnKeycloakContacts",
                "SELECT * FROM  " + TABLE_NAME +
                        " WHERE " + CERTIFIED_BY_OWN_KEYCLOAK + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBoolean(1, true)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    while (res.next()) {
                        certifiedContacts.add(ContactIdentity(identityManagerSession, res))
                    }
                }
            }
            // for each of them, set them as not certified anymore
            for (contactIdentity in certifiedContacts) {
                // no need to provide lastKnownSerializedCertifiedDetails as unmarkAllCertifiedByOwnKeycloakContacts is only called when:
                // - our ownedIdentity is no longer certified
                contactIdentity.setCertifiedByOwnKeycloak(false, null)
            }
        }

        // endregion
        // region constructors
        fun create(
            identityManagerSession: IdentityManagerSession,
            contactIdentity: Identity?,
            ownedIdentity: Identity?,
            jsonIdentityDetailsWithVersionAndPhoto: JsonIdentityDetailsWithVersionAndPhoto?,
            trustOrigin: TrustOrigin?,
            revokedAsCompromised: Boolean,
            oneToOne: Boolean
        ): ContactIdentity? {
            if ((contactIdentity == null) || (ownedIdentity == null) || (jsonIdentityDetailsWithVersionAndPhoto == null)) {
                return null
            }
            try {
                if (!identityManagerSession.session.isInTransaction) {
                    Logger.e("Calling ContactIdentity.create() outside a transaction")
                    throw SQLException()
                }
                val contactIdentityDetails: ContactIdentityDetails? =
                    ContactIdentityDetails.create(
                        identityManagerSession,
                        contactIdentity,
                        ownedIdentity,
                        jsonIdentityDetailsWithVersionAndPhoto
                    )
                if (contactIdentityDetails == null) {
                    Logger.e("Error create contactIdentityDetails in ContactIdentity.create()")
                    throw SQLException()
                }

                // when creating a not one-to-one contact, set their one-to-one status as unknown
                val contactIdentityObject = ContactIdentity(
                    identityManagerSession,
                    contactIdentity,
                    ownedIdentity,
                    contactIdentityDetails.version,
                    TrustLevel(0, 0),
                    if (oneToOne) ONE_TO_ONE_STATUS_TRUE else ONE_TO_ONE_STATUS_UNKNOWN
                )
                contactIdentityObject.revokedAsCompromised = revokedAsCompromised
                contactIdentityObject.insert()

                val jsonKeycloakUserDetails =
                    identityManagerSession.identityDelegate?.verifyKeycloakIdentitySignature(
                        identityManagerSession.session,
                        ownedIdentity,
                        jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails()!!
                            .getSignedUserDetails()
                    )

                if (jsonKeycloakUserDetails != null) {
                    try {
                        val certifiedJsonIdentityDetails =
                            jsonKeycloakUserDetails.getIdentityDetails(
                                jsonIdentityDetailsWithVersionAndPhoto.getIdentityDetails()!!
                                    .getSignedUserDetails()
                            )
                        contactIdentityObject.markContactAsCertifiedByOwnKeycloak(
                            certifiedJsonIdentityDetails
                        )
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                }

                if (trustOrigin != null) {
                    val contactTrustOrigin: ContactTrustOrigin? =
                        ContactTrustOrigin.create(
                            identityManagerSession,
                            contactIdentity,
                            ownedIdentity,
                            trustOrigin
                        )
                    if (contactTrustOrigin == null) {
                        Logger.e("Error create contactTrustOrigin in ContactIdentity.create()")
                        throw SQLException()
                    }
                    contactIdentityObject.setTrustLevel(contactTrustOrigin.trustLevel ?: TrustLevel(0, 0))
                } else {
                    contactIdentityObject.setTrustLevel(TrustLevel(0, 0))
                }
                return contactIdentityObject
            } catch (_: SQLException) {
                return null
            }
        }

        // endregion
        // region database
        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            CONTACT_IDENTITY + " BLOB NOT NULL, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            TRUSTED_DETAILS_VERSION + " INT NOT NULL, " +
                            PUBLISHED_DETAILS_VERSION + " INT NOT NULL, " +
                            TRUST_LEVEL + " TEXT NOT NULL, " +
                            CERTIFIED_BY_OWN_KEYCLOAK + " BIT NOT NULL, " +
                            REVOKED_AS_COMPROMISED + " BIT NOT NULL, " +
                            FORCEFULLY_TRUSTED_BY_USER + " BIT NOT NULL, " +
                            ONE_TO_ONE + " BIT NOT NULL, " +
                            LAST_CONTACT_DEVICE_DISCOVERY + " INTEGER NOT NULL, " +
                            RECENTLY_ONLINE + " BIT NOT NULL DEFAULT 1, " +
                            " CONSTRAINT PK_" + TABLE_NAME + " PRIMARY KEY(" + CONTACT_IDENTITY + ", " + OWNED_IDENTITY + "), " +
                            " FOREIGN KEY (" + OWNED_IDENTITY + ") REFERENCES " + OwnedIdentity.TABLE_NAME + "(" + OwnedIdentity.OWNED_IDENTITY + ") ON DELETE CASCADE, " +
                            " FOREIGN KEY (" + CONTACT_IDENTITY + ", " + OWNED_IDENTITY + ", " + TRUSTED_DETAILS_VERSION + ") REFERENCES " + ContactIdentityDetails.TABLE_NAME + "(" + ContactIdentityDetails.CONTACT_IDENTITY + ", " + ContactIdentityDetails.OWNED_IDENTITY + ", " + ContactIdentityDetails.VERSION + "), " +
                            " FOREIGN KEY (" + CONTACT_IDENTITY + ", " + OWNED_IDENTITY + ", " + PUBLISHED_DETAILS_VERSION + ") REFERENCES " + ContactIdentityDetails.TABLE_NAME + "(" + ContactIdentityDetails.CONTACT_IDENTITY + ", " + ContactIdentityDetails.OWNED_IDENTITY + ", " + ContactIdentityDetails.VERSION + "));"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 6 && newVersion >= 6) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE contact_identity RENAME TO old_contact_identity")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS contact_identity_details (" +
                                " contact_identity BLOB NOT NULL, " +
                                " owned_identity BLOB NOT NULL, " +
                                " version INT NOT NULL, " +
                                " serialized_json_details TEXT NOT NULL, " +
                                " photo_url TEXT, " +
                                " photo_server_label BLOB, " +
                                " photo_server_key BLOB, " +
                                " CONSTRAINT PK_contact_identity_details PRIMARY KEY(contact_identity, owned_identity, version));"
                    )
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS contact_identity (" +
                                " identity BLOB NOT NULL, " +
                                " owned_identity BLOB NOT NULL, " +
                                " trusted_details_version INT NOT NULL, " +
                                " published_details_version INT NOT NULL, " +
                                " encoded_trust_origins BLOB NOT NULL, " +
                                " CONSTRAINT PK_contact_identity PRIMARY KEY(identity, owned_identity), " +
                                " FOREIGN KEY (owned_identity) REFERENCES owned_identity(identity)," +
                                " FOREIGN KEY (identity, owned_identity, trusted_details_version) REFERENCES contact_identity_details(contact_identity, owned_identity, version)," +
                                " FOREIGN KEY (identity, owned_identity, published_details_version) REFERENCES contact_identity_details(contact_identity, owned_identity, version));"
                    )
                    val objectMapper = ObjectMapper()
                    statement.executeQuery("SELECT * FROM old_contact_identity").use { res ->
                        while (res.next()) {
                            session.prepareStatement("INSERT INTO contact_identity VALUES (?,?,?,?,?);")
                                .use { preparedStatement ->
                                    preparedStatement.setBytes(1, res.getBytes(1))
                                    preparedStatement.setBytes(2, res.getBytes(2))
                                    preparedStatement.setInt(3, 0)
                                    preparedStatement.setInt(4, 0)
                                    preparedStatement.setBytes(5, res.getBytes(5))
                                    preparedStatement.executeUpdate()
                                }
                            session.prepareStatement("INSERT INTO contact_identity_details VALUES (?,?,?,?,?, ?,?);")
                                .use { preparedStatement ->
                                    preparedStatement.setBytes(1, res.getBytes(1))
                                    preparedStatement.setBytes(2, res.getBytes(2))
                                    preparedStatement.setInt(3, 0)
                                    val map = HashMap<String?, String?>()
                                    map.put("first_name", res.getString(3))
                                    try {
                                        preparedStatement.setString(
                                            4,
                                            objectMapper.writeValueAsString(map)
                                        )
                                    } catch (e: Exception) {
                                        Logger.x(e)
                                        // skip the contact
                                        continue
                                    }
                                    preparedStatement.setString(5, null)
                                    preparedStatement.setBytes(6, null)
                                    preparedStatement.setBytes(7, null)
                                    preparedStatement.executeUpdate()
                                }
                        }
                    }
                    statement.execute("DROP TABLE old_contact_identity")
                }
                oldVersion = 6
            }
            if (oldVersion < 9 && newVersion >= 9) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE contact_identity RENAME TO old_contact_identity")
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS contact_identity (" +
                                " identity BLOB NOT NULL, " +
                                " owned_identity BLOB NOT NULL, " +
                                " trusted_details_version INT NOT NULL, " +
                                " published_details_version INT NOT NULL, " +
                                " trust_level TEXT NOT NULL, " +
                                " CONSTRAINT PK_contact_identity PRIMARY KEY(identity, owned_identity), " +
                                " FOREIGN KEY (owned_identity) REFERENCES owned_identity(identity)," +
                                " FOREIGN KEY (identity, owned_identity, trusted_details_version) REFERENCES contact_identity_details(contact_identity, owned_identity, version)," +
                                " FOREIGN KEY (identity, owned_identity, published_details_version) REFERENCES contact_identity_details(contact_identity, owned_identity, version));"
                    )
                    statement.execute(
                        "CREATE TABLE IF NOT EXISTS contact_trust_origin (" +
                                "row_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                                "contact_identity BLOB NOT NULL, " +
                                "owned_identity BLOB NOT NULL, " +
                                "timestamp INTEGER NOT NULL, " +
                                "trust_type INTEGER NOT NULL, " +
                                "mediator_or_group_owner_identity BLOB, " +
                                "mediator_or_group_owner_trust_level_major INTEGER, " +
                                "identity_server TEXT, " +
                                " FOREIGN KEY (contact_identity, owned_identity ) REFERENCES contact_identity(identity, owned_identity) ON DELETE CASCADE);"
                    )
                    statement.executeQuery("SELECT * FROM old_contact_identity").use { res ->
                        while (res.next()) {
                            try {
                                val encodeds = Encoded(res.getBytes(5))
                                var maxTL = 0
                                for (encoded in encodeds.decodeList()) {
                                    try {
                                        val listOfEncoded: Array<Encoded> = encoded.decodeList()
                                        if (listOfEncoded.size == 0) {
                                            continue
                                        }
                                        val type = listOfEncoded[0].decodeLong().toInt()
                                        when (type) {
                                            0 -> {
                                                if (listOfEncoded.size != 2) {
                                                    continue
                                                }
                                                session.prepareStatement("INSERT INTO contact_trust_origin(contact_identity,owned_identity,timestamp,trust_type,mediator_or_group_owner_identity,mediator_or_group_owner_trust_level_major,identity_server) VALUES (?,?,?,?,?,?,?);")
                                                    .use { preparedStatement ->
                                                        preparedStatement.setBytes(
                                                            1,
                                                            res.getBytes(1)
                                                        )
                                                        preparedStatement.setBytes(
                                                            2,
                                                            res.getBytes(2)
                                                        )
                                                        preparedStatement.setLong(
                                                            3,
                                                            listOfEncoded[1].decodeLong()
                                                        )
                                                        preparedStatement.setInt(4, 1)
                                                        preparedStatement.setBytes(5, null)
                                                        preparedStatement.setNull(6, Types.INTEGER)
                                                        preparedStatement.setString(7, null)
                                                        preparedStatement.executeUpdate()
                                                    }
                                                if (maxTL < 4) {
                                                    maxTL = 4
                                                }
                                            }

                                            1 -> {
                                                if (listOfEncoded.size != 3) {
                                                    continue
                                                }
                                                session.prepareStatement("INSERT INTO contact_trust_origin(contact_identity,owned_identity,timestamp,trust_type,mediator_or_group_owner_identity,mediator_or_group_owner_trust_level_major,identity_server) VALUES (?,?,?,?,?,?,?);")
                                                    .use { preparedStatement ->
                                                        preparedStatement.setBytes(
                                                            1,
                                                            res.getBytes(1)
                                                        )
                                                        preparedStatement.setBytes(
                                                            2,
                                                            res.getBytes(2)
                                                        )
                                                        preparedStatement.setLong(
                                                            3,
                                                            listOfEncoded[1].decodeLong()
                                                        )
                                                        preparedStatement.setInt(4, 2)
                                                        preparedStatement.setBytes(
                                                            5,
                                                            listOfEncoded[2].decodeBytes()
                                                        )
                                                        preparedStatement.setInt(6, 4)
                                                        preparedStatement.setString(7, null)
                                                        preparedStatement.executeUpdate()
                                                    }
                                                if (maxTL < 2) {
                                                    maxTL = 2
                                                }
                                            }

                                            2 -> {
                                                if (listOfEncoded.size != 4) {
                                                    continue
                                                }
                                                session.prepareStatement("INSERT INTO contact_trust_origin(contact_identity,owned_identity,timestamp,trust_type,mediator_or_group_owner_identity,mediator_or_group_owner_trust_level_major,identity_server) VALUES (?,?,?,?,?,?,?);")
                                                    .use { preparedStatement ->
                                                        preparedStatement.setBytes(
                                                            1,
                                                            res.getBytes(1)
                                                        )
                                                        preparedStatement.setBytes(
                                                            2,
                                                            res.getBytes(2)
                                                        )
                                                        preparedStatement.setLong(
                                                            3,
                                                            listOfEncoded[1].decodeLong()
                                                        )
                                                        preparedStatement.setInt(4, 3)
                                                        preparedStatement.setBytes(
                                                            5,
                                                            listOfEncoded[2].decodeBytes()
                                                        )
                                                        preparedStatement.setInt(6, 4)
                                                        preparedStatement.setString(7, null)
                                                        preparedStatement.executeUpdate()
                                                    }
                                                if (maxTL < 2) {
                                                    maxTL = 2
                                                }
                                            }
                                        }
                                    } catch (_: DecodingException) {
                                        // do nothing
                                    }
                                }
                                session.prepareStatement("INSERT INTO contact_identity VALUES (?,?,?,?,?);")
                                    .use { preparedStatement ->
                                        preparedStatement.setBytes(1, res.getBytes(1))
                                        preparedStatement.setBytes(2, res.getBytes(2))
                                        preparedStatement.setInt(3, res.getInt(3))
                                        preparedStatement.setInt(4, res.getInt(4))
                                        if (maxTL == 4) {
                                            preparedStatement.setString(5, "4.0")
                                        } else if (maxTL == 2) {
                                            preparedStatement.setString(5, "2.4")
                                        } else {
                                            preparedStatement.setString(5, "0.0")
                                        }
                                        preparedStatement.executeUpdate()
                                    }
                            } catch (_: DecodingException) {
                            }
                        }
                    }
                    statement.execute("DROP TABLE old_contact_identity")
                }
                oldVersion = 9
            }
            if (oldVersion < 20 && newVersion >= 20) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE contact_identity ADD COLUMN keycloak_managed BIT NOT NULL DEFAULT 0")
                }
                oldVersion = 20
            }
            if (oldVersion < 25 && newVersion >= 25) {
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE contact_identity ADD COLUMN revoked_as_compromised BIT NOT NULL DEFAULT 0")
                    statement.execute("ALTER TABLE contact_identity ADD COLUMN forcefully_trusted_by_user BIT NOT NULL DEFAULT 0")
                }
                oldVersion = 25
            }
            if (oldVersion < 28 && newVersion >= 28) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `contact_identity` TABLE FROM VERSION " + oldVersion + " TO 28")
                    statement.execute("ALTER TABLE contact_identity ADD COLUMN one_to_one BIT NOT NULL DEFAULT 1")
                }
                oldVersion = 28
            }
            if (oldVersion < 35 && newVersion >= 35) {
                session.createStatement().use { statement ->
                    Logger.d("MIGRATING `contact_identity` TABLE FROM VERSION " + oldVersion + " TO 35")
                    statement.execute("ALTER TABLE contact_identity ADD COLUMN last_no_device_contact_device_discovery INTEGER NOT NULL DEFAULT 0")
                }
                oldVersion = 35
            }
            if (oldVersion < 41 && newVersion >= 41) {
                Logger.d("MIGRATING `contact_identity` DATABASE FROM VERSION " + oldVersion + " TO 41")
                session.createStatement().use { statement ->
                    statement.execute("ALTER TABLE contact_identity ADD COLUMN `recently_online` BIT NOT NULL DEFAULT 1")
                }
                oldVersion = 41
            }
        }

        // endregion
        // region getters
        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity?,
            contactIdentity: Identity?
        ): ContactIdentity? {
            if ((contactIdentity == null) || (ownedIdentity == null)) {
                return null
            }
            identityManagerSession.session.prepareStatement(
                "ContactIdentity.get",
                "SELECT * FROM " + TABLE_NAME + " WHERE " + CONTACT_IDENTITY + " = ? AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, contactIdentity.getBytes())
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return ContactIdentity(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        fun getAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): Array<ContactIdentity> {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.getAll",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactIdentity> = ArrayList()
                        while (res.next()) {
                            list.add(ContactIdentity(identityManagerSession, res))
                        }
                        return list.toTypedArray<ContactIdentity>()
                    }
                }
            } catch (_: SQLException) {
                return emptyArray()
            }
        }

        fun getAllCertifiedByKeycloak(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): MutableList<ContactIdentity?> {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.getAllCertifiedByKeycloak",
                    "SELECT * FROM " + TABLE_NAME +
                            " WHERE " + OWNED_IDENTITY + " = ? " +
                            " AND " + CERTIFIED_BY_OWN_KEYCLOAK + " = 1;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactIdentity?> = ArrayList<ContactIdentity?>()
                        while (res.next()) {
                            list.add(ContactIdentity(identityManagerSession, res))
                        }
                        return list
                    }
                }
            } catch (_: SQLException) {
                return ArrayList<ContactIdentity?>()
            }
        }

        fun getAllForAllOwnedIdentities(identityManagerSession: IdentityManagerSession): Array<ContactIdentity?> {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.getAllForAllOwnedIdentities",
                    "SELECT * FROM " + TABLE_NAME
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactIdentity?> = ArrayList<ContactIdentity?>()
                        while (res.next()) {
                            list.add(ContactIdentity(identityManagerSession, res))
                        }
                        return list.toTypedArray<ContactIdentity?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<ContactIdentity>(0)
            }
        }

        fun getAllActiveWithoutDevices(
            identityManagerSession: IdentityManagerSession,
            timestamp: Long
        ): Array<ContactIdentity?> {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.getAllActiveWithoutDevices",
                    "SELECT * FROM " + TABLE_NAME + " AS c WHERE " +
                            " (c." + REVOKED_AS_COMPROMISED + " = 0 OR c." + FORCEFULLY_TRUSTED_BY_USER + " = 1) " +
                            " AND c." + LAST_CONTACT_DEVICE_DISCOVERY + " < ? " +
                            " AND NOT EXISTS (" +
                            " SELECT 1 FROM " + ContactDevice.TABLE_NAME +
                            " WHERE " + ContactDevice.CONTACT_IDENTITY + " = c." + CONTACT_IDENTITY +
                            " AND " + ContactDevice.OWNED_IDENTITY + " = c." + OWNED_IDENTITY + ")"
                ).use { statement ->
                    statement.setLong(1, timestamp)
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactIdentity?> = ArrayList<ContactIdentity?>()
                        while (res.next()) {
                            list.add(ContactIdentity(identityManagerSession, res))
                        }
                        return list.toTypedArray<ContactIdentity?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<ContactIdentity>(0)
            }
        }

        fun getAllInactiveWithDevices(identityManagerSession: IdentityManagerSession): Array<ContactIdentity?> {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.getAllInactiveWithDevices",
                    "SELECT * FROM " + TABLE_NAME + " AS c WHERE " +
                            " (c." + REVOKED_AS_COMPROMISED + " = 1 AND c." + FORCEFULLY_TRUSTED_BY_USER + " = 0) " +
                            " AND EXISTS (" +
                            " SELECT 1 FROM " + ContactDevice.TABLE_NAME +
                            " WHERE " + ContactDevice.CONTACT_IDENTITY + " = c." + CONTACT_IDENTITY +
                            " AND " + ContactDevice.OWNED_IDENTITY + " = c." + OWNED_IDENTITY + ")"
                ).use { statement ->
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactIdentity?> = ArrayList<ContactIdentity?>()
                        while (res.next()) {
                            list.add(ContactIdentity(identityManagerSession, res))
                        }
                        return list.toTypedArray<ContactIdentity?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<ContactIdentity>(0)
            }
        }


        fun getAllActiveWithDevicesAndOldDiscovery(
            identityManagerSession: IdentityManagerSession,
            timestamp: Long
        ): Array<ContactIdentity?> {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.getAllActiveWithDevicesAndOldDiscovery",
                    "SELECT * FROM " + TABLE_NAME + " AS c WHERE " +
                            " (c." + REVOKED_AS_COMPROMISED + " = 0 OR c." + FORCEFULLY_TRUSTED_BY_USER + " = 1) " +
                            " AND c." + LAST_CONTACT_DEVICE_DISCOVERY + " < ? " +
                            " AND EXISTS (" +
                            " SELECT 1 FROM " + ContactDevice.TABLE_NAME +
                            " WHERE " + ContactDevice.CONTACT_IDENTITY + " = c." + CONTACT_IDENTITY +
                            " AND " + ContactDevice.OWNED_IDENTITY + " = c." + OWNED_IDENTITY + ")"
                ).use { statement ->
                    statement.setLong(1, timestamp)
                    statement.executeQuery().use { res ->
                        val list: MutableList<ContactIdentity?> = ArrayList<ContactIdentity?>()
                        while (res.next()) {
                            list.add(ContactIdentity(identityManagerSession, res))
                        }
                        return list.toTypedArray<ContactIdentity?>()
                    }
                }
            } catch (_: SQLException) {
                return arrayOfNulls<ContactIdentity>(0)
            }
        }

        fun getSerializedPublishedDetails(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            contactIdentity: Identity
        ): String? {
            try {
                identityManagerSession.session.prepareStatement(
                    "ContactIdentity.getSerializedPublishedDetails",
                    "SELECT details." + ContactIdentityDetails.SERIALIZED_JSON_DETAILS +
                            " FROM " + TABLE_NAME + " AS contact " +
                            " INNER JOIN " + ContactIdentityDetails.TABLE_NAME + " AS details " +
                            " ON contact." + OWNED_IDENTITY + " = details." + ContactIdentityDetails.OWNED_IDENTITY +
                            " AND contact." + CONTACT_IDENTITY + " = details." + ContactIdentityDetails.CONTACT_IDENTITY +
                            " AND contact." + PUBLISHED_DETAILS_VERSION + " = details." + ContactIdentityDetails.VERSION +
                            " WHERE contact." + OWNED_IDENTITY + " = ? " +
                            " AND contact." + CONTACT_IDENTITY + " = ?;"
                ).use { statement ->
                    statement.setBytes(1, ownedIdentity.getBytes())
                    statement.setBytes(2, contactIdentity.getBytes())
                    statement.executeQuery().use { res ->
                        if (res.next()) {
                            return res.getString(1)
                        }
                        return null
                    }
                }
            } catch (_: SQLException) {
                return null
            }
        }


        private const val HOOK_BIT_INSERTED: Long = 0x1
        private const val HOOK_BIT_DELETED: Long = 0x2
        private const val HOOK_BIT_PUBLISHED_DETAILS_TRUSTED: Long = 0x4
        private const val HOOK_BIT_NEW_PUBLISHED_DETAILS: Long = 0x8
        private const val HOOK_BIT_PHOTO_SET: Long = 0x10
        private const val HOOK_BIT_TRUST_LEVEL_INCREASED: Long = 0x20
        private const val HOOK_BIT_KEYCLOAK_MANAGED_CHANGED: Long = 0x40
        private const val HOOK_BIT_ACTIVE_CHANGED: Long = 0x80
        private const val HOOK_BIT_REVOKED: Long = 0x100
        private const val HOOK_BIT_ONE_TO_ONE_CHANGED: Long = 0x200
        private const val HOOK_BIT_RECENTLY_ONLINE_CHANGED: Long = 0x400

        // endregion
        // region backup
        @Throws(SQLException::class)
        fun backupAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): Array<Pojo_0?> {
            val contactIdentities: Array<ContactIdentity> =
                getAll(identityManagerSession, ownedIdentity)
            val pojos = arrayOfNulls<Pojo_0>(contactIdentities.size)
            for (i in contactIdentities.indices) {
                pojos[i] = contactIdentities[i].backup()
            }
            return pojos
        }

        @Throws(SQLException::class)
        fun restoreAll(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            pojos: Array<Pojo_0>?,
            backupTimestamp: Long
        ) {
            if (pojos == null) {
                return
            }
            // first recreate all contacts
            for (pojo in pojos) {
                restoreContact(identityManagerSession, ownedIdentity, pojo)
            }
            // then recreate all groups
            for (pojo in pojos) {
                restoreContactGroups(identityManagerSession, ownedIdentity, pojo, backupTimestamp)
            }
        }

        @Throws(SQLException::class)
        private fun restoreContact(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            pojo: Pojo_0
        ) {
            var contactIdentity: Identity? = null
            try {
                contactIdentity = Identity.of(pojo.contact_identity!!)
            } catch (e: DecodingException) {
                Logger.e("Error recreating ContactIdentity from backup!")
                Logger.x(e)
            }
            if (contactIdentity == null) {
                return
            }

            identityManagerSession.session.startTransaction()
            val trusted_details: ContactIdentityDetails = ContactIdentityDetails.restore(
                identityManagerSession,
                ownedIdentity,
                contactIdentity,
                pojo.trusted_details!!
            )
            var published_details: ContactIdentityDetails? = null
            if (pojo.published_details != null && pojo.published_details!!.version != pojo.trusted_details!!.version) {
                published_details = ContactIdentityDetails.restore(
                    identityManagerSession,
                    ownedIdentity,
                    contactIdentity,
                    pojo.published_details!!
                )
            }

            val contactIdentityObject = ContactIdentity(
                identityManagerSession,
                contactIdentity,
                ownedIdentity,
                trusted_details.version,
                TrustLevel.of(pojo.trust_level!!),
                if (pojo.one_to_one == null) ONE_TO_ONE_STATUS_UNKNOWN else (if (pojo.one_to_one == true) ONE_TO_ONE_STATUS_TRUE else ONE_TO_ONE_STATUS_FALSE)
            )
            if (published_details != null) {
                contactIdentityObject.publishedDetailsVersion = published_details.version
            }
            contactIdentityObject.revokedAsCompromised = pojo.revoked
            contactIdentityObject.forcefullyTrustedByUser = pojo.forcefully_trusted
            contactIdentityObject.insert()

            val jsonKeycloakUserDetails =
                identityManagerSession.identityDelegate?.verifyKeycloakIdentitySignature(
                    identityManagerSession.session,
                    ownedIdentity,
                    trusted_details.jsonIdentityDetailsWithVersionAndPhoto?.getIdentityDetails()
                        ?.getSignedUserDetails()
                )
            if (jsonKeycloakUserDetails != null) {
                contactIdentityObject.setCertifiedByOwnKeycloak(true, null)
            }

            @Suppress("UNCHECKED_CAST")
            ContactTrustOrigin.restoreAll(
                identityManagerSession,
                ownedIdentity,
                contactIdentity,
                pojo.trust_origins as Array<ContactTrustOrigin.Pojo_0>?
            )
            identityManagerSession.session.commit()
        }


        @Throws(SQLException::class)
        private fun restoreContactGroups(
            identityManagerSession: IdentityManagerSession?,
            ownedIdentity: Identity?,
            pojo: Pojo_0,
            backupTimestamp: Long
        ) {
            var contactIdentity: Identity? = null
            try {
                contactIdentity = Identity.of(pojo.contact_identity!!)
            } catch (e: DecodingException) {
                Logger.e("Error recreating ContactIdentityGroups from backup!")
                Logger.x(e)
            }
            if (contactIdentity == null) {
                return
            }

            @Suppress("UNCHECKED_CAST")
            ContactGroup.restoreAllForOwner(
                identityManagerSession!!,
                ownedIdentity!!,
                contactIdentity,
                pojo.contact_groups as Array<ContactGroup.Pojo_0>?,
                backupTimestamp
            )
        }
    }
}
