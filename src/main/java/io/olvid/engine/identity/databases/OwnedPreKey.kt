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

import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Signature
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants.SignatureContext
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.KeyId
import io.olvid.engine.datatypes.ObvDatabase
import io.olvid.engine.datatypes.PrivateIdentity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvCapability
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import java.sql.ResultSet
import java.sql.SQLException

class OwnedPreKey : ObvDatabase {
    private val identityManagerSession: IdentityManagerSession?

    @JvmField val keyId: KeyId
    private var ownedIdentity: Identity? = null
    @JvmField val expirationTimestamp: Long
    var encryptionPrivateKey: EncryptionPrivateKey? = null
        private set
    @JvmField val encodedSignedPreKey: Encoded

    fun getOwnedIdentity(): Identity {
        return ownedIdentity!!
    }

    constructor(
        identityManagerSession: IdentityManagerSession?,
        keyId: KeyId,
        ownedIdentity: Identity,
        expirationTimestamp: Long,
        encryptionPrivateKey: EncryptionPrivateKey?,
        encodedSignedPreKey: Encoded
    ) {
        this.identityManagerSession = identityManagerSession
        this.keyId = keyId
        this.ownedIdentity = ownedIdentity
        this.expirationTimestamp = expirationTimestamp
        this.encryptionPrivateKey = encryptionPrivateKey
        this.encodedSignedPreKey = encodedSignedPreKey
    }


    private constructor(identityManagerSession: IdentityManagerSession, res: ResultSet) {
        this.identityManagerSession = identityManagerSession
        this.keyId = KeyId(res.getBytes(KEY_ID))
        try {
            this.ownedIdentity = Identity.of(res.getBytes(OWNED_IDENTITY))
        } catch (_: DecodingException) {
            throw SQLException()
        }
        this.expirationTimestamp = res.getLong(EXPIRATION_TIMESTAMP)
        val encryptionPrivateKeyBytes: ByteArray = res.getBytes(ENCRYPTION_PRIVATE_KEY)
        try {
            this.encryptionPrivateKey =
                Encoded(encryptionPrivateKeyBytes).decodePrivateKey() as EncryptionPrivateKey?
        } catch (_: DecodingException) {
        }
        this.encodedSignedPreKey = Encoded(res.getBytes(ENCODED_SIGNED_PRE_KEY))
    }


    @Throws(SQLException::class)
    override fun insert() {
        identityManagerSession!!.session.prepareStatement(
            "OwnedPreKey.insert",
            "INSERT INTO " + TABLE_NAME + " VALUES (?,?,?,?,?);"
        ).use { statement ->
            statement.setBytes(1, keyId.bytes)
            statement.setBytes(2, ownedIdentity!!.getBytes())
            statement.setLong(3, expirationTimestamp)
            statement.setBytes(4, Encoded.of(encryptionPrivateKey!!).bytes)
            statement.setBytes(5, encodedSignedPreKey.bytes)
            statement.executeUpdate()
        }
    }

    @Throws(SQLException::class)
    override fun delete() {
        identityManagerSession!!.session.prepareStatement(
            "OwnedPreKey.delete",
            "DELETE FROM " + TABLE_NAME + " WHERE " + KEY_ID + " = ?;"
        ).use { statement ->
            statement.setBytes(1, keyId.bytes)
            statement.executeUpdate()
        }
    }


    //    private long commitHookBits = 0;
    override fun wasCommitted() {
//        commitHookBits = 0;
    }

    companion object {
        const val TABLE_NAME: String = "owned_pre_key"

        const val KEY_ID: String = "key_id"
        const val OWNED_IDENTITY: String = "owned_identity"
        const val EXPIRATION_TIMESTAMP: String = "expiration_timestamp"
        const val ENCRYPTION_PRIVATE_KEY: String = "encryption_private_key"
        const val ENCODED_SIGNED_PRE_KEY: String = "encoded_signed_pre_key"

        fun create(
            identityManagerSession: IdentityManagerSession?,
            ownedIdentity: Identity?,
            privateIdentity: PrivateIdentity?,
            currentDeviceUid: UID?,
            expirationTimestamp: Long,
            prng: PRNGService
        ): OwnedPreKey? {
            if (ownedIdentity == null || privateIdentity == null || currentDeviceUid == null) {
                return null
            }
            // generate a key pair
            val keyId = KeyId(prng.bytes(KeyId.KEYID_LENGTH))
            val encryptionKeyPair = Suite.generateEncryptionKeyPair(null, prng)
            if (encryptionKeyPair == null) {
                return null
            }
            val rawDeviceCapabilities =
                ObvCapability.capabilityListToStringArray(ObvCapability.currentCapabilities)
            // encode the public part to sign it for server upload
            val encodedPreKey = Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(keyId.bytes),
                    Encoded.of((encryptionKeyPair.getPublicKey() as EncryptionPublicKey).compactKey),
                    Encoded.of(currentDeviceUid),
                    Encoded.of(expirationTimestamp),
                )
            )
            val dict = HashMap<DictionaryKey, Encoded>()
            dict.put(DictionaryKey("prk"), encodedPreKey)
            dict.put(DictionaryKey("cap"), Encoded.of(rawDeviceCapabilities))
            val encodedDict: Encoded = Encoded.of(dict)
            val signature: ByteArray?
            try {
                signature = Signature.sign(
                    SignatureContext.DEVICE_PRE_KEY,
                    encodedDict.bytes,
                    privateIdentity.serverAuthenticationPrivateKey.signaturePrivateKey,
                    prng
                )
                if (signature == null) {
                    return null
                }
            } catch (e: Exception) {
                Logger.x(e)
                return null
            }

            try {
                val ownedPreKey = OwnedPreKey(
                    identityManagerSession,
                    keyId,
                    ownedIdentity,
                    expirationTimestamp,
                    encryptionKeyPair.getPrivateKey() as EncryptionPrivateKey,
                    Encoded.of(
                        arrayOf<Encoded>(
                            encodedDict,
                            Encoded.of(signature),
                        )
                    )
                )
                ownedPreKey.insert()
                return ownedPreKey
            } catch (_: SQLException) {
                return null
            }
        }

        @Throws(SQLException::class)
        fun createTable(session: Session) {
            session.createStatement().use { statement ->
                statement.execute(
                    "CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " (" +
                            KEY_ID + " BLOB PRIMARY KEY, " +
                            OWNED_IDENTITY + " BLOB NOT NULL, " +
                            EXPIRATION_TIMESTAMP + " INTEGER NOT NULL, " +
                            ENCRYPTION_PRIVATE_KEY + " BLOB NOT NULL, " +
                            ENCODED_SIGNED_PRE_KEY + " BLOB NOT NULL, " +
                            "FOREIGN KEY (" + OWNED_IDENTITY + ") REFERENCES " + OwnedIdentity.TABLE_NAME + " (" + OwnedIdentity.OWNED_IDENTITY + ") ON DELETE CASCADE);"
                )
            }
        }

        @Throws(SQLException::class)
        fun upgradeTable(session: Session, oldVersion: Int, newVersion: Int) {
            var oldVersion = oldVersion
            if (oldVersion < 41 && newVersion >= 41) {
                Logger.d("CREATING `owned_pre_key` DATABASE FOR VERSION 41")
                session.createStatement().use { statement ->
                    statement.execute(
                        "CREATE TABLE `owned_pre_key` (" +
                                " key_id BLOB PRIMARY KEY, " +
                                " owned_identity BLOB NOT NULL, " +
                                " expiration_timestamp INTEGER NOT NULL, " +
                                " encryption_private_key BLOB NOT NULL, " +
                                " encoded_signed_pre_key BLOB NOT NULL, " +
                                " FOREIGN KEY (owned_identity) REFERENCES owned_identity(identity) ON DELETE CASCADE);"
                    )
                }
                oldVersion = 41
            }
        }

        @Throws(SQLException::class)
        fun get(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            keyId: KeyId
        ): OwnedPreKey? {
            identityManagerSession.session.prepareStatement(
                "OwnedPreKey.get",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + KEY_ID + " = ? " +
                        " AND " + OWNED_IDENTITY + " = ?;"
            ).use { statement ->
                statement.setBytes(1, keyId.bytes)
                statement.setBytes(2, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return OwnedPreKey(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }


        @Throws(SQLException::class)
        fun getLatest(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity
        ): OwnedPreKey? {
            identityManagerSession.session.prepareStatement(
                "OwnedPreKey.getLatest",
                "SELECT * FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " ORDER BY " + EXPIRATION_TIMESTAMP + " DESC LIMIT 1;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.executeQuery().use { res ->
                    if (res.next()) {
                        return OwnedPreKey(identityManagerSession, res)
                    } else {
                        return null
                    }
                }
            }
        }

        @Throws(SQLException::class)
        fun deleteExpired(
            identityManagerSession: IdentityManagerSession,
            ownedIdentity: Identity,
            timestamp: Long
        ) {
            identityManagerSession.session.prepareStatement(
                "OwnedPreKey.deleteExpired",
                "DELETE FROM " + TABLE_NAME +
                        " WHERE " + OWNED_IDENTITY + " = ? " +
                        " AND " + EXPIRATION_TIMESTAMP + " < ?;"
            ).use { statement ->
                statement.setBytes(1, ownedIdentity.getBytes())
                statement.setLong(2, timestamp)
                statement.executeUpdate()
            }
        }
    }
}
