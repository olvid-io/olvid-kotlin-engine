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

package io.olvid.engine.datatypes

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.MAC
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.MACKey
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.metamanager.IdentityDelegate
import java.nio.charset.StandardCharsets

class PrivateIdentity(
    @JvmField val publicIdentity: Identity,
    @JvmField val serverAuthenticationPrivateKey: ServerAuthenticationPrivateKey,
    @JvmField val encryptionPrivateKey: EncryptionPrivateKey,
    @JvmField val macKey: MACKey
) {

    fun computeUniqueUid(): UID {
        return publicIdentity.computeUniqueUid()
    }

    fun getServerAuthenticationPublicKey(): ServerAuthenticationPublicKey {
        return publicIdentity.serverAuthenticationPublicKey
    }

    fun getEncryptionPublicKey(): EncryptionPublicKey {
        return publicIdentity.encryptionPublicKey
    }

    fun serialize(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(publicIdentity.getBytes()),
                Encoded.of(serverAuthenticationPrivateKey),
                Encoded.of(encryptionPrivateKey),
                Encoded.of(macKey)
            )
        ).bytes
    }

    @Throws(Exception::class)
    fun getDeterministicSeedForOwnedIdentity(
        diversificationTag: ByteArray,
        context: IdentityDelegate.DeterministicSeedContext
    ): Seed {
        val mac = Suite.getMAC(macKey)!!
        val digest = when (context) {
            IdentityDelegate.DeterministicSeedContext.COMPUTE_SAS ->
                mac.digest(macKey, COMPUTE_SAS_DETERMINISTIC_SEED_MAC_PAYLOAD)!!
            IdentityDelegate.DeterministicSeedContext.COMPUTE_TRANSFER_SAS ->
                mac.digest(macKey, COMPUTE_TRANSFER_SAS_DETERMINISTIC_SEED_MAC_PAYLOAD)!!
            IdentityDelegate.DeterministicSeedContext.ENCRYPT_RETURN_RECEIPT ->
                mac.digest(macKey, ENCRYPT_RETURN_RECEIPT_DETERMINISTIC_SEED_MAC_PAYLOAD)!!
        }

        val hashInput = ByteArray(digest.size + diversificationTag.size)
        System.arraycopy(digest, 0, hashInput, 0, digest.size)
        System.arraycopy(diversificationTag, 0, hashInput, digest.size, diversificationTag.size)
        val sha256 = Suite.getHash(Hash.SHA256)
        val hash = sha256.digest(hashInput)
        return Seed(hash)
    }

    @Throws(Exception::class)
    fun getDeterministicBackupSeedForLegacyIdentity(): BackupSeed {
        val mac = Suite.getMAC(macKey)!!
        val digest = mac.digest(macKey, BACKUP_SEED_FOR_LEGACY_IDENTITY_MAC_PAYLOAD)!!
        val hashInput = ByteArray(digest.size + BACKUP_SEED_FOR_LEGACY_IDENTITY_HASH_PADDING.size)
        System.arraycopy(digest, 0, hashInput, 0, digest.size)
        System.arraycopy(
            BACKUP_SEED_FOR_LEGACY_IDENTITY_HASH_PADDING,
            0,
            hashInput,
            digest.size,
            BACKUP_SEED_FOR_LEGACY_IDENTITY_HASH_PADDING.size
        )
        val sha256 = Suite.getHash(Hash.SHA256)
        val hash = sha256.digest(hashInput)
        return BackupSeed(hash.copyOfRange(0, BackupSeed.BACKUP_SEED_LENGTH))
    }

    companion object {
        private val COMPUTE_SAS_DETERMINISTIC_SEED_MAC_PAYLOAD = byteArrayOf(0x55)
        private val COMPUTE_TRANSFER_SAS_DETERMINISTIC_SEED_MAC_PAYLOAD = byteArrayOf(0x56)
        private val ENCRYPT_RETURN_RECEIPT_DETERMINISTIC_SEED_MAC_PAYLOAD = byteArrayOf(0x57)

        private val BACKUP_SEED_FOR_LEGACY_IDENTITY_MAC_PAYLOAD = byteArrayOf(0xcc.toByte())
        private val BACKUP_SEED_FOR_LEGACY_IDENTITY_HASH_PADDING = "backupKey".toByteArray(StandardCharsets.UTF_8)

        @JvmStatic
        fun of(bytes: ByteArray): PrivateIdentity? {
            return try {
                val encodedElements = Encoded(bytes).decodeList()
                PrivateIdentity(
                    encodedElements[0].decodeIdentity(),
                    encodedElements[1].decodePrivateKey() as ServerAuthenticationPrivateKey,
                    encodedElements[2].decodePrivateKey() as EncryptionPrivateKey,
                    encodedElements[3].decodeSymmetricKey() as MACKey
                )
            } catch (_: Exception) {
                Logger.w("An error occurred while deserializing a PrivateIdentity.")
                null
            }
        }
    }
}
