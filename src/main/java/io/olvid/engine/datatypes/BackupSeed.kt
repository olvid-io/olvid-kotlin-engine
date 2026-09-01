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
import io.olvid.engine.crypto.AuthEnc
import io.olvid.engine.crypto.MAC
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.symmetric.AuthEncAES256ThenSHA256Key
import io.olvid.engine.datatypes.key.symmetric.MACKey

class BackupSeed {
    companion object {
        const val BACKUP_SEED_LENGTH = 20

        private val seedArray = "0123456789ABCDEFGHJKLMNPQRTUVWXY".toCharArray()
        private val seedInvArray = byteArrayOf(
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
            -1, 10, 11, 12, 13, 14, 15, 16, 17,  1, 18, 19, 20, 21, 22,  0,
            23, 24, 25,  5, 26, 27, 28, 29, 30, 31,  2, -1, -1, -1, -1, -1,
            -1, 10, 11, 12, 13, 14, 15, 16, 17,  1, 18, 19, 20, 21, 22,  0,
            23, 24, 25,  5, 26, 27, 28, 29, 30, 31,  2, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
        )

        @JvmStatic
        fun generate(prng: PRNG): BackupSeed? {
            return try {
                BackupSeed(prng.bytes(BACKUP_SEED_LENGTH))
            } catch (e: Exception) {
                Logger.x(e)
                null
            }
        }
    }

    @JvmField val backupSeedBytes: ByteArray

    @Throws(Exception::class)
    constructor(backupSeedBytes: ByteArray) {
        if (backupSeedBytes.size != BACKUP_SEED_LENGTH) {
            throw Exception("Bad backupSeedBytes length")
        }
        this.backupSeedBytes = backupSeedBytes
    }

    @Throws(SeedTooLongException::class, SeedTooShortException::class)
    constructor(seedString: String) {
        val bytes = ByteArray(BACKUP_SEED_LENGTH)
        var written = 0
        for (letter in seedString.toCharArray()) {
            val letterInt = letter.code
            if (letterInt < 0 || letterInt >= seedInvArray.size) {
                continue
            }
            val valByte = seedInvArray[letterInt]
            if (valByte == (-1).toByte()) {
                continue
            }
            if (written > (8 * BACKUP_SEED_LENGTH - 5)) {
                throw SeedTooLongException()
            }
            val byteOffset = written and 7
            if (byteOffset < 4) {
                bytes[written shr 3] = (bytes[written shr 3].toInt() or (valByte.toInt() shl (3 - byteOffset))).toByte()
            } else {
                bytes[written shr 3] = (bytes[written shr 3].toInt() or (valByte.toInt() shr (byteOffset - 3))).toByte()
                bytes[(written shr 3) + 1] = (bytes[(written shr 3) + 1].toInt() or (valByte.toInt() shl (11 - byteOffset))).toByte()
            }
            written += 5
        }
        if (written != (8 * BACKUP_SEED_LENGTH)) {
            throw SeedTooShortException()
        }
        this.backupSeedBytes = bytes
    }

    override fun toString(): String {
        val chars = CharArray(39)
        var read = 0
        for (i in 0 until 39) {
            if (i % 5 == 4) {
                chars[i] = ' '
            } else {
                val byteOffset = read and 7
                val charVal = if (byteOffset < 4) {
                    (backupSeedBytes[read shr 3].toInt() shr (3 - byteOffset)) and 31
                } else {
                    val firstPart = (backupSeedBytes[read shr 3].toInt() shl (byteOffset - 3)) and 31
                    val secondPart = (backupSeedBytes[(read shr 3) + 1].toInt() and 0xff) shr (11 - byteOffset)
                    firstPart or secondPart
                }
                chars[i] = seedArray[charVal]
                read += 5
            }
        }
        return String(chars)
    }

    override fun equals(other: Any?): Boolean {
        if (other !is BackupSeed) {
            return false
        }
        return backupSeedBytes.contentEquals(other.backupSeedBytes)
    }

    override fun hashCode(): Int {
        return backupSeedBytes.contentHashCode()
    }

    fun deriveKeys(): DerivedKeys {
        val fullSeedBytes = ByteArray(32)
        backupSeedBytes.copyInto(fullSeedBytes, 0, 0, BACKUP_SEED_LENGTH)
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, Seed(fullSeedBytes))
        val backupKeyUid = UID(prng)
        val encryptionKeyPair = EncryptionEciesCurve25519KeyPair.generate(prng)
        val mac = Suite.getMAC(MAC.HMAC_SHA256)!!
        val macKey = mac.generateKey(prng)!!
        return DerivedKeys(backupKeyUid, encryptionKeyPair, macKey)
    }

    class DerivedKeys internal constructor(
        @JvmField val backupKeyUid: UID,
        @JvmField val encryptionKeyPair: EncryptionEciesCurve25519KeyPair,
        @JvmField val macKey: MACKey
    )

    fun deriveKeysV2(): DerivedKeysV2 {
        val fullSeedBytes = ByteArray(32)
        backupSeedBytes.copyInto(fullSeedBytes, 0, 0, BACKUP_SEED_LENGTH)
        val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, Seed(fullSeedBytes))
        val backupKeyUid = UID(prng)
        val authEnc = Suite.getAuthEnc(AuthEnc.CTR_AES256_THEN_HMAC_SHA256)!!
        val encryptionKey = authEnc.generateKey(prng) as AuthEncAES256ThenSHA256Key
        val authenticationKeyPair = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        return DerivedKeysV2(backupKeyUid, encryptionKey, authenticationKeyPair)
    }

    class DerivedKeysV2 internal constructor(
        @JvmField val backupKeyUid: UID,
        @JvmField val encryptionKey: AuthEncAES256ThenSHA256Key,
        @JvmField val authenticationKeyPair: ServerAuthenticationECSdsaCurve25519KeyPair
    )

    class SeedTooShortException : Exception()
    class SeedTooLongException : Exception()
}
