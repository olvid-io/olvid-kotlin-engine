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
package io.olvid.engine.networkfetch.datatypes

import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.PRNGHmacSHA256
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidIdentityMaskingUidRegistryTest {
    private class TestPrngService(seed: Seed) : PRNGService, PRNG by PRNGHmacSHA256(seed) {
        override fun reseed(seed: Seed?) {
            // deterministic test PRNG, never reseeded
        }
    }

    private val prng = TestPrngService(Seed(ByteArray(32)))
    private val mask = UID(prng)
    private val identityAndUid = IdentityAndUid(
        Identity(
            "test.olvid.com",
            ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng).publicKey as ServerAuthenticationPublicKey,
            EncryptionEciesCurve25519KeyPair.generate(prng).publicKey as EncryptionPublicKey
        ),
        UID(prng)
    )

    @Test
    fun lookupBeforeTheFirstLoadWaitsForIt() {
        val registry = AndroidIdentityMaskingUidRegistry(loadTimeoutMillis = 5_000)
        Thread {
            Thread.sleep(200)
            registry.put(mask, identityAndUid)
            registry.markLoaded()
        }.start()

        val start = System.currentTimeMillis()
        assertEquals(identityAndUid, registry.get(mask))
        assertTrue(System.currentTimeMillis() - start in 150..4_000)
    }

    @Test
    fun unknownMaskAfterTheLoadReturnsAtOnce() {
        val registry = AndroidIdentityMaskingUidRegistry(loadTimeoutMillis = 5_000)
        registry.put(mask, identityAndUid)
        registry.markLoaded()

        val start = System.currentTimeMillis()
        assertNull(registry.get(UID(prng)))
        assertEquals(identityAndUid, registry.get(mask))
        assertTrue(System.currentTimeMillis() - start < 100)
    }

    @Test
    fun lookupGivesUpWhenTheLoadNeverHappens() {
        val registry = AndroidIdentityMaskingUidRegistry(loadTimeoutMillis = 200)

        val start = System.currentTimeMillis()
        assertNull(registry.get(mask))
        assertTrue(System.currentTimeMillis() - start in 150..2_000)
    }
}
