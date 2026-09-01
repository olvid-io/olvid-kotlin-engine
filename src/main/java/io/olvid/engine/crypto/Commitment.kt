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
package io.olvid.engine.crypto

import io.olvid.engine.crypto.Commitment.CommitmentOutput
import java.util.Arrays


interface Commitment {
    fun commit(tag: ByteArray?, value: ByteArray?, prng: PRNGService?): CommitmentOutput
    fun open(tag: ByteArray?, commitment: ByteArray?, decommitment: ByteArray?): ByteArray?

    class CommitmentOutput(@JvmField val commitment: ByteArray, @JvmField val decommitment: ByteArray)
}

internal class CommitmentWithSHA256 : Commitment {
    override fun commit(tag: ByteArray?, value: ByteArray?, prng: PRNGService?): CommitmentOutput {
        val h = HashSHA256()
        val e = prng!!.bytes(COMMITMENT_RANDOM_LENGTH)
        val decommitment = ByteArray(value!!.size + COMMITMENT_RANDOM_LENGTH)
        System.arraycopy(value, 0, decommitment, 0, value.size)
        System.arraycopy(e, 0, decommitment, value.size, COMMITMENT_RANDOM_LENGTH)

        val input = ByteArray(tag!!.size + value.size + COMMITMENT_RANDOM_LENGTH)
        System.arraycopy(tag, 0, input, 0, tag.size)
        System.arraycopy(decommitment, 0, input, tag.size, decommitment.size)

        val commitment = h.digest(input)

        return CommitmentOutput(commitment, decommitment)
    }

    override fun open(tag: ByteArray?, commitment: ByteArray?, decommitment: ByteArray?): ByteArray? {
        val h = HashSHA256()
        val input = ByteArray(tag!!.size + decommitment!!.size)
        System.arraycopy(tag, 0, input, 0, tag.size)
        System.arraycopy(decommitment, 0, input, tag.size, decommitment.size)

        val commitment2 = h.digest(input)
        if (commitment.contentEquals(commitment2)) {
            return decommitment.copyOfRange(0, decommitment.size - COMMITMENT_RANDOM_LENGTH)
        } else {
            return null
        }
    }

    companion object {
        const val COMMITMENT_RANDOM_LENGTH: Int = 32
    }
}