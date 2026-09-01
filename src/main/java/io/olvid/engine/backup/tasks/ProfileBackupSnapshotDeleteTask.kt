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
package io.olvid.engine.backup.tasks

import io.olvid.engine.backup.datatypes.BackupTaskStatus
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Signature
import io.olvid.engine.datatypes.BackupSeed
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.BackupsV2DeleteBackupQuery
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.operations.StandaloneServerQueryOperation
import javax.net.ssl.SSLSocketFactory


class ProfileBackupSnapshotDeleteTask(
    private val server: String?,
    private val profileBackupSeed: BackupSeed,
    private val backupThreadId: UID,
    private val version: Long,
    private val prng: PRNGService,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?
) {
    fun execute(): BackupTaskStatus {
        val derivedKeysV2 = profileBackupSeed.deriveKeysV2()

        val signaturePayload = Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(derivedKeysV2.backupKeyUid),
                Encoded.of(backupThreadId),
                Encoded.of(version),
            )
        ).bytes
        val signature = Signature.sign(
            Constants.SignatureContext.BACKUP_DELETE,
            signaturePayload,
            derivedKeysV2.authenticationKeyPair.getPrivateKey().signaturePrivateKey,
            prng
        )

        val standaloneServerQueryOperation = StandaloneServerQueryOperation(
            ServerQuery(
                null,
                null,
                BackupsV2DeleteBackupQuery(
                    server,
                    derivedKeysV2.backupKeyUid,
                    backupThreadId,
                    version,
                    signature
                )
            ), sslSocketFactory, userAgentOverride
        )
        val queue = OperationQueue()
        queue.queue(standaloneServerQueryOperation)
        queue.execute(1, "Engine-ProfileBackupSnapshotDeleteTask")
        queue.join()

        if (!standaloneServerQueryOperation.isFinished) {
            // can be: general error, server parsing error, unknown backup uid, unknown threadId, unknown version, invalid signature
            return BackupTaskStatus.PERMANENT_FAILURE
        }

        return BackupTaskStatus.SUCCESS
    }
}

