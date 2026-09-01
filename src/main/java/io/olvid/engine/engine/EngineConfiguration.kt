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
package io.olvid.engine.engine

import io.olvid.engine.Logger.LogOutputter
import io.olvid.engine.engine.types.sync.ObvBackupAndSyncDelegate
import io.olvid.engine.storage.EngineFileIo
import java.io.File
import javax.net.ssl.SSLSocketFactory

/**
 * All per-consumer (platform) configuration for an [Engine] instance.
 *
 * The engine itself is platform-neutral; everything that differs between the Android app, the desktop
 * client, and the daemon/bots is supplied here. Two inputs are mandatory and have no sensible default:
 *  - [baseDirectory]: where the engine stores its database, attachments and photos;
 *  - [fileIo]: the file-content strategy — `PlainFileIo` for plain storage (Android), `SecureFileIo`
 *    for encrypted-at-rest storage (desktop/daemon). It is required (not defaulted) so each consumer
 *    states its storage model explicitly rather than silently inheriting plain files.
 *
 * Every other field is optional with a default and may be set by name (Kotlin) or via field/setter
 * assignment (Java) — only the deltas need to be specified. This is preferred over a builder: there is
 * no construction-time validation or immutability requirement, so a plain configuration object keeps
 * the defaults visible in one place and stays ergonomic from both Java and Kotlin.
 */
class EngineConfiguration(
    @JvmField val baseDirectory: File,
    @JvmField val fileIo: EngineFileIo,
) {
    /** Consumer hook for application backup and multi-device sync. */
    @JvmField var appBackupAndSyncDelegate: ObvBackupAndSyncDelegate? = null

    /** SQLCipher key for the engine database; `null` keeps the database un-encrypted. */
    @JvmField var dbKey: String? = null

    /** Custom TLS socket factory for server connections; `null` uses the platform default. */
    @JvmField var sslSocketFactory: SSLSocketFactory? = null

    /** Overrides the HTTP User-Agent (e.g. for MDM/branding); `null` uses the default. */
    @JvmField var userAgentOverride: String? = null

    /** Sink for engine logs; `null` disables log output. */
    @JvmField var logOutputter: LogOutputter? = null

    /** Log verbosity level. */
    @JvmField var logLevel: Int = 0

    /** Number of threads used to send messages (the daemon may raise this). */
    @JvmField var sendMessageThreadCount: Int = 1

    /** Number of threads used to send return receipts. */
    @JvmField var sendReturnReceiptThreadCount: Int = 1
}
