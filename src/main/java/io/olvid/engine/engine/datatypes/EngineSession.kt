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
package io.olvid.engine.engine.datatypes

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.datatypes.Session
import java.lang.AutoCloseable
import java.sql.SQLException

class EngineSession(
    session: Session,
    userInterfaceDialogListener: UserInterfaceDialogListener?,
    jsonObjectMapper: ObjectMapper?
) : AutoCloseable {
    @JvmField val session: Session
    @JvmField val userInterfaceDialogListener: UserInterfaceDialogListener?
    @JvmField val jsonObjectMapper: ObjectMapper?

    init {
        this.session = session
        this.userInterfaceDialogListener = userInterfaceDialogListener
        this.jsonObjectMapper = jsonObjectMapper
    }

    @Throws(SQLException::class)
    override fun close() {
        session.close()
    }
}
