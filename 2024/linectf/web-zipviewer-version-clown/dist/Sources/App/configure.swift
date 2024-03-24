import Leaf
import Vapor

public func configure(_ app: Application) async throws {

    app.views.use(.leaf)

    app.routes.caseInsensitive = true
    app.routes.defaultMaxBodySize = 128

    let fileMiddleware = FileMiddleware(
        publicDirectory: app.directory.publicDirectory
    )
    app.middleware.use(fileMiddleware)

    app.sessions.configuration.cookieName = "vapor_session"
    app.sessions.configuration.cookieFactory = { sessionID in
        .init(string: sessionID.string, isSecure: false)
    }
    app.middleware.use(app.sessions.middleware)
    app.sessions.use(.memory)

    try routes(app)
}
