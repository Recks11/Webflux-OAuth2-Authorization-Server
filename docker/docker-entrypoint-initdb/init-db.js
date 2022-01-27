db = db.getSiblingDB('admin')
db.auth('root', 'kajbfiuwniowbiu2332')

db = db.getSiblingDB('auth-server')

db.createUser(
    {
        user: "auth-server-app",
        pwd: "app-password",
        roles: [
            {
                role: "readWrite",
                db: "auth-server"
            }
        ]
    }
);