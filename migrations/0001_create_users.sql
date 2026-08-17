CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,

    full_name TEXT NOT NULL
      CHECK(
        length(trim(full_name)) >= 2
        AND length(full_name) <= 100
      ),

    email TEXT NOT NULL COLLATE NOCASE UNIQUE
      CHECK(
        length(email) >= 5
        AND length(email) <= 254
      ),

    password_hash TEXT NOT NULL,

    created_at TEXT NOT NULL
      DEFAULT CURRENT_TIMESTAMP,

    license_status TEXT NOT NULL
      DEFAULT 'Aktif'
      CHECK(
        license_status IN (
          'Aktif',
          'Tidak Aktif',
          'Suspend'
        )
      )
);