PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  phone TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin','owner')),
  approved INTEGER NOT NULL DEFAULT 0,
  credits INTEGER NOT NULL DEFAULT 0 CHECK(credits >= 0),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scenarios (
  id TEXT PRIMARY KEY,
  author_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  players INTEGER NOT NULL,
  teams_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','hidden')),
  rejection_reason TEXT,
  likes_count INTEGER NOT NULL DEFAULT 0,
  views_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS likes (
  user_id TEXT NOT NULL REFERENCES users(id),
  scenario_id TEXT NOT NULL REFERENCES scenarios(id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, scenario_id)
);
CREATE TABLE IF NOT EXISTS follows (
  follower_id TEXT NOT NULL REFERENCES users(id),
  followed_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(follower_id, followed_id),
  CHECK(follower_id <> followed_id)
);
CREATE TABLE IF NOT EXISTS purchases (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  product_id TEXT NOT NULL CHECK(product_id IN ('license_1','license_3','license_10')),
  purchase_token_hash TEXT UNIQUE NOT NULL,
  quantity INTEGER NOT NULL,
  amount_irr INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','verified','rejected','refunded')),
  provider TEXT NOT NULL DEFAULT 'myket',
  created_at INTEGER NOT NULL,
  verified_at INTEGER
);
CREATE TABLE IF NOT EXISTS credit_ledger (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  delta INTEGER NOT NULL,
  reason TEXT NOT NULL,
  reference_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_logs (
  id TEXT PRIMARY KEY,
  actor_id TEXT,
  action TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scenarios_status_created ON scenarios(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scenarios_author ON scenarios(author_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_purchases_user ON purchases(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON credit_ledger(user_id, created_at DESC);
