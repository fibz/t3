# Knex DB Setup

## Install Dependencies

```bash
npm install knex better-sqlite3 pg dotenv
```

## Environment Variables

Create `.env`:

```env
# Development (SQLite)
NODE_ENV=development

# Production (PostgreSQL)
# NODE_ENV=production
# DB_HOST=localhost
# DB_PORT=5432
# DB_USER=t3portal
# DB_PASSWORD=yourpassword
# DB_NAME=t3portal
```

## Run Migrations

```bash
# Development (SQLite)
npm install
npm run migrate

# Production (PostgreSQL)
NODE_ENV=production npm run migrate
```

## Add npm Scripts

Add to `package.json`:

```json
{
  "scripts": {
    "migrate": "knex migrate:latest",
    "migrate:rollback": "knex migrate:rollback",
    "seed": "knex seed:run"
  }
}
```

## Usage in Code

```javascript
const db = require('./src/db');

// Query examples
const users = await db('users').select('*');
const user = await db('users').where({ username: 'admin' }).first();
const scans = await db('scans').where({ user_id: 1 }).orderBy('started_at', 'desc');

// Insert
await db('users').insert({
  username: 'admin',
  password_hash: '...',
  created_at: Date.now()
});
```
