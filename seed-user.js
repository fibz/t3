const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

// Usage: node seed-user.js <username> <password> <email> <company> [serverIp]
const [, , username, password, email, company, serverIp] = process.argv;
if (!username || !password || !email || !company) {
  console.log('Usage: node seed-user.js <username> <password> <email> <company> [serverIp]');
  process.exit(1);
}
const file = path.join(__dirname, 'data', 'users.json');
let users = [];
try { users = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
if (users.find(u => u.username === username)) { console.log('user already exists'); process.exit(0); }
const isFirstUser = users.length === 0;
users.push({
  username,
  passwordHash: bcrypt.hashSync(password, 10),
  email,
  company,
  serverIp: serverIp || '',
  role: isFirstUser ? 'admin' : 'operator',
  enabled: true
});
fs.writeFileSync(file, JSON.stringify(users, null, 2));
console.log(`added user ${username} (${isFirstUser ? 'admin' : 'operator'}). total users: ${users.length}`);