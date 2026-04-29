const fs = require("fs");
const path = require("path");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/novel_reader";
const MONGO_DATABASE = process.env.MONGO_DATABASE || process.env.MONGO_DB || "novel_reader";
const USERS_COLLECTION = process.env.USERS_COLLECTION || "users";
const PASSWORD_SALT_ROUNDS = Number(process.env.PASSWORD_SALT_ROUNDS || 10);

const inputFile = process.argv[2] || path.resolve(process.cwd(), "users.json");

function now() {
  return Date.now();
}

function safeNumber(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function normalizeAccount(account) {
  return String(account || "").trim().toLowerCase();
}

function createUid() {
  return "u_" + crypto.randomBytes(12).toString("hex");
}

function parseExportedJson(filePath) {
  const raw = fs.readFileSync(filePath, "utf8").trim();
  if (!raw) return [];

  const parsed = JSON.parse(raw);
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.data)) return parsed.data;
  if (Array.isArray(parsed.docs)) return parsed.docs;
  if (Array.isArray(parsed.records)) return parsed.records;
  return [parsed];
}

async function normalizeUser(row) {
  const account = normalizeAccount(row.account || row.username || row.userName || row.phone || "");
  if (!account) return null;

  let passwordHash = row.passwordHash || row.password_hash || "";
  const plainPassword = row.password || row.pass || "";
  if (!passwordHash && plainPassword) {
    passwordHash = await bcrypt.hash(String(plainPassword), PASSWORD_SALT_ROUNDS);
  }

  const totalSingleVoiceChars = safeNumber(row.totalSingleVoiceChars);
  const totalRoleVoiceChars = safeNumber(row.totalRoleVoiceChars);
  const totalInteractiveChars = safeNumber(row.totalInteractiveChars);
  const totalAudiobookChars = safeNumber(
    row.totalAudiobookChars || row.listeningWords || row.listenWords ||
    (totalSingleVoiceChars + totalRoleVoiceChars + totalInteractiveChars)
  );

  return {
    uid: row.uid || row._openid || row.openid || createUid(),
    account,
    nickname: String(row.nickname || row.nickName || row.name || "阅读用户").trim() || "阅读用户",
    passwordHash,
    phone: row.phone || "",
    avatarUrl: row.avatarUrl || row.avatar || "",
    loginType: row.loginType || "password",
    dayKey: Number(row.dayKey || 0),
    todayReadingSeconds: safeNumber(row.todayReadingSeconds),
    totalReadingSeconds: safeNumber(row.totalReadingSeconds || row.readingSeconds || row.readTime),
    todaySingleVoiceChars: safeNumber(row.todaySingleVoiceChars),
    totalSingleVoiceChars,
    todayRoleVoiceChars: safeNumber(row.todayRoleVoiceChars),
    totalRoleVoiceChars,
    todayInteractiveChars: safeNumber(row.todayInteractiveChars),
    totalInteractiveChars,
    totalAudiobookChars,
    deleted: Boolean(row.deleted),
    createdAt: Number(row.createdAt || now()),
    updatedAt: now(),
    legacyId: row._id || ""
  };
}

async function main() {
  if (!fs.existsSync(inputFile)) {
    throw new Error(`File not found: ${inputFile}`);
  }

  const rows = parseExportedJson(inputFile);
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const db = client.db(MONGO_DATABASE);
  const users = db.collection(USERS_COLLECTION);

  let imported = 0;
  let skipped = 0;

  for (const row of rows) {
    const user = await normalizeUser(row);
    if (!user) {
      skipped++;
      continue;
    }

    await users.updateOne(
      { account: user.account },
      { $set: user },
      { upsert: true }
    );
    imported++;
  }

  try {
    await users.createIndex({ account: 1 }, { unique: true });
    await users.createIndex({ uid: 1 }, { unique: true });
    await users.createIndex({ nickname: 1 }, { unique: true, sparse: true });
    await users.createIndex({ totalReadingSeconds: -1 });
    await users.createIndex({ totalAudiobookChars: -1 });
    await users.createIndex({ deleted: 1 });
  } catch (error) {
    console.warn("create indexes warning:", error.message);
  }

  await client.close();
  console.log(`Import finished. imported=${imported}, skipped=${skipped}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
