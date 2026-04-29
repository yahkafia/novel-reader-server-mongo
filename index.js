const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
const { MongoClient } = require("mongodb");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const PORT = Number(process.env.PORT || 3000);
const TOKEN_SECRET = process.env.TOKEN_SECRET || process.env.JWT_SECRET || "dev_secret_change_me";
const PASSWORD_SALT_ROUNDS = Number(process.env.PASSWORD_SALT_ROUNDS || 10);
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/novel_reader";
const MONGO_DATABASE = process.env.MONGO_DATABASE || process.env.MONGO_DB || "novel_reader";
const USERS_COLLECTION = process.env.USERS_COLLECTION || "users";

let mongoClient;
let mongoDb;
let users;

function ok(data = {}) {
  return { code: 0, message: "ok", data };
}

function fail(message, data = {}) {
  return { code: 1, message, data };
}

function now() {
  return Date.now();
}

function normalizeAccount(account) {
  return String(account || "").trim().toLowerCase();
}

function validateAccount(account) {
  return /^[a-zA-Z0-9_]{4,20}$/.test(account);
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 6 && password.length <= 32;
}

function validateNickname(nickname) {
  return typeof nickname === "string" && nickname.trim().length >= 1 && nickname.trim().length <= 20;
}

function createUid() {
  return "u_" + crypto.randomBytes(12).toString("hex");
}

function createToken(user) {
  return jwt.sign(
    {
      uid: user.uid,
      account: user.account,
      loginType: "password"
    },
    TOKEN_SECRET,
    { expiresIn: "30d" }
  );
}

function safeNumber(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function toAccountUser(row, accessToken = "") {
  return {
    uid: row.uid || "",
    account: row.account || "",
    nickname: row.nickname || "阅读用户",
    phone: row.phone || "",
    avatarUrl: row.avatarUrl || "",
    loginType: row.loginType || "password",
    accessToken
  };
}

function toStats(row) {
  return {
    dayKey: Number(row.dayKey || 0),
    todayReadingSeconds: safeNumber(row.todayReadingSeconds),
    totalReadingSeconds: safeNumber(row.totalReadingSeconds),
    todaySingleVoiceChars: safeNumber(row.todaySingleVoiceChars),
    totalSingleVoiceChars: safeNumber(row.totalSingleVoiceChars),
    todayRoleVoiceChars: safeNumber(row.todayRoleVoiceChars),
    totalRoleVoiceChars: safeNumber(row.totalRoleVoiceChars),
    todayInteractiveChars: safeNumber(row.todayInteractiveChars),
    totalInteractiveChars: safeNumber(row.totalInteractiveChars)
  };
}

function normalizeStatsFromBody(body) {
  const totalSingleVoiceChars = safeNumber(body.totalSingleVoiceChars);
  const totalRoleVoiceChars = safeNumber(body.totalRoleVoiceChars);
  const totalInteractiveChars = safeNumber(body.totalInteractiveChars);
  const computedTotalAudiobookChars = totalSingleVoiceChars + totalRoleVoiceChars + totalInteractiveChars;

  return {
    dayKey: Number(body.dayKey || 0),
    todayReadingSeconds: safeNumber(body.todayReadingSeconds),
    totalReadingSeconds: safeNumber(body.totalReadingSeconds),
    todaySingleVoiceChars: safeNumber(body.todaySingleVoiceChars),
    totalSingleVoiceChars,
    todayRoleVoiceChars: safeNumber(body.todayRoleVoiceChars),
    totalRoleVoiceChars,
    todayInteractiveChars: safeNumber(body.todayInteractiveChars),
    totalInteractiveChars,
    totalAudiobookChars: safeNumber(body.totalAudiobookChars || computedTotalAudiobookChars)
  };
}

async function connectDb() {
  if (users) return users;

  mongoClient = new MongoClient(MONGO_URI, {
    serverSelectionTimeoutMS: 8000
  });
  await mongoClient.connect();
  mongoDb = mongoClient.db(MONGO_DATABASE);
  users = mongoDb.collection(USERS_COLLECTION);

  // 索引创建失败不应阻止服务启动；可能是旧数据有重复昵称/账号，日志里会提示。
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

  console.log(`[DB] MongoDB connected: db=${MONGO_DATABASE}, collection=${USERS_COLLECTION}`);
  return users;
}

async function findUserByAccount(account) {
  await connectDb();
  return users.findOne({ account, deleted: { $ne: true } });
}

async function findUserByUid(uid) {
  await connectDb();
  return users.findOne({ uid, deleted: { $ne: true } });
}

async function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.substring(7) : "";

    if (!token) return res.json(fail("请先登录"));

    const payload = jwt.verify(token, TOKEN_SECRET);
    const user = await findUserByUid(payload.uid);

    if (!user) return res.json(fail("账号不存在或已注销"));

    req.user = user;
    next();
  } catch (error) {
    console.error("auth failed:", error);
    return res.json(fail("登录状态已失效，请重新登录"));
  }
}

async function updateUserByUid(uid, patch) {
  await connectDb();
  await users.updateOne({ uid }, { $set: patch });
}

app.get("/", async (req, res) => {
  const diag = {
    service: "novel-reader-account-server",
    version: "mongo-v1",
    database: MONGO_DATABASE,
    collection: USERS_COLLECTION,
    hasTokenSecret: Boolean(process.env.TOKEN_SECRET || process.env.JWT_SECRET)
  };

  try {
    await connectDb();
    await users.findOne({}, { projection: { uid: 1 } });
    res.json(ok({ ...diag, status: "connected" }));
  } catch (error) {
    console.error("database check failed:", error);
    res.json(fail("MongoDB 数据库连接失败：" + error.message, diag));
  }
});

app.get("/health", async (req, res) => {
  try {
    await connectDb();
    res.json(ok({
      service: "novel-reader-account-server",
      version: "mongo-v1",
      status: "running",
      database: "connected",
      dbName: MONGO_DATABASE,
      collection: USERS_COLLECTION,
      hasTokenSecret: Boolean(process.env.TOKEN_SECRET || process.env.JWT_SECRET)
    }));
  } catch (error) {
    res.json(fail("MongoDB 数据库连接失败：" + error.message, {
      service: "novel-reader-account-server",
      version: "mongo-v1",
      status: "running",
      database: "disconnected"
    }));
  }
});

app.post("/auth/nickname/check", async (req, res) => {
  try {
    await connectDb();
    const nickname = String(req.body.nickname || "").trim();

    if (!nickname || nickname.length > 20) {
      return res.json(ok({ available: false, exists: false, duplicate: false }));
    }

    const exists = Boolean(await users.findOne({ nickname, deleted: { $ne: true } }, { projection: { uid: 1 } }));
    res.json(ok({ available: !exists, exists, duplicate: exists }));
  } catch (error) {
    console.error("check nickname failed:", error);
    res.json(fail(error.message || "昵称检测失败"));
  }
});

app.post("/account/profile/update", authRequired, async (req, res) => {
  try {
    const nickname = String(req.body.nickname || "").trim();

    if (!nickname || nickname.length > 20) return res.json(fail("昵称需为1-20个字符"));

    const existed = await users.findOne({ nickname, deleted: { $ne: true } });
    if (existed && existed.uid !== req.user.uid) {
      return res.json(fail("昵称已被使用，请更换昵称"));
    }

    await updateUserByUid(req.user.uid, { nickname, updatedAt: now() });
    const updatedUser = { ...req.user, nickname };

    res.json(ok({
      user: toAccountUser(updatedUser, req.headers.authorization?.replace("Bearer ", "") || "")
    }));
  } catch (error) {
    console.error("update profile failed:", error);
    res.json(fail(error.message || "修改昵称失败"));
  }
});

app.post("/auth/password/register", async (req, res) => {
  try {
    await connectDb();
    const account = normalizeAccount(req.body.account);
    const password = String(req.body.password || "");
    const nickname = String(req.body.nickname || "").trim() || "阅读用户";

    if (!validateAccount(account)) return res.json(fail("账号需为4-20位字母、数字或下划线"));
    if (!validatePassword(password)) return res.json(fail("密码长度需为6-32位"));
    if (!validateNickname(nickname)) return res.json(fail("昵称需为1-20个字符"));

    const existed = await users.findOne({ account });
    if (existed) {
      if (existed.deleted === true) return res.json(fail("该账号已注销，不能重复注册"));
      return res.json(fail("账号已存在"));
    }

    const nicknameResult = await users.findOne({ nickname, deleted: { $ne: true } });
    if (nicknameResult) return res.json(fail("昵称已被使用，请更换昵称"));

    const uid = createUid();
    const passwordHash = await bcrypt.hash(password, PASSWORD_SALT_ROUNDS);

    const user = {
      uid,
      account,
      nickname,
      passwordHash,
      phone: "",
      avatarUrl: "",
      loginType: "password",
      dayKey: 0,
      todayReadingSeconds: 0,
      totalReadingSeconds: 0,
      todaySingleVoiceChars: 0,
      totalSingleVoiceChars: 0,
      todayRoleVoiceChars: 0,
      totalRoleVoiceChars: 0,
      todayInteractiveChars: 0,
      totalInteractiveChars: 0,
      totalAudiobookChars: 0,
      deleted: false,
      createdAt: now(),
      updatedAt: now()
    };

    await users.insertOne(user);
    const accessToken = createToken(user);

    res.json(ok({ user: toAccountUser(user, accessToken) }));
  } catch (error) {
    console.error("register failed:", error);
    if (error.code === 11000) return res.json(fail("账号或昵称已存在"));
    res.json(fail(error.message || "注册失败"));
  }
});

app.post("/auth/password/login", async (req, res) => {
  try {
    const account = normalizeAccount(req.body.account);
    const password = String(req.body.password || "");

    if (!validateAccount(account)) return res.json(fail("请输入正确的账号"));
    if (!password) return res.json(fail("请输入密码"));

    const user = await findUserByAccount(account);
    if (!user) return res.json(fail("账号不存在"));

    const matched = await bcrypt.compare(password, user.passwordHash || "");
    if (!matched) return res.json(fail("密码错误"));

    await updateUserByUid(user.uid, { lastLoginAt: now(), updatedAt: now() });

    const accessToken = createToken(user);
    res.json(ok({ user: toAccountUser(user, accessToken) }));
  } catch (error) {
    console.error("login failed:", error);
    res.json(fail(error.message || "登录失败"));
  }
});

app.post("/auth/password/change", authRequired, async (req, res) => {
  try {
    const oldPassword = String(req.body.oldPassword || "");
    const newPassword = String(req.body.newPassword || "");

    if (!oldPassword) return res.json(fail("请输入原密码"));
    if (!validatePassword(newPassword)) return res.json(fail("新密码长度需为6-32位"));

    const matched = await bcrypt.compare(oldPassword, req.user.passwordHash || "");
    if (!matched) return res.json(fail("原密码错误"));

    const newHash = await bcrypt.hash(newPassword, PASSWORD_SALT_ROUNDS);
    await updateUserByUid(req.user.uid, { passwordHash: newHash, updatedAt: now() });

    res.json(ok());
  } catch (error) {
    console.error("change password failed:", error);
    res.json(fail(error.message || "修改密码失败"));
  }
});

app.post("/auth/logout", authRequired, async (req, res) => {
  res.json(ok());
});

app.post("/account/delete", authRequired, async (req, res) => {
  try {
    await updateUserByUid(req.user.uid, {
      deleted: true,
      account: `${req.user.account}_deleted_${req.user.uid}`,
      nickname: `${req.user.nickname || "阅读用户"}_deleted_${req.user.uid}`,
      updatedAt: now()
    });
    res.json(ok());
  } catch (error) {
    console.error("delete account failed:", error);
    res.json(fail(error.message || "注销账号失败"));
  }
});

app.post("/user/stats/sync", authRequired, async (req, res) => {
  try {
    const incoming = normalizeStatsFromBody(req.body);
    const oldStats = {
      dayKey: Number(req.user.dayKey || 0),
      todayReadingSeconds: safeNumber(req.user.todayReadingSeconds),
      totalReadingSeconds: safeNumber(req.user.totalReadingSeconds),
      todaySingleVoiceChars: safeNumber(req.user.todaySingleVoiceChars),
      totalSingleVoiceChars: safeNumber(req.user.totalSingleVoiceChars),
      todayRoleVoiceChars: safeNumber(req.user.todayRoleVoiceChars),
      totalRoleVoiceChars: safeNumber(req.user.totalRoleVoiceChars),
      todayInteractiveChars: safeNumber(req.user.todayInteractiveChars),
      totalInteractiveChars: safeNumber(req.user.totalInteractiveChars),
      totalAudiobookChars: safeNumber(req.user.totalAudiobookChars)
    };

    const sameDay = incoming.dayKey > 0 && incoming.dayKey === oldStats.dayKey;
    const merged = {
      dayKey: incoming.dayKey || oldStats.dayKey,
      todayReadingSeconds: sameDay ? Math.max(oldStats.todayReadingSeconds, incoming.todayReadingSeconds) : incoming.todayReadingSeconds,
      todaySingleVoiceChars: sameDay ? Math.max(oldStats.todaySingleVoiceChars, incoming.todaySingleVoiceChars) : incoming.todaySingleVoiceChars,
      todayRoleVoiceChars: sameDay ? Math.max(oldStats.todayRoleVoiceChars, incoming.todayRoleVoiceChars) : incoming.todayRoleVoiceChars,
      todayInteractiveChars: sameDay ? Math.max(oldStats.todayInteractiveChars, incoming.todayInteractiveChars) : incoming.todayInteractiveChars,
      totalReadingSeconds: Math.max(oldStats.totalReadingSeconds, incoming.totalReadingSeconds),
      totalSingleVoiceChars: Math.max(oldStats.totalSingleVoiceChars, incoming.totalSingleVoiceChars),
      totalRoleVoiceChars: Math.max(oldStats.totalRoleVoiceChars, incoming.totalRoleVoiceChars),
      totalInteractiveChars: Math.max(oldStats.totalInteractiveChars, incoming.totalInteractiveChars),
      totalAudiobookChars: Math.max(oldStats.totalAudiobookChars, incoming.totalAudiobookChars),
      updatedAt: now()
    };

    await updateUserByUid(req.user.uid, merged);
    res.json(ok({
      stats: {
        dayKey: merged.dayKey,
        todayReadingSeconds: merged.todayReadingSeconds,
        totalReadingSeconds: merged.totalReadingSeconds,
        todaySingleVoiceChars: merged.todaySingleVoiceChars,
        totalSingleVoiceChars: merged.totalSingleVoiceChars,
        todayRoleVoiceChars: merged.todayRoleVoiceChars,
        totalRoleVoiceChars: merged.totalRoleVoiceChars,
        todayInteractiveChars: merged.todayInteractiveChars,
        totalInteractiveChars: merged.totalInteractiveChars
      }
    }));
  } catch (error) {
    console.error("sync stats failed:", error);
    res.json(fail(error.message || "同步统计失败"));
  }
});

app.post("/user/stats/get", authRequired, async (req, res) => {
  try {
    res.json(ok({ stats: toStats(req.user) }));
  } catch (error) {
    console.error("get stats failed:", error);
    res.json(fail(error.message || "获取统计数据失败"));
  }
});

app.post("/rankings", async (req, res) => {
  try {
    await connectDb();
    const readingRows = await users
      .find({ deleted: { $ne: true } })
      .sort({ totalReadingSeconds: -1 })
      .limit(50)
      .toArray();

    const audioRows = await users
      .find({ deleted: { $ne: true } })
      .sort({ totalAudiobookChars: -1 })
      .limit(50)
      .toArray();

    const readingTime = readingRows.map((row, index) => ({
      rank: index + 1,
      nickname: row.nickname || `读者${index + 1}`,
      value: safeNumber(row.totalReadingSeconds)
    }));

    const audiobookChars = audioRows.map((row, index) => ({
      rank: index + 1,
      nickname: row.nickname || `读者${index + 1}`,
      value: safeNumber(row.totalAudiobookChars)
    }));

    res.json(ok({ readingTime, audiobookChars }));
  } catch (error) {
    console.error("rankings failed:", error);
    res.json(fail(error.message || "排行榜加载失败"));
  }
});

async function start() {
  try {
    await connectDb();
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("server start failed:", error);
    process.exit(1);
  }
}

process.on("SIGINT", async () => {
  if (mongoClient) await mongoClient.close();
  process.exit(0);
});

start();
