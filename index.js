const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
const { MongoClient } = require("mongodb");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));
const path = require("path");

const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(__dirname, "public");
app.use("/files", express.static(path.join(PUBLIC_DIR, "files")));

const PORT = Number(process.env.PORT || 3000);
const TOKEN_SECRET = process.env.TOKEN_SECRET || process.env.JWT_SECRET || "dev_secret_change_me";
const PASSWORD_SALT_ROUNDS = Number(process.env.PASSWORD_SALT_ROUNDS || 10);
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/novel_reader";
const MONGO_DATABASE = process.env.MONGO_DATABASE || process.env.MONGO_DB || "novel_reader";
const USERS_COLLECTION = process.env.USERS_COLLECTION || "users";

let mongoClient;
let mongoDb;
let users;
let resourcePackages;

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
  resourcePackages = mongoDb.collection("original_resource_packages");

  try {
    await resourcePackages.createIndex({ scriptId: 1, version: -1 });
    await resourcePackages.createIndex(
      { scriptId: 1, version: 1 },
      { unique: true }
    );
    await resourcePackages.createIndex({ enabled: 1 });
  } catch (error) {
    console.warn("create resource package indexes warning:", error.message);
  }

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
      joinsRanking: true,
      rankingVisible: true,
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
      originalSaves: {},
      originalGacha: {},
      originalUnlockFlags: {},
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

app.post("/account/ranking/participation/get", authRequired, async (req, res) => {
  try {
    const joinsRanking = req.user.joinsRanking !== false;
    const rankingVisible = req.user.rankingVisible !== false;

    res.json(ok({
      joinsRanking,
      rankingVisible
    }));
  } catch (error) {
    console.error("get ranking participation failed:", error);
    res.json(fail(error.message || "获取排行榜参与状态失败"));
  }
});

app.post("/account/ranking/participation/update", authRequired, async (req, res) => {
  try {
    const joinsRanking = req.body.joinsRanking !== false;
    const rankingVisible = req.body.rankingVisible !== false;

    await updateUserByUid(req.user.uid, {
      joinsRanking,
      rankingVisible,
      updatedAt: now()
    });

    res.json(ok({
      joinsRanking,
      rankingVisible
    }));
  } catch (error) {
    console.error("update ranking participation failed:", error);
    res.json(fail(error.message || "更新排行榜参与状态失败"));
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
    const joinsRanking =
      typeof req.body.joinsRanking === "boolean"
        ? req.body.joinsRanking
        : req.user.joinsRanking !== false;

    const rankingVisible =
      typeof req.body.rankingVisible === "boolean"
        ? req.body.rankingVisible
        : req.user.rankingVisible !== false;
    
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

      joinsRanking,
      rankingVisible,
      
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

function sanitizeKey(value) {
  return String(value || "")
    .trim()
    .replace(/\./g, "_")
    .replace(/\$/g, "_");
}

function normalizeOriginalSaveSlot(scriptId, slot) {
  const safeScriptId = sanitizeKey(scriptId);
  const safeSlot = slot && typeof slot === "object" ? { ...slot } : {};

  const slotId = sanitizeKey(
    safeSlot.slotId ||
    safeSlot.id ||
    safeSlot.saveId ||
    "default"
  );

  return {
    ...safeSlot,
    slotId,
    scriptId: safeScriptId,
    updatedAt: now()
  };
}

// ================= 原创剧情抽卡 / 剧情点 =================

const GACHA_CARD_IDS = ["linxia", "luxingyu", "sushiyan", "shenmo"];

const STORY_POINT_UNIT_PER_POINT = 10;     // 1 剧情点 = 10 units
const BLUE_CARD_REFUND_UNITS = 2;          // 普通蓝卡返还 0.2 剧情点 = 2 units
const READING_SECONDS_PER_POINT = 600;     // 阅读 600 秒 = 1 剧情点
const AUDIOBOOK_CHARS_PER_POINT = 500;     // 听书 500 字 = 1 剧情点
const SINGLE_DRAW_COST_UNITS = 10;         // 每抽消耗 10 units
const GOLD_RATE = 0.05;                    // 5% 出金
const PITY_TRIGGER_COUNT = 9;              // 本抽前 pityCount == 9 时必出金

// 隐藏剧情与金卡类型的绑定。
// 如果客户端传 hiddenScriptId，这里会严格校验。
// 如果后续客户端传的是具体视频 ID，也做了兼容。
const HIDDEN_CARD_REQUIREMENTS = {
  hidden_day4_linxia_luxingyu: "linxia",
  hidden_day4_luxingyu_shenmo: "luxingyu",
  hidden_day4_sushiyan_shenmo: "sushiyan",
  hidden_day4_shenmo_luxingyu: "shenmo",

  VID_D4_LX_LXY_HIDDEN_REEF_BOX: "linxia",
  VID_D4_LX_LXY_HIDDEN_SHELL_PROMISE: "linxia",

  VID_D4_LXY_SM_HIDDEN_REEF_CARD: "luxingyu",
  VID_D4_LXY_SM_HIDDEN_CARD_HANDOVER: "luxingyu",

  VID_D4_SSY_SM_HIDDEN_REEF_QUESTION: "sushiyan",
  VID_D4_SSY_SM_HIDDEN_NO_FRAMEWORK: "sushiyan",

  VID_D4_SM_LXY_HIDDEN_HIGH_REEF: "shenmo",
  VID_D4_SM_LXY_HIDDEN_PAPER_BOAT: "shenmo"
};

function normalizeCardId(cardId) {
  return String(cardId || "").trim().toLowerCase();
}

function normalizeCardInventory(raw) {
  const source = raw && typeof raw === "object" ? raw : {};
  const inventory = {};
  for (const cardId of GACHA_CARD_IDS) {
    inventory[cardId] = safeNumber(source[cardId]);
  }
  return inventory;
}

function normalizeUnlockedVideoIds(raw) {
  if (!Array.isArray(raw)) return [];
  return Array.from(
    new Set(
      raw
        .map((item) => String(item || "").trim())
        .filter(Boolean)
    )
  );
}

function defaultOriginalGachaState(scriptId) {
  return {
    scriptId,
    storyPointUnits: 0,
    pityCount: 0,
    spentReadingSeconds: 0,
    spentAudiobookChars: 0,
    cardInventory: normalizeCardInventory({}),
    unlockedVideoIds: [],
    updatedAt: now()
  };
}

function normalizeOriginalGachaState(scriptId, raw) {
  const item = raw && typeof raw === "object" ? raw : {};
  return {
    scriptId,
    storyPointUnits: safeNumber(item.storyPointUnits),
    pityCount: Math.min(safeNumber(item.pityCount), PITY_TRIGGER_COUNT),
    spentReadingSeconds: safeNumber(item.spentReadingSeconds),
    spentAudiobookChars: safeNumber(item.spentAudiobookChars),
    cardInventory: normalizeCardInventory(item.cardInventory || item.inventory),
    unlockedVideoIds: normalizeUnlockedVideoIds(
      item.unlockedVideoIds || item.unlockedHiddenStories
    ),
    updatedAt: Number(item.updatedAt || now())
  };
}

function getOriginalGachaStateFromUser(user, scriptId) {
  const safeScriptId = sanitizeKey(scriptId);
  const all =
    user && user.originalGacha && typeof user.originalGacha === "object"
      ? user.originalGacha
      : {};
  return normalizeOriginalGachaState(safeScriptId, all[safeScriptId]);
}

function toOriginalGachaResponse(state) {
  return {
    scriptId: state.scriptId,
    storyPointUnits: safeNumber(state.storyPointUnits),
    pityCount: Math.min(safeNumber(state.pityCount), PITY_TRIGGER_COUNT),
    spentReadingSeconds: safeNumber(state.spentReadingSeconds),
    spentAudiobookChars: safeNumber(state.spentAudiobookChars),
    cardInventory: normalizeCardInventory(state.cardInventory),
    unlockedVideoIds: normalizeUnlockedVideoIds(state.unlockedVideoIds)
  };
}

function totalAudiobookCharsOfUser(user) {
  const computed =
    safeNumber(user.totalSingleVoiceChars) +
    safeNumber(user.totalRoleVoiceChars) +
    safeNumber(user.totalInteractiveChars);

  return Math.max(safeNumber(user.totalAudiobookChars), computed);
}

function buildExchangePreview(user, state) {
  const totalReadingSeconds = safeNumber(user.totalReadingSeconds);
  const totalAudiobookChars = totalAudiobookCharsOfUser(user);

  const remainingReadingSeconds = Math.max(
    0,
    totalReadingSeconds - safeNumber(state.spentReadingSeconds)
  );

  const remainingAudiobookChars = Math.max(
    0,
    totalAudiobookChars - safeNumber(state.spentAudiobookChars)
  );

  return {
    maxByReading: Math.floor(remainingReadingSeconds / READING_SECONDS_PER_POINT),
    maxByAudiobook: Math.floor(remainingAudiobookChars / AUDIOBOOK_CHARS_PER_POINT)
  };
}

function pickGoldCardId() {
  const index = Math.floor(Math.random() * GACHA_CARD_IDS.length);
  return GACHA_CARD_IDS[index];
}

function getRequiredCardIdForVideo(videoId) {
  const raw = String(videoId || "").trim();
  if (!raw) return "";

  if (HIDDEN_CARD_REQUIREMENTS[raw]) {
    return HIDDEN_CARD_REQUIREMENTS[raw];
  }

  // 小写兼容，比如客户端传 hidden_day4_linxia_luxingyu
  const lowerMap = {};
  for (const [key, value] of Object.entries(HIDDEN_CARD_REQUIREMENTS)) {
    lowerMap[key.toLowerCase()] = value;
  }

  return lowerMap[raw.toLowerCase()] || "";
}

async function withOptionalTransaction(handler) {
  await connectDb();

  if (!mongoClient || typeof mongoClient.startSession !== "function") {
    return handler(undefined);
  }

  const session = mongoClient.startSession();

  try {
    let result;
    await session.withTransaction(async () => {
      result = await handler(session);
    });
    return result;
  } catch (error) {
    const message = String((error && error.message) || "");
    const unsupported =
      message.includes("Transaction numbers are only allowed") ||
      message.includes("replica set") ||
      message.includes("not a replica set") ||
      error.codeName === "IllegalOperation";

    if (!unsupported) throw error;

    console.warn("MongoDB transaction unsupported, fallback without transaction:", message);
    return handler(undefined);
  } finally {
    await session.endSession();
  }
}

function sessionOption(session) {
  return session ? { session } : undefined;
}

function buildOriginalUnlockSavePatch(user, scriptId, videoId) {
  const safeScriptId = sanitizeKey(scriptId);
  const safeVideoKey = sanitizeKey(videoId);

  const patch = {
    [`originalUnlockFlags.${safeScriptId}.${safeVideoKey}`]: true
  };

  const allSaves =
    user && user.originalSaves && typeof user.originalSaves === "object"
      ? user.originalSaves
      : {};

  const savesByScript = allSaves[safeScriptId];

  if (!savesByScript || typeof savesByScript !== "object") {
    return patch;
  }

  const updatedSavesByScript = {};

  for (const [slotId, slotValue] of Object.entries(savesByScript)) {
    if (!slotValue || typeof slotValue !== "object") {
      updatedSavesByScript[slotId] = slotValue;
      continue;
    }

    const slot = { ...slotValue };

    if (Array.isArray(slot.flags)) {
      slot.flags = Array.from(new Set([...slot.flags, videoId]));
    } else if (slot.flags && typeof slot.flags === "object") {
      slot.flags = {
        ...slot.flags,
        [videoId]: true,
        [`unlocked_${videoId}`]: true
      };
    } else {
      slot.flags = {
        [videoId]: true,
        [`unlocked_${videoId}`]: true
      };
    }

    if (Array.isArray(slot.unlockedVideoIds)) {
      slot.unlockedVideoIds = Array.from(new Set([...slot.unlockedVideoIds, videoId]));
    } else {
      slot.unlockedVideoIds = [videoId];
    }

    slot.updatedAt = now();
    updatedSavesByScript[slotId] = slot;
  }

  patch[`originalSaves.${safeScriptId}`] = updatedSavesByScript;
  return patch;
}

/**
 * 同步原创互动剧存档。
 *
 * App 请求：
 * {
 *   "scriptId": "seven_nights_coast",
 *   "slot": { ...OriginalSaveSlot... }
 * }
 *
 * 返回：
 * {
 *   "slot": { ... }
 * }
 */
app.post("/original/saves/sync", authRequired, async (req, res) => {
  try {
    await connectDb();

    const scriptId = sanitizeKey(req.body.scriptId);
    const slot = req.body.slot || {};

    if (!scriptId) return res.json(fail("缺少 scriptId"));

    const normalizedSlot = normalizeOriginalSaveSlot(scriptId, slot);
    const slotId = normalizedSlot.slotId;

    if (!slotId) return res.json(fail("缺少 slotId"));

    const savePath = `originalSaves.${scriptId}.${slotId}`;

    await users.updateOne(
      { uid: req.user.uid, deleted: { $ne: true } },
      {
        $set: {
          [savePath]: normalizedSlot,
          updatedAt: now()
        }
      }
    );

    res.json(ok({ slot: normalizedSlot }));
  } catch (error) {
    console.error("sync original save failed:", error);
    res.json(fail(error.message || "同步原创剧情存档失败"));
  }
});

/**
 * 获取原创互动剧存档列表。
 *
 * App 请求：
 * {
 *   "scriptId": "seven_nights_coast"
 * }
 *
 * 返回：
 * {
 *   "slots": [...]
 * }
 */
app.post("/original/saves/list", authRequired, async (req, res) => {
  try {
    const scriptId = sanitizeKey(req.body.scriptId);
    if (!scriptId) return res.json(fail("缺少 scriptId"));

    const user = await findUserByUid(req.user.uid);
    const savesByScript =
      user?.originalSaves &&
      user.originalSaves[scriptId] &&
      typeof user.originalSaves[scriptId] === "object"
        ? user.originalSaves[scriptId]
        : {};

    const slots = Object.values(savesByScript)
      .filter(Boolean)
      .sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));

    res.json(ok({ slots }));
  } catch (error) {
    console.error("list original saves failed:", error);
    res.json(fail(error.message || "获取原创剧情存档失败"));
  }
});

/**
 * 删除原创互动剧存档。
 *
 * App 请求：
 * {
 *   "scriptId": "seven_nights_coast",
 *   "slotId": "slot_1"
 * }
 */
app.post("/original/saves/delete", authRequired, async (req, res) => {
  try {
    await connectDb();

    const scriptId = sanitizeKey(req.body.scriptId);
    const slotId = sanitizeKey(req.body.slotId);

    if (!scriptId) return res.json(fail("缺少 scriptId"));
    if (!slotId) return res.json(fail("缺少 slotId"));

    const savePath = `originalSaves.${scriptId}.${slotId}`;

    await users.updateOne(
      { uid: req.user.uid, deleted: { $ne: true } },
      {
        $unset: {
          [savePath]: ""
        },
        $set: {
          updatedAt: now()
        }
      }
    );

    res.json(ok());
  } catch (error) {
    console.error("delete original save failed:", error);
    res.json(fail(error.message || "删除原创剧情存档失败"));
  }
});

/**
 * 获取原创剧情抽卡状态。
 *
 * App 请求：
 * {
 *   "scriptId": "seven_night_beach"
 * }
 */
app.post("/original/gacha/state", authRequired, async (req, res) => {
  try {
    await connectDb();

    const scriptId = sanitizeKey(req.body.scriptId);
    if (!scriptId) return res.json(fail("缺少 scriptId"));

    const user = await findUserByUid(req.user.uid);
    const state = getOriginalGachaStateFromUser(user, scriptId);

    if (!user.originalGacha || !user.originalGacha[scriptId]) {
      await users.updateOne(
        { uid: req.user.uid, deleted: { $ne: true } },
        {
          $set: {
            [`originalGacha.${scriptId}`]: state,
            updatedAt: now()
          }
        }
      );
    }

    res.json(ok({ gacha: toOriginalGachaResponse(state) }));
  } catch (error) {
    console.error("get original gacha state failed:", error);
    res.json(fail(error.message || "获取剧情点状态失败"));
  }
});

/**
 * 兑换预览。
 *
 * 阅读：
 * floor((totalReadingSeconds - spentReadingSeconds) / 600)
 *
 * 听书：
 * floor((totalSingleVoiceChars + totalRoleVoiceChars + totalInteractiveChars - spentAudiobookChars) / 500)
 */
app.post("/original/gacha/exchange/preview", authRequired, async (req, res) => {
  try {
    const scriptId = sanitizeKey(req.body.scriptId);
    if (!scriptId) return res.json(fail("缺少 scriptId"));

    const user = await findUserByUid(req.user.uid);
    const state = getOriginalGachaStateFromUser(user, scriptId);
    const preview = buildExchangePreview(user, state);

    res.json(ok({ preview }));
  } catch (error) {
    console.error("preview original gacha exchange failed:", error);
    res.json(fail(error.message || "获取兑换预览失败"));
  }
});

/**
 * 兑换剧情点。
 *
 * App 请求：
 * {
 *   "scriptId": "seven_night_beach",
 *   "source": "reading" | "audiobook",
 *   "points": 1
 * }
 */
app.post("/original/gacha/exchange", authRequired, async (req, res) => {
  try {
    const scriptId = sanitizeKey(req.body.scriptId);
    const source = String(req.body.source || "").trim();
    const points = safeNumber(req.body.points);

    if (!scriptId) return res.json(fail("缺少 scriptId"));
    if (source !== "reading" && source !== "audiobook") {
      return res.json(fail("兑换来源无效"));
    }
    if (points <= 0) {
      return res.json(fail("兑换剧情点数量必须大于0"));
    }

    const result = await withOptionalTransaction(async (session) => {
      const user = await users.findOne(
        { uid: req.user.uid, deleted: { $ne: true } },
        sessionOption(session)
      );

      if (!user) throw new Error("账号不存在或已注销");

      const state = getOriginalGachaStateFromUser(user, scriptId);
      const preview = buildExchangePreview(user, state);
      const maxAllowed =
        source === "reading" ? preview.maxByReading : preview.maxByAudiobook;

      if (points > maxAllowed) {
        throw new Error(
          source === "reading" ? "可兑换阅读时长不足" : "可兑换听书字数不足"
        );
      }

      const newState = {
        ...state,
        storyPointUnits:
          safeNumber(state.storyPointUnits) + points * STORY_POINT_UNIT_PER_POINT,
        spentReadingSeconds:
          safeNumber(state.spentReadingSeconds) +
          (source === "reading" ? points * READING_SECONDS_PER_POINT : 0),
        spentAudiobookChars:
          safeNumber(state.spentAudiobookChars) +
          (source === "audiobook" ? points * AUDIOBOOK_CHARS_PER_POINT : 0),
        updatedAt: now()
      };

      await users.updateOne(
        { uid: req.user.uid, deleted: { $ne: true } },
        {
          $set: {
            [`originalGacha.${scriptId}`]: newState,
            updatedAt: now()
          }
        },
        sessionOption(session)
      );

      const previewAfter = buildExchangePreview(user, newState);

      return {
        gacha: toOriginalGachaResponse(newState),
        preview: previewAfter
      };
    });

    res.json(ok(result));
  } catch (error) {
    console.error("original gacha exchange failed:", error);
    res.json(fail(error.message || "兑换剧情点失败"));
  }
});

/**
 * 抽卡。
 *
 * 规则：
 * - 每抽消耗 10 units
 * - 金卡概率 5%
 * - 本抽前 pityCount == 9 时必出金
 * - 未出金返还 2 units
 * - 金卡四角色等概率
 */
app.post("/original/gacha/draw", authRequired, async (req, res) => {
  try {
    const scriptId = sanitizeKey(req.body.scriptId);
    const count = safeNumber(req.body.count);

    if (!scriptId) return res.json(fail("缺少 scriptId"));
    if (count !== 1 && count !== 10) {
      return res.json(fail("抽卡次数只能是 1 或 10"));
    }

    const result = await withOptionalTransaction(async (session) => {
      const user = await users.findOne(
        { uid: req.user.uid, deleted: { $ne: true } },
        sessionOption(session)
      );

      if (!user) throw new Error("账号不存在或已注销");

      const state = getOriginalGachaStateFromUser(user, scriptId);
      const totalCost = count * SINGLE_DRAW_COST_UNITS;

      if (safeNumber(state.storyPointUnits) < totalCost) {
        throw new Error("剧情点不足");
      }

      const newState = {
        ...state,
        storyPointUnits: safeNumber(state.storyPointUnits) - totalCost,
        pityCount: Math.min(safeNumber(state.pityCount), PITY_TRIGGER_COUNT),
        cardInventory: normalizeCardInventory(state.cardInventory),
        unlockedVideoIds: normalizeUnlockedVideoIds(state.unlockedVideoIds),
        updatedAt: now()
      };

      const items = [];

      for (let i = 0; i < count; i += 1) {
        const mustGold = safeNumber(newState.pityCount) >= PITY_TRIGGER_COUNT;
        const isGold = mustGold || Math.random() < GOLD_RATE;

        if (isGold) {
          const cardId = pickGoldCardId();

          newState.cardInventory[cardId] =
            safeNumber(newState.cardInventory[cardId]) + 1;

          newState.pityCount = 0;

          items.push({
            type: "gold_card",
            cardId,
            storyPointUnits: 0
          });
        } else {
          newState.storyPointUnits += BLUE_CARD_REFUND_UNITS;
          newState.pityCount = safeNumber(newState.pityCount) + 1;

          items.push({
            type: "story_point",
            storyPointUnits: BLUE_CARD_REFUND_UNITS
          });
        }
      }

      await users.updateOne(
        { uid: req.user.uid, deleted: { $ne: true } },
        {
          $set: {
            [`originalGacha.${scriptId}`]: newState,
            updatedAt: now()
          }
        },
        sessionOption(session)
      );

      return {
        items,
        gacha: toOriginalGachaResponse(newState)
      };
    });

    res.json(ok(result));
  } catch (error) {
    console.error("original gacha draw failed:", error);
    res.json(fail(error.message || "抽卡失败"));
  }
});

/**
 * 使用角色金卡解锁隐藏剧情。
 *
 * App 请求：
 * {
 *   "scriptId": "seven_night_beach",
 *   "cardId": "linxia",
 *   "videoId": "hidden_day4_linxia_luxingyu"
 * }
 */
app.post("/original/gacha/use-card", authRequired, async (req, res) => {
  try {
    const scriptId = sanitizeKey(req.body.scriptId);
    const cardId = normalizeCardId(req.body.cardId);
    const videoId = String(req.body.videoId || "").trim();

    if (!scriptId) return res.json(fail("缺少 scriptId"));
    if (!GACHA_CARD_IDS.includes(cardId)) {
      return res.json(fail("金卡类型无效"));
    }
    if (!videoId) return res.json(fail("缺少 videoId"));

    const requiredCardId = getRequiredCardIdForVideo(videoId);
    if (requiredCardId && requiredCardId !== cardId) {
      return res.json(fail(`该隐藏剧情需要 ${requiredCardId} 金卡解锁`));
    }

    const result = await withOptionalTransaction(async (session) => {
      const user = await users.findOne(
        { uid: req.user.uid, deleted: { $ne: true } },
        sessionOption(session)
      );

      if (!user) throw new Error("账号不存在或已注销");

      const state = getOriginalGachaStateFromUser(user, scriptId);
      const inventory = normalizeCardInventory(state.cardInventory);
      const unlockedVideoIds = normalizeUnlockedVideoIds(state.unlockedVideoIds);

      if (unlockedVideoIds.includes(videoId)) {
        throw new Error("该隐藏剧情已解锁");
      }

      if (safeNumber(inventory[cardId]) <= 0) {
        throw new Error("对应角色金卡数量不足");
      }

      inventory[cardId] -= 1;

      const newState = {
        ...state,
        cardInventory: inventory,
        unlockedVideoIds: [...unlockedVideoIds, videoId],
        updatedAt: now()
      };

      const unlockPatch = buildOriginalUnlockSavePatch(user, scriptId, videoId);

      await users.updateOne(
        { uid: req.user.uid, deleted: { $ne: true } },
        {
          $set: {
            [`originalGacha.${scriptId}`]: newState,
            ...unlockPatch,
            updatedAt: now()
          }
        },
        sessionOption(session)
      );

      return {
        gacha: toOriginalGachaResponse(newState)
      };
    });

    res.json(ok(result));
  } catch (error) {
    console.error("use original gacha card failed:", error);
    res.json(fail(error.message || "使用金卡失败"));
  }
});

app.post("/original/resources/package", authRequired, async (req, res) => {
  try {
    await connectDb();

    const scriptId = String(req.body.scriptId || "").trim();

    if (!scriptId) {
      return res.json(fail("缺少 scriptId"));
    }

    const pkg = await resourcePackages
      .find({
        scriptId,
        enabled: { $ne: false }
      })
      .sort({ version: -1 })
      .limit(1)
      .next();

    if (!pkg) {
      return res.json(fail("资源包不存在"));
    }

    res.json(ok({
      package: {
        scriptId: pkg.scriptId,
        version: Number(pkg.version || 1),
        sizeBytes: Number(pkg.sizeBytes || 0),
        sha256: pkg.sha256 || "",
        downloadUrl: pkg.downloadUrl || "",
        encryption: pkg.encryption || "AES-GCM",
        keyBase64: pkg.keyBase64 || "",
        ivBase64: pkg.ivBase64 || ""
      }
    }));
  } catch (error) {
    console.error("get original resource package failed:", error);
    res.json(fail(error.message || "获取原创资源包失败"));
  }
});

app.post("/rankings", async (req, res) => {
  try {
    await connectDb();

    const rankingFilter = {
      deleted: { $ne: true },
      joinsRanking: { $ne: false },
      rankingVisible: { $ne: false }
    };

    const readingRows = await users
      .find(rankingFilter)
      .sort({ totalReadingSeconds: -1 })
      .limit(50)
      .toArray();

    const audioRows = await users
      .find(rankingFilter)
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
