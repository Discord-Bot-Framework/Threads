from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import difflib
import functools
import pathlib
import re
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

import aiohttp
import arc
import hikari
import lmdb
import miru
from hikari.impl.special_endpoints import PollAnswerBuilder, PollBuilder
from src.container.app import get_miru
from src.shared.logger import get_module_logger
from src.shared.persistence.constants import MSGPACK_DECODE_ERRORS
from src.shared.persistence.store import Store, pack_msgpack, unpack_msgpack
from src.shared.utils.view import (
    Color,
    bind_view_to_response,
    defer,
    reply_embed,
    reply_err,
    reply_ok,
)
from yarl import URL

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

BASE_DIR = pathlib.Path(__file__).resolve().parent
BANNED_USERS_FILE = BASE_DIR / "banned_users.json"
THREAD_PERMISSIONS_FILE = BASE_DIR / "thread_permissions.json"
TIMEOUT_HISTORY_FILE = BASE_DIR / "timeout_history.json"
STARRED_MESSAGES_FILE = BASE_DIR / "starred_messages.json"
PHISHING_DB_FILE = BASE_DIR / "phishing_domains.json"
SCRUB_RULES_FILE = BASE_DIR / "scrub_rules.json"
DB_PATH = BASE_DIR / "threads"
DB_MAP_SIZE: int = 50 * 1024 * 1024
STORE_DATABASES: dict[str, str] = {
    BANNED_USERS_FILE.name: "banned_users",
    THREAD_PERMISSIONS_FILE.name: "thread_permissions",
    TIMEOUT_HISTORY_FILE.name: "timeout_history",
    STARRED_MESSAGES_FILE.name: "starred_messages",
    PHISHING_DB_FILE.name: "phishing_domains",
    SCRUB_RULES_FILE.name: "scrub_rules",
}

LOG_CHANNEL_ID = 1166627731916734504
LOG_FORUM_ID = 1159097493875871784
LOG_POST_ID = 1325393614343376916
STARBOARD_FORUM_ID = 1168209956802142360
STARBOARD_POST_ID = 1312109214533025904
TAIWAN_ROLE_ID = 1261328929013108778
THREADS_ROLE_ID = 1223635198327914639
GUILD_ID = 1150630510696075404
CONGRESS_FORUM_ID = 1196707789859459132
CONGRESS_MEMBER_ROLE = 1200254783110525010
CONGRESS_MOD_ROLE = 1300132191883235368
POLL_FORUM_ID = (1155914521907568740,)

ROLE_CHANNEL_PERMISSIONS: dict[int, tuple[int, ...]] = {
    1223635198327914639: (
        1152311220557320202,
        1168209956802142360,
        1230197011761074340,
        1155914521907568740,
        1169032829548630107,
        1213345198147637268,
        1183254117813071922,
        1151389184779636766,
        1250396377540853801,
    ),
    1213490790341279754: (1185259262654562355, 1151389184779636766),
    1251935385521750116: (1151389184779636766,),
}
ALLOWED_CHANNELS: tuple[int, ...] = (
    1152311220557320202,
    1168209956802142360,
    1230197011761074340,
    1155914521907568740,
    1169032829548630107,
    1185259262654562355,
    1183048643071180871,
    1213345198147637268,
    1183254117813071922,
    1151389184779636766,
    1196707789859459132,
    1250396377540853801,
)
STAR_EMOJIS = ("✨", "⭐", "🌟", "💫")
URL_PATTERN = re.compile(r"(https?://\S+)")
EMOJI_PATTERN = re.compile(
    r"[\U0001F300-\U0001F9FF]|[\u2600-\u26FF\u2700-\u27BF]|<a?:[a-zA-Z0-9_]+:[0-9]+>",
)
MENTION_PATTERN = re.compile(r"<[@#]&?\d+>|@everyone|@here")
TOKEN_PATTERN = re.compile(r"<url>|<mention>|[a-z0-9_]+")
INTERNAL_REPEAT_PATTERN = re.compile(r"(.{2,24}?)\1{3,}", re.DOTALL)

logger = get_module_logger(__file__, __name__, "threads.log")


class ActionType(Enum):
    CHECK = auto()
    LOCK = auto()
    UNLOCK = auto()
    BAN = auto()
    UNBAN = auto()
    DELETE = auto()
    EDIT = auto()
    PIN = auto()
    UNPIN = auto()
    SHARE_PERMISSIONS = auto()
    REVOKE_PERMISSIONS = auto()


@dataclasses.dataclass(slots=True)
class ActionDetails:
    action: ActionType
    reason: str
    post_name: str
    actor: hikari.Member | hikari.User | hikari.OwnUser
    target: hikari.Member | hikari.User | hikari.OwnUser | None = None
    result: str = "completed"
    channel: hikari.GuildThreadChannel | hikari.GuildChannel | None = None
    additional_info: Mapping[str, Any] | None = None


@dataclasses.dataclass(slots=True)
class TimeoutConfig:
    base_duration: int = 300
    multiplier: float = 1.5
    decay_hours: int = 24
    max_duration: int = 3600
    low_activity_threshold: int = 10
    high_activity_threshold: int = 100
    low_violation_rate: float = 1.0
    high_violation_rate: float = 5.0
    base_duration_step: int = 60
    multiplier_step: float = 0.1
    decay_hours_step: int = 1


@dataclasses.dataclass(slots=True)
class MessageRecord:
    timestamp: datetime
    content: str | None = None
    channel_id: str | None = None


@dataclasses.dataclass(slots=True)
class SpamThresholds:
    rate_limit: int = 5
    global_rate_limit: int = 10
    max_mentions: int = 5
    max_emojis: int = 10
    history_window: int = 30
    warning_cooldown: int = 60
    rapid_window_seconds: int = 6
    burst_window_seconds: int = 30
    rapid_message_limit: int = 4
    burst_message_limit: int = 10
    similarity_hit_window: int = 45
    similarity_hit_limit: int = 2
    channel_bucket_capacity: float = 6.0
    channel_bucket_refill_per_sec: float = 1.2
    global_bucket_capacity: float = 12.0
    global_bucket_refill_per_sec: float = 1.8
    similarity_thresholds: dict[str, float] = dataclasses.field(
        default_factory=lambda: {
            "short": 0.90,
            "medium": 0.84,
            "long": 0.78,
        },
    )
    exempt_roles: set[int] = dataclasses.field(
        default_factory=lambda: {
            1243261836187664545,
            1275980805273026571,
            1292065942544711781,
            1200052609487208488,
            1200042960969019473,
        },
    )


@dataclasses.dataclass(slots=True)
class SpamState:
    message_history: defaultdict[str, deque[datetime]] = dataclasses.field(
        default_factory=lambda: defaultdict(deque),
    )
    content_history: defaultdict[str, deque[MessageRecord]] = dataclasses.field(
        default_factory=lambda: defaultdict(deque),
    )
    guild_wide_history: defaultdict[str, deque[MessageRecord]] = dataclasses.field(
        default_factory=lambda: defaultdict(deque),
    )
    similarity_hits: defaultdict[str, deque[datetime]] = dataclasses.field(
        default_factory=lambda: defaultdict(deque),
    )
    rate_buckets: defaultdict[str, tuple[float, float]] = dataclasses.field(
        default_factory=lambda: defaultdict(lambda: (0.0, 0.0)),
    )
    cooldowns: defaultdict[str, float] = dataclasses.field(
        default_factory=lambda: defaultdict(float),
    )


@dataclasses.dataclass(slots=True)
class StarStats:
    hourly: dict[str, int] = dataclasses.field(default_factory=dict)
    daily: dict[str, int] = dataclasses.field(default_factory=dict)
    weekly: dict[str, int] = dataclasses.field(default_factory=dict)
    threshold_history: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    last_adjustment: datetime = dataclasses.field(
        default_factory=lambda: datetime.now(UTC),
    )


@dataclasses.dataclass(slots=True)
class StarConfig:
    min_threshold: int = 3
    max_threshold: int = 10
    adjustment_interval: int = 3600
    decay_factor: float = 0.95
    growth_factor: float = 1.05
    activity_weight: float = 0.3
    time_weight: float = 0.2
    quality_weight: float = 0.5


class ThreadModel:
    def __init__(self) -> None:
        self._store = Store(
            DB_PATH,
            tuple(STORE_DATABASES.values()),
            map_size=DB_MAP_SIZE,
        )
        self.timeout_config = TimeoutConfig()
        self.banned_users: defaultdict[str, defaultdict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set),
        )
        self.thread_permissions: defaultdict[str, set[str]] = defaultdict(set)
        self.timeout_history: dict[str, dict[str, Any]] = {}
        self.phishing_domains: dict[str, dict[str, Any]] = {}
        self.message_history: defaultdict[int, list[datetime]] = defaultdict(list)
        self.violation_history: defaultdict[int, list[datetime]] = defaultdict(list)
        self.last_timeout_adjustment = datetime.now(UTC)
        self.timeout_adjustment_interval = timedelta(hours=1)
        self.ban_cache: dict[tuple[str, str, str], tuple[bool, datetime]] = {}
        self.cache_duration = timedelta(minutes=5)

        self.starred_messages: dict[str, int] = {}
        self.starboard_messages: dict[str, str] = {}
        self.star_threshold = 3
        self.star_stats = StarStats()
        self.star_config = StarConfig()

        self.spam = SpamState()
        self.spam_thresholds = SpamThresholds()

        self.rules: dict[str, Any] = {}
        self._banned_users_snapshot: dict[bytes, bytes] = {}
        self._thread_permissions_snapshot: dict[bytes, bytes] = {}
        self._timeout_history_snapshot: dict[bytes, bytes] = {}
        self._phishing_snapshot: dict[bytes, bytes] = {}
        self._scrub_rules_snapshot: dict[bytes, bytes] = {}
        self._star_snapshot: dict[bytes, bytes] = {}

    async def load_all(self) -> None:
        await asyncio.gather(
            self.load_banned_users(BANNED_USERS_FILE),
            self.load_thread_permissions(THREAD_PERMISSIONS_FILE),
            self.load_timeout_history(TIMEOUT_HISTORY_FILE),
            self.load_phishing_db(PHISHING_DB_FILE),
            self.load_starred_messages(STARRED_MESSAGES_FILE),
            self.load_scrub_rules(SCRUB_RULES_FILE),
        )

    def _open_env(self) -> lmdb.Environment:
        self._store.open()
        env = self._store.env
        if env is None:
            msg = "Failed to initialize LMDB environment."
            raise RuntimeError(msg)
        return env

    def close(self) -> None:
        self._store.close()

    def _pack(self, payload: Any) -> bytes:
        return pack_msgpack(payload)

    def _unpack(self, packed: bytes) -> Any:
        return unpack_msgpack(packed, strict_map_key=False)

    def _load_packed_records(self, db_name: str) -> dict[bytes, bytes]:
        env = self._open_env()
        store_db = self._store.get_db(db_name)
        if store_db is None:
            return {}
        records: dict[bytes, bytes] = {}
        try:
            with env.begin(write=False, db=store_db) as txn:
                for key, value in txn.cursor():
                    records[bytes(key)] = bytes(value)
        except lmdb.Error:
            logger.exception("Failed to load records for store %s", db_name)
            return {}
        return records

    def _sync_records(
        self,
        db_name: str,
        desired: dict[bytes, Any],
        snapshot: dict[bytes, bytes],
    ) -> None:
        env = self._open_env()
        store_db = self._store.get_db(db_name)
        if store_db is None:
            logger.error("Failed to resolve LMDB store %s", db_name)
            return

        desired_packed: dict[bytes, bytes] = {}
        for key, value in desired.items():
            desired_packed[key] = self._pack(value)

        to_delete = [key for key in snapshot if key not in desired_packed]
        try:
            with env.begin(write=True, db=store_db) as txn:
                for key in to_delete:
                    txn.delete(key)
                for key, packed in desired_packed.items():
                    if snapshot.get(key) != packed:
                        txn.put(key, packed)
        except lmdb.Error:
            logger.exception("Failed to sync records for store %s", db_name)
            return
        snapshot.clear()
        snapshot.update(desired_packed)

    async def _read_store(self, file_path: pathlib.Path) -> Any:
        name = file_path.name
        if name == SCRUB_RULES_FILE.name:
            return self.rules
        if name == PHISHING_DB_FILE.name:
            return self.phishing_domains
        if name == TIMEOUT_HISTORY_FILE.name:
            return self.timeout_history
        if name == THREAD_PERMISSIONS_FILE.name:
            return {thread_id: sorted(users) for thread_id, users in self.thread_permissions.items()}
        if name == BANNED_USERS_FILE.name:
            return {
                channel_id: {post_id: sorted(users) for post_id, users in post_data.items()}
                for channel_id, post_data in self.banned_users.items()
            }
        if name == STARRED_MESSAGES_FILE.name:
            return {
                "starred_messages": self.starred_messages,
                "starboard_messages": self.starboard_messages,
            }
        return None

    async def load_scrub_rules(self, file_path: pathlib.Path) -> None:
        del file_path
        packed_records = self._load_packed_records("scrub_rules")
        parsed: dict[str, Any] = {}
        for packed in packed_records.values():
            with contextlib.suppress(*MSGPACK_DECODE_ERRORS):
                record = self._unpack(packed)
                if not isinstance(record, dict):
                    continue
                key = record.get("key")
                if isinstance(key, str):
                    parsed[key] = record.get("value")
        self.rules = parsed
        self._scrub_rules_snapshot = dict(packed_records)

    async def save_scrub_rules(self, file_path: pathlib.Path) -> None:
        del file_path
        desired: dict[bytes, Any] = {
            str(key).encode("utf-8"): {"key": str(key), "value": value} for key, value in self.rules.items()
        }
        self._sync_records("scrub_rules", desired, self._scrub_rules_snapshot)

    async def load_phishing_db(self, file_path: pathlib.Path) -> None:
        del file_path
        packed_records = self._load_packed_records("phishing_domains")
        parsed: dict[str, dict[str, Any]] = {}
        for packed in packed_records.values():
            with contextlib.suppress(*MSGPACK_DECODE_ERRORS):
                record = self._unpack(packed)
                if not isinstance(record, dict):
                    continue
                domain = record.get("domain")
                entry = record.get("entry")
                if isinstance(domain, str) and isinstance(entry, dict):
                    parsed[domain] = entry
        self.phishing_domains = parsed
        self._phishing_snapshot = dict(packed_records)

    async def save_phishing_db(self, file_path: pathlib.Path) -> None:
        del file_path
        desired: dict[bytes, Any] = {
            domain.encode("utf-8"): {"domain": domain, "entry": entry}
            for domain, entry in self.phishing_domains.items()
            if isinstance(domain, str) and isinstance(entry, dict)
        }
        self._sync_records("phishing_domains", desired, self._phishing_snapshot)

    async def load_timeout_history(self, file_path: pathlib.Path) -> None:
        del file_path
        packed_records = self._load_packed_records("timeout_history")
        parsed: dict[str, dict[str, Any]] = {}
        for packed in packed_records.values():
            with contextlib.suppress(*MSGPACK_DECODE_ERRORS):
                record = self._unpack(packed)
                if not isinstance(record, dict):
                    continue
                user_id = record.get("user_id")
                if not isinstance(user_id, (str, int)):
                    continue
                violation_count = record.get("violation_count", 0)
                last_timeout = record.get("last_timeout", 0.0)
                parsed[str(user_id)] = {
                    "violation_count": int(violation_count) if isinstance(violation_count, (int, float)) else 0,
                    "last_timeout": float(last_timeout) if isinstance(last_timeout, (int, float)) else 0.0,
                }
        self.timeout_history = parsed
        self._timeout_history_snapshot = dict(packed_records)

    async def save_timeout_history(self, file_path: pathlib.Path) -> None:
        del file_path
        desired: dict[bytes, Any] = {}
        for user_id, data in self.timeout_history.items():
            if not isinstance(data, dict):
                continue
            violation_count = data.get("violation_count", 0)
            last_timeout = data.get("last_timeout", 0.0)
            desired[str(user_id).encode("utf-8")] = {
                "user_id": str(user_id),
                "violation_count": int(violation_count) if isinstance(violation_count, (int, float)) else 0,
                "last_timeout": float(last_timeout) if isinstance(last_timeout, (int, float)) else 0.0,
            }
        self._sync_records("timeout_history", desired, self._timeout_history_snapshot)

    async def load_banned_users(self, file_path: pathlib.Path) -> None:
        del file_path
        packed_records = self._load_packed_records("banned_users")
        normalized: defaultdict[str, defaultdict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set),
        )
        for packed in packed_records.values():
            with contextlib.suppress(*MSGPACK_DECODE_ERRORS):
                record = self._unpack(packed)
                if not isinstance(record, dict):
                    continue
                channel_id = record.get("channel_id")
                post_id = record.get("post_id")
                users = record.get("users")
                if not isinstance(channel_id, (str, int)) or not isinstance(
                    post_id,
                    (str, int),
                ):
                    continue
                if not isinstance(users, list):
                    continue
                normalized[str(channel_id)][str(post_id)] = {
                    str(user_id) for user_id in users if isinstance(user_id, (str, int))
                }
        self.banned_users = normalized
        self._banned_users_snapshot = dict(packed_records)

    async def save_banned_users(self, file_path: pathlib.Path) -> None:
        del file_path
        desired: dict[bytes, Any] = {}
        for channel_id, post_data in self.banned_users.items():
            for post_id, users in post_data.items():
                key = f"{channel_id}:{post_id}".encode()
                desired[key] = {
                    "channel_id": str(channel_id),
                    "post_id": str(post_id),
                    "users": sorted(str(user_id) for user_id in users),
                }
        self._sync_records("banned_users", desired, self._banned_users_snapshot)

    async def load_thread_permissions(self, file_path: pathlib.Path) -> None:
        del file_path
        packed_records = self._load_packed_records("thread_permissions")
        normalized: defaultdict[str, set[str]] = defaultdict(set)
        for packed in packed_records.values():
            with contextlib.suppress(*MSGPACK_DECODE_ERRORS):
                record = self._unpack(packed)
                if not isinstance(record, dict):
                    continue
                thread_id = record.get("thread_id")
                users = record.get("users")
                if not isinstance(thread_id, (str, int)) or not isinstance(users, list):
                    continue
                normalized[str(thread_id)] = {str(user_id) for user_id in users if isinstance(user_id, (str, int))}
        self.thread_permissions = normalized
        self._thread_permissions_snapshot = dict(packed_records)

    async def save_thread_permissions(self, file_path: pathlib.Path) -> None:
        del file_path
        desired: dict[bytes, Any] = {
            str(thread_id).encode("utf-8"): {
                "thread_id": str(thread_id),
                "users": sorted(str(user_id) for user_id in users),
            }
            for thread_id, users in self.thread_permissions.items()
        }
        self._sync_records(
            "thread_permissions",
            desired,
            self._thread_permissions_snapshot,
        )

    async def load_starred_messages(self, file_path: pathlib.Path) -> None:
        del file_path
        packed_records = self._load_packed_records("starred_messages")

        starred_messages: dict[str, int] = {}
        starboard_messages: dict[str, str] = {}
        hourly: dict[str, int] = {}
        daily: dict[str, int] = {}
        weekly: dict[str, int] = {}
        threshold_history: list[dict[str, Any]] = []
        last_adjustment = datetime.now(UTC)
        star_threshold = self.star_threshold
        star_config = self.star_config

        for key, packed in packed_records.items():
            key_text = key.decode("utf-8", errors="ignore")
            with contextlib.suppress(*MSGPACK_DECODE_ERRORS):
                record = self._unpack(packed)
                if not isinstance(record, dict):
                    continue
                if key_text.startswith("sm:"):
                    message_id = record.get("message_id")
                    count = record.get("count")
                    if isinstance(message_id, (str, int)) and isinstance(count, int):
                        starred_messages[str(message_id)] = count
                elif key_text.startswith("sb:"):
                    source_id = record.get("source_id")
                    target_id = record.get("target_id")
                    if isinstance(source_id, (str, int)) and isinstance(
                        target_id,
                        (str, int),
                    ):
                        starboard_messages[str(source_id)] = str(target_id)
                elif key_text.startswith("sh:h:"):
                    ts = record.get("timestamp")
                    count = record.get("count")
                    if isinstance(ts, str) and isinstance(count, int):
                        hourly[ts] = count
                elif key_text.startswith("sh:d:"):
                    ts = record.get("timestamp")
                    count = record.get("count")
                    if isinstance(ts, str) and isinstance(count, int):
                        daily[ts] = count
                elif key_text.startswith("sh:w:"):
                    ts = record.get("timestamp")
                    count = record.get("count")
                    if isinstance(ts, str) and isinstance(count, int):
                        weekly[ts] = count
                elif key_text == "cfg:star_threshold":
                    value = record.get("value")
                    if isinstance(value, int):
                        star_threshold = value
                elif key_text == "cfg:star_config":
                    value = record.get("value")
                    if isinstance(value, dict):
                        star_config = self._normalize_star_config(value)
                elif key_text == "cfg:last_adjustment":
                    value = record.get("value")
                    if isinstance(value, str):
                        last_adjustment = self._normalize_dt(value)
                elif key_text == "cfg:threshold_history":
                    value = record.get("value")
                    if isinstance(value, list):
                        threshold_history = [item for item in value if isinstance(item, dict)]

        self.starred_messages = starred_messages
        self.starboard_messages = starboard_messages
        self.star_threshold = star_threshold
        self.star_config = star_config
        self.star_stats = StarStats(
            hourly=hourly,
            daily=daily,
            weekly=weekly,
            threshold_history=threshold_history,
            last_adjustment=last_adjustment,
        )
        self._star_snapshot = dict(packed_records)

    async def save_starred_messages(self, file_path: pathlib.Path) -> None:
        del file_path
        desired: dict[bytes, Any] = {}
        for message_id, count in self.starred_messages.items():
            desired[f"sm:{message_id}".encode()] = {
                "message_id": message_id,
                "count": int(count),
            }
        for source_id, target_id in self.starboard_messages.items():
            desired[f"sb:{source_id}".encode()] = {
                "source_id": source_id,
                "target_id": target_id,
            }
        for ts, count in self.star_stats.hourly.items():
            desired[f"sh:h:{ts}".encode()] = {
                "timestamp": ts,
                "count": int(count),
            }
        for ts, count in self.star_stats.daily.items():
            desired[f"sh:d:{ts}".encode()] = {
                "timestamp": ts,
                "count": int(count),
            }
        for ts, count in self.star_stats.weekly.items():
            desired[f"sh:w:{ts}".encode()] = {
                "timestamp": ts,
                "count": int(count),
            }

        desired[b"cfg:star_threshold"] = {"value": int(self.star_threshold)}
        desired[b"cfg:star_config"] = {"value": dataclasses.asdict(self.star_config)}
        desired[b"cfg:last_adjustment"] = {
            "value": self.star_stats.last_adjustment.isoformat(),
        }
        desired[b"cfg:threshold_history"] = {
            "value": self.star_stats.threshold_history,
        }
        self._sync_records("starred_messages", desired, self._star_snapshot)

    def _normalize_star_stats(self, raw: dict[str, Any]) -> StarStats:
        hourly = raw.get("hourly", {})
        daily = raw.get("daily", {})
        weekly = raw.get("weekly", {})
        last_adjustment = raw.get("last_adjustment", {})
        threshold_history = raw.get("threshold_history", {})

        stats = StarStats(
            hourly=self._normalize_stats_bucket(hourly),
            daily=self._normalize_stats_bucket(daily),
            weekly=self._normalize_stats_bucket(weekly),
            threshold_history=(
                threshold_history.get("history", [])
                if isinstance(threshold_history, dict) and isinstance(threshold_history.get("history"), list)
                else []
            ),
            last_adjustment=self._normalize_dt(last_adjustment),
        )
        return stats

    def _normalize_stats_bucket(self, raw_bucket: Any) -> dict[str, int]:
        if not isinstance(raw_bucket, dict):
            return {}
        source = raw_bucket.get("stats") if "stats" in raw_bucket else raw_bucket
        if not isinstance(source, dict):
            return {}
        out: dict[str, int] = {}
        for k, v in source.items():
            if isinstance(v, int):
                out[str(k)] = v
        return out

    def _normalize_dt(self, raw: Any) -> datetime:
        if isinstance(raw, dict):
            raw = raw.get("timestamp")
        if isinstance(raw, str):
            with contextlib.suppress(ValueError):
                parsed = datetime.fromisoformat(raw)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=UTC)
                return parsed
        return datetime.now(UTC)

    def _normalize_star_config(self, config: Mapping[str, Any]) -> StarConfig:
        values = dataclasses.asdict(StarConfig())
        for key, default in values.items():
            candidate = config.get(key)
            if isinstance(default, int) and isinstance(candidate, int):
                values[key] = candidate
            elif isinstance(default, float) and isinstance(candidate, (int, float)):
                values[key] = float(candidate)
        return StarConfig(**values)

    def record_message(self, channel_id: int) -> None:
        self.message_history[channel_id].append(datetime.now(UTC))

    def record_violation(self, channel_id: int) -> None:
        self.violation_history[channel_id].append(datetime.now(UTC))

    async def adjust_timeout_cfg(self) -> None:
        now = datetime.now(UTC)
        if now - self.last_timeout_adjustment < self.timeout_adjustment_interval:
            return

        one_hour_ago = now - timedelta(hours=1)
        for history in (self.message_history, self.violation_history):
            for key in list(history.keys()):
                history[key] = [entry for entry in history[key] if entry >= one_hour_ago]
                if not history[key]:
                    del history[key]

        total_messages = sum(len(values) for values in self.message_history.values())
        total_violations = sum(len(values) for values in self.violation_history.values())
        violation_rate = (total_violations * 100 / total_messages) if total_messages else 0

        cfg = self.timeout_config
        activity_factor = (total_messages > cfg.high_activity_threshold) - (total_messages < cfg.low_activity_threshold)
        violation_factor = (violation_rate > cfg.high_violation_rate) - (violation_rate < cfg.low_violation_rate)
        total_factor = activity_factor + violation_factor

        cfg.base_duration = max(
            60,
            min(600, cfg.base_duration + total_factor * cfg.base_duration_step),
        )
        cfg.multiplier = max(
            1.2,
            min(2.0, cfg.multiplier + total_factor * cfg.multiplier_step),
        )
        cfg.decay_hours = max(
            12,
            min(48, cfg.decay_hours - activity_factor * cfg.decay_hours_step),
        )
        cfg.max_duration = 3600

        self.last_timeout_adjustment = now

    def calculate_timeout_duration(self, user_id: str) -> int:
        current_ts = datetime.now(UTC).timestamp()
        user_data = self.timeout_history.setdefault(
            user_id,
            {
                "violation_count": 0,
                "last_timeout": current_ts,
            },
        )

        last_timeout = user_data.get("last_timeout")
        last_timeout_ts = float(last_timeout) if isinstance(last_timeout, (float, int)) else current_ts
        decay_periods = int(
            (current_ts - last_timeout_ts) / (self.timeout_config.decay_hours * 3600),
        )

        current_count = user_data.get("violation_count")
        violation_count = int(current_count) if isinstance(current_count, (int, float)) else 0
        violation_count = max(1, violation_count - decay_periods + 1)

        user_data["violation_count"] = violation_count
        user_data["last_timeout"] = current_ts

        duration = int(
            self.timeout_config.base_duration * (self.timeout_config.multiplier ** (violation_count - 1)),
        )
        return min(duration, self.timeout_config.max_duration)

    async def adjust_star_threshold(self) -> None:
        now = datetime.now(UTC)
        if (now - self.star_stats.last_adjustment).total_seconds() < self.star_config.adjustment_interval:
            return

        hourly_stars = sum(self.star_stats.hourly.values())
        daily_stars = sum(self.star_stats.daily.values())
        weekly_stars = sum(self.star_stats.weekly.values())

        activity_score = (hourly_stars / 10 + daily_stars / 200 + weekly_stars / 1000) / 3

        if 0 <= now.hour < 6:
            time_factor = 0.8
        elif 6 <= now.hour < 12:
            time_factor = 1.1
        elif 12 <= now.hour < 18:
            time_factor = 1.2
        else:
            time_factor = 1.0

        quality_score = len(self.starboard_messages) / (len(self.starred_messages) or 1)

        final_score = (
            activity_score * self.star_config.activity_weight
            + time_factor * self.star_config.time_weight
            + quality_score * self.star_config.quality_weight
        )

        if final_score > 1.0:
            new_threshold = min(
                int(self.star_threshold * self.star_config.growth_factor),
                self.star_config.max_threshold,
            )
        else:
            new_threshold = max(
                int(self.star_threshold * self.star_config.decay_factor),
                self.star_config.min_threshold,
            )

        if new_threshold != self.star_threshold:
            self.star_threshold = new_threshold
            self.star_stats.threshold_history.append(
                {
                    "timestamp": now.isoformat(),
                    "new_threshold": new_threshold,
                    "activity_score": activity_score,
                    "time_factor": time_factor,
                    "quality_score": quality_score,
                    "final_score": final_score,
                },
            )
            if len(self.star_stats.threshold_history) > 100:
                self.star_stats.threshold_history = self.star_stats.threshold_history[-100:]

        hour_cutoff = (now - timedelta(hours=24)).isoformat()
        day_cutoff = (now - timedelta(days=7)).isoformat()
        week_cutoff = (now - timedelta(weeks=4)).isoformat()

        self.star_stats.hourly = {k: v for k, v in self.star_stats.hourly.items() if k >= hour_cutoff}
        self.star_stats.daily = {k: v for k, v in self.star_stats.daily.items() if k >= day_cutoff}
        self.star_stats.weekly = {k: v for k, v in self.star_stats.weekly.items() if k >= week_cutoff}
        self.star_stats.last_adjustment = now

    def is_user_banned(self, channel_id: str, post_id: str, user_id: str) -> bool:
        key = (channel_id, post_id, user_id)
        now = datetime.now(UTC)
        cached = self.ban_cache.get(key)
        if cached and now - cached[1] < self.cache_duration:
            return cached[0]
        result = user_id in self.banned_users[channel_id][post_id]
        self.ban_cache[key] = (result, now)
        return result

    def invalidate_ban_cache(self, channel_id: str, post_id: str, user_id: str) -> None:
        self.ban_cache.pop((channel_id, post_id, user_id), None)

    def has_thread_permissions(self, post_id: str, user_id: str) -> bool:
        return user_id in self.thread_permissions[post_id]


plugin = arc.GatewayPlugin(name="Threads")
threads_group = plugin.include_slash_group("threads", "Threads commands")
scrub_group = threads_group.include_subgroup(
    "scrub",
    "Scrub tracking elements from hyperlinks",
)

model = ThreadModel()
ban_lock = asyncio.Lock()
last_log_key: str | None = None


async def initialize_data() -> None:
    await model.load_all()


@plugin.listen(hikari.StartedEvent)
async def on_started(_: hikari.StartedEvent) -> None:
    await initialize_data()


@functools.lru_cache(maxsize=1)
def get_log_channels() -> tuple[int, int, int]:
    return (LOG_CHANNEL_ID, LOG_POST_ID, LOG_FORUM_ID)


def get_action_color(action: ActionType) -> int:
    mapping: dict[ActionType, Color] = {
        ActionType.CHECK: Color.INFO,
        ActionType.LOCK: Color.WARNING,
        ActionType.UNLOCK: Color.INFO,
        ActionType.BAN: Color.ERROR,
        ActionType.UNBAN: Color.INFO,
        ActionType.DELETE: Color.WARNING,
        ActionType.EDIT: Color.INFO,
        ActionType.PIN: Color.INFO,
        ActionType.UNPIN: Color.INFO,
        ActionType.SHARE_PERMISSIONS: Color.INFO,
        ActionType.REVOKE_PERMISSIONS: Color.WARNING,
    }
    return int(mapping.get(action, Color.INFO))


def format_additional_info(info: Mapping[str, Any]) -> str:
    lines: list[str] = []
    for key, value in info.items():
        key_name = key.replace("_", " ").title()
        if isinstance(value, list) and value and isinstance(value[0], dict):
            lines.append(f"**{key_name}**:")
            for item in value:
                if isinstance(item, dict):
                    for item_key, item_value in item.items():
                        lines.append(f"- {item_key}: {item_value}")
        else:
            lines.append(f"**{key_name}**: {value}")
    return "\n".join(lines)


def get_notification_message(details: ActionDetails) -> str:
    channel_mention = details.channel.mention if details.channel else "the thread"
    action = details.action
    base_messages = {
        ActionType.CHECK: f"{channel_mention} has been checked.",
        ActionType.LOCK: f"{channel_mention} has been locked.",
        ActionType.UNLOCK: f"{channel_mention} has been unlocked.",
        ActionType.DELETE: f"Your message has been deleted from {channel_mention}.",
        ActionType.BAN: (
            f"You have been banned from {channel_mention}. If you continue to attempt to "
            "post, your comments will be deleted."
        ),
        ActionType.UNBAN: f"You have been unbanned from {channel_mention}.",
        ActionType.SHARE_PERMISSIONS: f"You have been granted permissions to {channel_mention}.",
        ActionType.REVOKE_PERMISSIONS: f"Your permissions for {channel_mention} have been revoked.",
    }

    if action is ActionType.EDIT:
        if details.additional_info and "tag_updates" in details.additional_info:
            updates = details.additional_info["tag_updates"]
            if isinstance(updates, list):
                verbs = [
                    f"{item.get('Action', 'Modifi')}ed tag `{item.get('Tag', '?')}`"
                    for item in updates
                    if isinstance(item, dict)
                ]
                if verbs:
                    return f"Tags have been modified in {channel_mention}: {', '.join(verbs)}."
        return f"Changes have been made to {channel_mention}."

    message = base_messages.get(
        action,
        f"An action ({action.name.lower()}) has been performed in {channel_mention}.",
    )
    if action not in {
        ActionType.BAN,
        ActionType.UNBAN,
        ActionType.SHARE_PERMISSIONS,
        ActionType.REVOKE_PERMISSIONS,
    }:
        message += f" Reason: {details.reason}"
    return message


async def send_to_channel(channel_id: int, embed: hikari.Embed) -> None:
    try:
        channel = await plugin.client.rest.fetch_channel(channel_id)
        if not isinstance(channel, hikari.GuildTextChannel):
            return
        await plugin.client.rest.create_message(channel_id, embed=embed)
    except Exception:
        logger.exception("Failed to send message to channel %s", channel_id)


async def send_to_forum_post(forum_id: int, post_id: int, embed: hikari.Embed) -> None:
    try:
        forum = await plugin.client.rest.fetch_channel(forum_id)
        thread = await plugin.client.rest.fetch_channel(post_id)
        if not isinstance(forum, hikari.GuildForumChannel):
            return
        if not isinstance(thread, hikari.GuildThreadChannel):
            return
        if thread.is_archived:
            await plugin.client.rest.edit_channel(thread.id, archived=False)
        await plugin.client.rest.create_message(thread.id, embed=embed)
    except Exception:
        logger.exception(
            "Failed to send message to forum=%s post=%s",
            forum_id,
            post_id,
        )


async def send_error(
    ctx: arc.GatewayContext | miru.ViewContext | None,
    message: str,
    title: str = "Error",
    log_to_channel: bool = False,
    ephemeral: bool = True,
) -> None:
    await reply_err(plugin.client, ctx, message, ephemeral=ephemeral)
    if not log_to_channel:
        return
    embed = await reply_embed(plugin.client, title, message, Color.ERROR)
    log_channel_id, log_post_id, log_forum_id = get_log_channels()
    await send_to_channel(log_channel_id, embed)
    await send_to_forum_post(log_forum_id, log_post_id, embed)


async def send_success(
    ctx: arc.GatewayContext | miru.ViewContext | None,
    message: str,
    title: str = "Success",
    log_to_channel: bool = False,
    ephemeral: bool = True,
) -> None:
    await reply_ok(plugin.client, ctx, message, title=title, ephemeral=ephemeral)
    if not log_to_channel:
        return
    embed = await reply_embed(plugin.client, title, message, Color.INFO)
    _, log_post_id, log_forum_id = get_log_channels()
    await send_to_forum_post(log_forum_id, log_post_id, embed)


async def send_dm(
    target: hikari.User | hikari.Member | hikari.OwnUser,
    embed: hikari.Embed,
    components: Sequence[hikari.api.ComponentBuilder] | None = None,
) -> None:
    try:
        dm_channel = await plugin.client.rest.create_dm_channel(target.id)
        await plugin.client.rest.create_message(
            dm_channel.id,
            embed=embed,
            components=components or hikari.UNDEFINED,
        )
    except Exception:
        logger.exception("Failed to send DM to user %s", target.id)


async def log_action_internal(details: ActionDetails) -> None:
    timestamp = int(datetime.now(UTC).timestamp())
    action_name = details.action.name.capitalize()

    fields: list[tuple[str, str, bool]] = [
        ("Actor", details.actor.mention if details.actor else "Unknown", True),
        ("Thread", details.channel.mention if details.channel else "Unknown", True),
        ("Time", f"<t:{timestamp}:F> (<t:{timestamp}:R>)", True),
        ("Result", details.result.capitalize(), True),
        ("Reason", details.reason, False),
    ]

    if details.target:
        fields.insert(3, ("Target", details.target.mention, True))
    if details.additional_info:
        fields.append(
            ("Additional Info", format_additional_info(details.additional_info), False),
        )

    embeds: list[hikari.Embed] = []
    current_embed = await reply_embed(
        plugin.client,
        title=f"Action Log: {action_name}",
        color=Color(get_action_color(details.action)),
    )

    for name, value, inline in fields:
        chunks = [value[i : i + 1024] for i in range(0, len(value), 1024)] or ["-"]
        for index, chunk in enumerate(chunks, start=1):
            field_name = name
            if len(chunks) > 1:
                field_name = f"{name} (Part {index}/{len(chunks)})"

            total_field_size = sum(len(str(item.value)) for item in current_embed.fields)
            if len(current_embed.fields) >= 25 or (total_field_size + len(chunk)) > 6000:
                embeds.append(current_embed)
                current_embed = await reply_embed(
                    plugin.client,
                    title=f"Action Log: {action_name} (Continued)",
                    color=Color(get_action_color(details.action)),
                )
            current_embed.add_field(name=field_name, value=chunk, inline=inline)

    embeds.append(current_embed)

    global last_log_key
    log_key = f"{details.action.name}:{details.post_name}:{timestamp}"
    if last_log_key == log_key:
        return
    last_log_key = log_key

    for embed in embeds:
        await send_to_forum_post(LOG_FORUM_ID, LOG_POST_ID, embed)
        await send_to_channel(LOG_CHANNEL_ID, embed)

    if details.target and not details.target.is_bot:
        dm_embed = await reply_embed(
            plugin.client,
            title=f"{action_name} Notification",
            description=get_notification_message(details),
            color=Color(get_action_color(details.action)),
        )
        components = (
            [
                plugin.client.rest.build_message_action_row().add_link_button(
                    "https://example.com/appeal",
                    label="Appeal",
                ),
            ]
            if details.action is ActionType.LOCK
            else None
        )
        if details.action in {
            ActionType.CHECK,
            ActionType.LOCK,
            ActionType.UNLOCK,
            ActionType.DELETE,
            ActionType.BAN,
            ActionType.UNBAN,
            ActionType.SHARE_PERMISSIONS,
            ActionType.REVOKE_PERMISSIONS,
        }:
            await send_dm(details.target, dm_embed, components)


def calculate_levenshtein_similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    if len(left) < len(right):
        left, right = right, left

    len_right = len(right)
    previous = list(range(len_right + 1))
    current = [0] * (len_right + 1)

    for i, char_left in enumerate(left):
        current[0] = i + 1
        for j, char_right in enumerate(right):
            current[j + 1] = min(
                previous[j + 1] + 1,
                current[j] + 1,
                previous[j] + (char_left != char_right),
            )
        previous, current = current, previous

    return 1.0 - (previous[-1] / max(len(left), len_right))


def _normalize_message_text(content: str) -> str:
    normalized = URL_PATTERN.sub(" <url> ", content.lower())
    normalized = MENTION_PATTERN.sub(" <mention> ", normalized)
    normalized = EMOJI_PATTERN.sub(" <emoji> ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _tokenize_for_similarity(content: str) -> set[str]:
    return {match.group(0) for match in TOKEN_PATTERN.finditer(content)}


def _jaccard_similarity(tokens_a: set[str], tokens_b: set[str]) -> float:
    if not tokens_a and not tokens_b:
        return 1.0
    union = tokens_a | tokens_b
    if not union:
        return 0.0
    return len(tokens_a & tokens_b) / len(union)


def _char_ngram_jaccard(left: str, right: str, n: int = 3) -> float:
    if not left and not right:
        return 1.0
    if len(left) < n or len(right) < n:
        return calculate_levenshtein_similarity(left, right)
    ngrams_left = {left[i : i + n] for i in range(len(left) - n + 1)}
    ngrams_right = {right[i : i + n] for i in range(len(right) - n + 1)}
    return _jaccard_similarity(ngrams_left, ngrams_right)


def _is_structured_text(content: str) -> bool:
    if "```" in content:
        return True
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if len(lines) < 3:
        return False
    structured = sum(1 for line in lines if line.startswith(("-", "*", ">")) or bool(re.match(r"^\d+[.)]\s+", line)))
    return structured / len(lines) >= 0.5


def _internal_repetition_score(content: str) -> float:
    stripped = content.strip()
    if len(stripped) < 8:
        return 0.0

    score = 0.0
    if INTERNAL_REPEAT_PATTERN.search(stripped):
        score += 0.65

    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    if len(lines) >= 3:
        unique_lines = len(set(lines))
        duplicate_line_ratio = 1 - (unique_lines / len(lines))
        if duplicate_line_ratio > 0.6:
            score += min(0.4, duplicate_line_ratio)

    filtered = re.sub(r"\s+", "", stripped)
    if filtered:
        charset = len(set(filtered))
        entropy_ratio = charset / len(filtered)
        if entropy_ratio < 0.22:
            score += 0.45

    if _is_structured_text(stripped):
        score *= 0.5

    return min(score, 1.2)


def _get_similarity_threshold(length: int) -> float:
    if length <= 16:
        return model.spam_thresholds.similarity_thresholds.get("short", 0.90)
    if length <= 120:
        return model.spam_thresholds.similarity_thresholds.get("medium", 0.84)
    return model.spam_thresholds.similarity_thresholds.get("long", 0.78)


async def check_message_similarity(
    new_text: str,
    old_text: str | None,
) -> tuple[bool, dict[str, float]]:
    if old_text is None:
        return (False, {})
    left = _normalize_message_text(new_text)
    right = _normalize_message_text(old_text)
    if not left or not right:
        return (False, {})

    length = max(len(left), len(right))
    levenshtein = calculate_levenshtein_similarity(left, right)
    token_jaccard = _jaccard_similarity(
        _tokenize_for_similarity(left),
        _tokenize_for_similarity(right),
    )
    sequence = difflib.SequenceMatcher(None, left, right).ratio()
    trigram = _char_ngram_jaccard(left, right, 3)

    if length <= 16:
        combined = max(sequence, token_jaccard, levenshtein)
    elif length <= 120:
        combined = (0.35 * levenshtein) + (0.35 * token_jaccard) + (0.30 * sequence)
    else:
        combined = (0.30 * levenshtein) + (0.30 * token_jaccard) + (0.40 * trigram)

    threshold = _get_similarity_threshold(length)
    similarities = {
        "combined": combined,
        "threshold": threshold,
        "levenshtein": levenshtein,
        "token_jaccard": token_jaccard,
        "sequence": sequence,
        "trigram": trigram,
    }
    return (combined >= threshold, similarities)


def _cleanup_spam_history(now: datetime) -> None:
    cutoff = now - timedelta(seconds=model.spam_thresholds.history_window)
    hit_cutoff = now - timedelta(seconds=model.spam_thresholds.similarity_hit_window)
    stale_bucket_seconds = max(model.spam_thresholds.history_window * 4, 120)
    now_ts = now.timestamp()
    for history in model.spam.message_history.values():
        while history and history[0] <= cutoff:
            history.popleft()
    for history in model.spam.content_history.values():
        while history and history[0].timestamp <= cutoff:
            history.popleft()
    for history in model.spam.guild_wide_history.values():
        while history and history[0].timestamp <= cutoff:
            history.popleft()
    for history in model.spam.similarity_hits.values():
        while history and history[0] <= hit_cutoff:
            history.popleft()
    stale_bucket_keys = [
        key for key, (_, last_refill) in model.spam.rate_buckets.items() if now_ts - last_refill > stale_bucket_seconds
    ]
    for key in stale_bucket_keys:
        del model.spam.rate_buckets[key]


def _count_recent_messages(
    history: deque[datetime],
    now: datetime,
    window_seconds: int,
) -> int:
    if not history:
        return 0
    cutoff = now - timedelta(seconds=window_seconds)
    return sum(1 for stamp in history if stamp >= cutoff)


def _consume_token_bucket(
    key: str,
    now_ts: float,
    cost: float,
    capacity: float,
    refill_per_sec: float,
) -> tuple[bool, float]:
    tokens, last_refill = model.spam.rate_buckets[key]
    if last_refill <= 0:
        tokens = capacity
        last_refill = now_ts

    elapsed = max(0.0, now_ts - last_refill)
    tokens = min(capacity, tokens + (elapsed * refill_per_sec))
    if tokens < cost:
        wait_seconds = (cost - tokens) / refill_per_sec if refill_per_sec > 0 else 1.0
        model.spam.rate_buckets[key] = (tokens, now_ts)
        return (False, wait_seconds)

    tokens -= cost
    model.spam.rate_buckets[key] = (tokens, now_ts)
    return (True, 0.0)


def _record_similarity_hit(key: str, now: datetime) -> int:
    hit_history = model.spam.similarity_hits[key]
    cutoff = now - timedelta(seconds=model.spam_thresholds.similarity_hit_window)
    while hit_history and hit_history[0] <= cutoff:
        hit_history.popleft()
    hit_history.append(now)
    return len(hit_history)


def _count_mentions(message: hikari.Message) -> int:
    return (
        len(message.user_mentions or ())
        + len(message.role_mention_ids or ())
        + len(message.channel_mentions or ())
        + (1 if message.mentions_everyone else 0)
    )


async def check_message_spam(
    message: hikari.Message,
) -> tuple[str, dict[str, Any]] | None:
    if message.author is None:
        return None

    user_id = str(message.author.id)
    channel_id = str(message.channel_id)
    guild_id = str(message.guild_id) if message.guild_id else None

    now = datetime.now(UTC)
    _cleanup_spam_history(now)

    channel_key = f"{user_id}:{channel_id}"
    global_key = user_id
    now_ts = now.timestamp()

    channel_times = model.spam.message_history[channel_key]
    global_times = model.spam.message_history[global_key]

    channel_times.append(now)
    global_times.append(now)

    content = (message.content or "").strip()
    mention_count = _count_mentions(message)
    emoji_count = sum(1 for _ in EMOJI_PATTERN.finditer(content))
    url_count = len(URL_PATTERN.findall(content))
    attachment_count = len(message.attachments or ())

    message_cost = (
        1.0 + (0.25 * url_count) + (0.2 * mention_count) + (0.3 * attachment_count) + (0.12 * max(0, emoji_count - 3))
    )

    channel_rapid = _count_recent_messages(
        channel_times,
        now,
        model.spam_thresholds.rapid_window_seconds,
    )
    channel_burst = _count_recent_messages(
        channel_times,
        now,
        model.spam_thresholds.burst_window_seconds,
    )
    global_rapid = _count_recent_messages(
        global_times,
        now,
        model.spam_thresholds.rapid_window_seconds,
    )
    global_burst = _count_recent_messages(
        global_times,
        now,
        model.spam_thresholds.burst_window_seconds,
    )

    rate_score = 0.0
    channel_rapid_limit = max(
        model.spam_thresholds.rapid_message_limit,
        model.spam_thresholds.rate_limit - 1,
    )
    if channel_rapid >= channel_rapid_limit:
        rate_score += 0.45
    if channel_burst >= model.spam_thresholds.burst_message_limit:
        rate_score += 0.35
    if global_rapid >= model.spam_thresholds.global_rate_limit:
        rate_score += 0.30
    if global_burst >= model.spam_thresholds.global_rate_limit * 2:
        rate_score += 0.25

    channel_bucket_ok, channel_wait = _consume_token_bucket(
        f"chan:{channel_key}",
        now_ts,
        message_cost,
        model.spam_thresholds.channel_bucket_capacity,
        model.spam_thresholds.channel_bucket_refill_per_sec,
    )
    global_bucket_ok, global_wait = _consume_token_bucket(
        f"guild:{global_key}",
        now_ts,
        message_cost,
        model.spam_thresholds.global_bucket_capacity,
        model.spam_thresholds.global_bucket_refill_per_sec,
    )
    if not channel_bucket_ok:
        rate_score += 0.70
    if not global_bucket_ok:
        rate_score += 0.55

    repetition_score = _internal_repetition_score(content)

    similarity_score = 0.0
    similarity_hits = 0
    matched_scope: str | None = None
    matched_record: MessageRecord | None = None
    best_scores: dict[str, float] = {}

    channel_history = model.spam.content_history[channel_key]
    for record in reversed(channel_history):
        similar, scores = await check_message_similarity(content, record.content)
        if similar:
            best_scores = scores
            similarity_score = max(
                similarity_score,
                min(scores.get("combined", 0.0), 1.0),
            )
            similarity_hits = max(
                similarity_hits,
                _record_similarity_hit(f"{channel_key}:similar", now),
            )
            matched_scope = "channel"
            matched_record = record
            break

    if guild_id:
        guild_history = model.spam.guild_wide_history[f"{user_id}:{guild_id}"]
        for record in reversed(guild_history):
            if record.channel_id == channel_id:
                continue
            similar, scores = await check_message_similarity(content, record.content)
            if similar:
                best_scores = scores
                similarity_score = max(
                    similarity_score,
                    min(scores.get("combined", 0.0), 1.0),
                )
                similarity_hits = max(
                    similarity_hits,
                    _record_similarity_hit(f"{user_id}:{guild_id}:cross-similar", now),
                )
                matched_scope = "guild"
                matched_record = record
                break

    if mention_count > model.spam_thresholds.max_mentions and message.guild_id:
        guild = await plugin.client.rest.fetch_guild(message.guild_id)
        member = guild.get_member(message.author.id)
        if member:
            roles = {role.id for role in member.get_roles()}
            if not (roles & model.spam_thresholds.exempt_roles):
                return (
                    (
                        f"The message mentioned {mention_count} users/roles, which exceeds our limit "
                        f"of {model.spam_thresholds.max_mentions}. This helps keep discussions focused "
                        "and prevents spam. Please reduce the number of mentions and try again."
                    ),
                    {"mention_count": mention_count},
                )

    if emoji_count > model.spam_thresholds.max_emojis:
        return (
            (
                f"The message contains {emoji_count} emojis, which exceeds our limit of "
                f"{model.spam_thresholds.max_emojis}. While emojis can be fun, too many can make "
                "messages hard to read. Please reduce the number of emojis and try again."
            ),
            {"emoji_count": emoji_count},
        )

    mention_pressure = mention_count / max(1, model.spam_thresholds.max_mentions) if mention_count > 0 else 0.0
    emoji_pressure = max(0.0, (emoji_count - 3) * 0.08)
    risk_score = rate_score + similarity_score + repetition_score + mention_pressure + emoji_pressure

    if similarity_hits >= model.spam_thresholds.similarity_hit_limit:
        compared_with = matched_record.content if matched_record else None
        return (
            (
                "This message is too similar to your recent messages. "
                "Please avoid reposting the same or slightly modified content."
            ),
            {
                "similarity_scores": best_scores,
                "similarity_hits": similarity_hits,
                "matched_scope": matched_scope,
                "compared_with": compared_with,
            },
        )

    if rate_score >= 1.0 and (repetition_score >= 0.8 or similarity_hits >= 1):
        wait_seconds = max(channel_wait, global_wait)
        return (
            (
                "You're sending highly repetitive messages too quickly. "
                f"Please slow down for about {max(wait_seconds, 1.0):.1f}s and avoid repeated content."
            ),
            {
                "rate_score": rate_score,
                "repetition_score": repetition_score,
                "similarity_hits": similarity_hits,
                "channel_rapid": channel_rapid,
                "channel_burst": channel_burst,
                "global_rapid": global_rapid,
            },
        )

    if repetition_score >= 1.0 and rate_score >= 0.5:
        return (
            "The message appears to contain repeated segments that look like spam. Please simplify and resend.",
            {
                "internal_repetition": True,
                "repetition_score": repetition_score,
            },
        )

    if risk_score >= 1.85:
        wait_seconds = max(channel_wait, global_wait)
        return (
            (
                "This message pattern looks like spam (rate + similarity + repetition). "
                f"Please wait {max(wait_seconds, 1.0):.1f}s and try a cleaner message."
            ),
            {
                "risk_score": risk_score,
                "rate_score": rate_score,
                "similarity_score": similarity_score,
                "repetition_score": repetition_score,
            },
        )

    msg_record = MessageRecord(timestamp=now, content=content, channel_id=channel_id)
    channel_history.append(msg_record)
    if guild_id:
        model.spam.guild_wide_history[f"{user_id}:{guild_id}"].append(msg_record)

    return None


def _is_allowed_parent(parent_id: int | None) -> bool:
    return parent_id in ALLOWED_CHANNELS


async def validate_channel(ctx: arc.GatewayContext | miru.ViewContext) -> bool:
    channel = await plugin.client.rest.fetch_channel(ctx.channel_id)
    if isinstance(channel, hikari.GuildThreadChannel):
        return _is_allowed_parent(channel.parent_id)
    if isinstance(channel, hikari.GuildForumChannel):
        return channel.id in ALLOWED_CHANNELS
    return False


async def can_manage_post(
    thread: hikari.GuildThreadChannel,
    user: hikari.Member | hikari.User,
) -> bool:
    guild = await plugin.client.rest.fetch_guild(GUILD_ID)
    member = guild.get_member(user.id)
    if member is None:
        with contextlib.suppress(hikari.NotFoundError):
            member = await plugin.client.rest.fetch_member(GUILD_ID, user.id)
    if member is None:
        return False

    roles = {role.id for role in member.get_roles()}

    if thread.parent_id == CONGRESS_FORUM_ID:
        return bool(roles & {CONGRESS_MOD_ROLE, CONGRESS_MEMBER_ROLE})

    if thread.owner_id == user.id:
        return True

    if model.has_thread_permissions(str(thread.id), str(user.id)):
        return True

    return any(
        role_id in roles and thread.parent_id in channels for role_id, channels in ROLE_CHANNEL_PERMISSIONS.items()
    )


async def can_manage_post_from_ctx(ctx: arc.GatewayContext) -> bool:
    channel = await plugin.client.rest.fetch_channel(ctx.channel_id)
    if not isinstance(channel, hikari.GuildThreadChannel):
        return False
    return await can_manage_post(channel, ctx.author)


async def can_manage_message(
    thread: hikari.GuildThreadChannel,
    user: hikari.Member | hikari.User,
) -> bool:
    return await can_manage_post(thread, user)


async def is_user_banned_cached(channel_id: str, post_id: str, author_id: str) -> bool:
    return await asyncio.to_thread(model.is_user_banned, channel_id, post_id, author_id)


class MessageActionSelect(miru.TextSelect):
    def __init__(self, message: hikari.Message) -> None:
        options = [
            miru.SelectOption(
                label="Delete Message",
                value="delete",
                description="Delete this message",
            ),
            miru.SelectOption(
                label="Unpin Message" if message.is_pinned else "Pin Message",
                value="unpin" if message.is_pinned else "pin",
                description="Unpin this message" if message.is_pinned else "Pin this message",
            ),
        ]
        super().__init__(
            options=options,
            placeholder="Select action for message",
            min_values=1,
            max_values=1,
        )
        self._message = message

    async def callback(self, ctx: miru.ViewContext) -> None:
        choice = self.values[0].lower() if self.values else ""
        details: ActionDetails | None = None
        message = self._message
        view = self.view
        if not isinstance(view, MessageActionView):
            await send_error(ctx, "Failed to detect valid view type.")
            return
        if message is None:
            await send_error(ctx, "Failed to locate message.")
            return
        if choice == "delete":
            details = await delete_message_action(ctx, view.channel, message)
        elif choice == "pin":
            details = await pin_message_action(ctx, view.channel, message, True)
        elif choice == "unpin":
            details = await pin_message_action(ctx, view.channel, message, False)
        else:
            await send_error(ctx, "Failed to process selected action.")

        if details is not None:
            await log_action_internal(details)
        view.stop()


class MessageActionView(miru.View):
    def __init__(
        self,
        message: hikari.Message,
        channel: hikari.GuildThreadChannel,
    ) -> None:
        super().__init__(timeout=300)
        self._message = message
        self._channel = channel
        self.add_item(MessageActionSelect(message))

    @property
    def message(self) -> hikari.Message | None:
        return self._message

    @property
    def channel(self) -> hikari.GuildThreadChannel:
        return self._channel


class ManageUserSelect(miru.TextSelect):
    def __init__(
        self,
        target_user: hikari.User,
        is_banned: bool,
        has_permissions: bool,
    ) -> None:
        options = [
            miru.SelectOption(
                label="Unban User" if is_banned else "Ban User",
                value="unban" if is_banned else "ban",
                description="Currently banned" if is_banned else "Currently not banned",
            ),
            miru.SelectOption(
                label="Revoke Permissions" if has_permissions else "Share Permissions",
                value="revoke_permissions" if has_permissions else "share_permissions",
                description="Currently shared" if has_permissions else "Currently not shared",
            ),
        ]
        super().__init__(
            options=options,
            placeholder="Select action for user",
            min_values=1,
            max_values=1,
        )
        self._target_user = target_user

    async def callback(self, ctx: miru.ViewContext) -> None:
        choice = self.values[0].lower() if self.values else ""
        action_map = {
            "ban": ActionType.BAN,
            "unban": ActionType.UNBAN,
            "share_permissions": ActionType.SHARE_PERMISSIONS,
            "revoke_permissions": ActionType.REVOKE_PERMISSIONS,
        }
        action = action_map.get(choice)
        if action is None:
            await send_error(ctx, "Failed to process selected action.")
            self.view.stop()
            return

        try:
            member = await plugin.client.rest.fetch_member(
                GUILD_ID,
                self._target_user.id,
            )
        except hikari.NotFoundError:
            await send_error(ctx, "Failed to locate user in server.")
            self.view.stop()
            return

        details: ActionDetails | None = None
        if action in {ActionType.BAN, ActionType.UNBAN}:
            details = await ban_unban_user(ctx, member, action)
        elif action in {ActionType.SHARE_PERMISSIONS, ActionType.REVOKE_PERMISSIONS}:
            details = await share_revoke_permissions(ctx, member, action)

        if details is not None:
            await log_action_internal(details)

        self.view.stop()


class ManageUserView(miru.View):
    def __init__(
        self,
        target_user: hikari.User,
        thread: hikari.GuildThreadChannel,
        is_banned: bool,
        has_permissions: bool,
    ) -> None:
        super().__init__(timeout=300)
        self._target_user = target_user
        self._thread = thread
        self._is_banned = is_banned
        self._has_permissions = has_permissions
        self.add_item(ManageUserSelect(target_user, is_banned, has_permissions))

    @property
    def target_user(self) -> hikari.User:
        return self._target_user

    @property
    def thread(self) -> hikari.GuildThreadChannel:
        return self._thread


@plugin.include
@arc.message_command(name="Message in Thread")
async def message_actions(ctx: arc.GatewayContext, message: hikari.Message) -> None:
    channel = await plugin.client.rest.fetch_channel(ctx.channel_id)
    if not isinstance(channel, hikari.GuildThreadChannel):
        await send_error(ctx, "Failed to execute command in thread channels only.")
        return

    if not await can_manage_message(channel, ctx.author):
        await send_error(ctx, "Failed to access message actions for this message.")
        return

    view = MessageActionView(message, channel)

    embed = await reply_embed(
        plugin.client,
        "Managing message",
        "Selecting action to perform on this message.",
    )
    response_obj = await ctx.respond(embed=embed, components=view)
    await bind_view_to_response(
        response_obj=response_obj,
        miru_client=get_miru(),
        view=view,
    )


async def delete_message_action(
    ctx: arc.GatewayContext | miru.ViewContext,
    post: hikari.GuildForumChannel | hikari.GuildThreadChannel,
    message: hikari.Message,
) -> ActionDetails | None:
    try:
        await plugin.client.rest.delete_message(message.channel_id, message.id)
    except hikari.NotFoundError:
        await send_error(ctx, "Failed to delete message.")
        return None
    except Exception:
        logger.exception("Failed to delete message %s", message.id)
        await send_error(ctx, "Failed to delete message.")
        return None

    post_name = post.name or str(post.id)
    await send_success(ctx, f"Deleting message from thread `{post_name}`.")
    return ActionDetails(
        action=ActionType.DELETE,
        reason=f"User-initiated message deletion by {ctx.author.mention}",
        post_name=post_name,
        actor=ctx.author,
        target=message.author,
        channel=post,
        additional_info={
            "deleted_message_id": str(message.id),
            "deleted_message_content": (message.content or "")[:1000] or "N/A",
            "deleted_message_attachments": [a.url for a in message.attachments],
        },
    )


async def pin_message_action(
    ctx: arc.GatewayContext | miru.ViewContext,
    post: hikari.GuildForumChannel | hikari.GuildThreadChannel,
    message: hikari.Message,
    pin: bool,
) -> ActionDetails | None:
    try:
        if pin:
            await plugin.client.rest.pin_message(message.channel_id, message.id)
            action = ActionType.PIN
            action_desc = "pinned"
        else:
            await plugin.client.rest.unpin_message(message.channel_id, message.id)
            action = ActionType.UNPIN
            action_desc = "unpinned"
    except Exception:
        logger.exception("Failed to change pin status for message %s", message.id)
        await send_error(ctx, "Failed to update message pin status.")
        return None

    await send_success(ctx, f"{action_desc.title()} message.")

    post_name = post.name or str(post.id)
    return ActionDetails(
        action=action,
        reason=f"User-initiated message {action_desc} by {ctx.author.mention}",
        post_name=post_name,
        actor=ctx.author,
        target=message.author,
        channel=post,
        additional_info={
            f"{action_desc}_message_id": str(message.id),
            f"{action_desc}_message_content": (message.content or "")[:1000] or "N/A",
        },
    )


@plugin.include
@arc.user_command(name="User in Thread")
async def manage_user_in_forum_post(
    ctx: arc.GatewayContext,
    target: hikari.User,
) -> None:
    if not await validate_channel(ctx):
        await send_error(ctx, "Failed to execute command in specific forum threads.")
        return

    channel = await plugin.client.rest.fetch_channel(ctx.channel_id)
    if not isinstance(channel, hikari.GuildThreadChannel):
        await send_error(ctx, "Failed to execute command in thread channels only.")
        return

    bot_user = plugin.client.app.get_me()
    if bot_user and bot_user.id == target.id:
        await send_error(ctx, "Failed to manage bot permissions or status in threads.")
        return

    guild = await plugin.client.rest.fetch_guild(GUILD_ID)
    author_member = guild.get_member(ctx.author.id)
    author_roles = {role.id for role in author_member.get_roles()} if author_member else set()

    if target.id == ctx.author.id and CONGRESS_MEMBER_ROLE not in author_roles:
        await send_error(
            ctx,
            f"Failed to manage own status in threads. Only members with <@&{CONGRESS_MEMBER_ROLE}> can manage own status.",
        )
        return

    if not await can_manage_post(channel, ctx.author):
        await send_error(ctx, "Failed to manage users in this thread.")
        return

    channel_id = str(channel.parent_id or channel.id)
    thread_id = str(channel.id)
    user_id = str(target.id)

    is_banned = await is_user_banned_cached(channel_id, thread_id, user_id)
    has_permissions = model.has_thread_permissions(thread_id, user_id)

    view = ManageUserView(target, channel, is_banned, has_permissions)

    embed = await reply_embed(
        plugin.client,
        "User in Thread",
        (
            f"Select action for {target.mention}:\n"
            f"Current status: {'Banned' if is_banned else 'Not banned'}.\n"
            f"Permissions: {'Shared' if has_permissions else 'Not shared'}."
        ),
    )
    response_obj = await ctx.respond(embed=embed, components=view)
    await bind_view_to_response(
        response_obj=response_obj,
        miru_client=get_miru(),
        view=view,
    )


async def share_revoke_permissions(
    ctx: arc.GatewayContext | miru.ViewContext,
    member: hikari.Member,
    action: ActionType,
) -> ActionDetails | None:
    if not await validate_channel(ctx):
        await send_error(ctx, "This command can only be used in threads.")
        return None

    channel = await plugin.client.rest.fetch_channel(ctx.channel_id)
    if not isinstance(channel, hikari.GuildThreadChannel):
        await send_error(ctx, "Failed to execute command in thread channels only.")
        return None

    guild = await plugin.client.rest.fetch_guild(GUILD_ID)
    author_member = guild.get_member(ctx.author.id)
    author_roles = {role.id for role in author_member.get_roles()} if author_member else set()

    if channel.parent_id != CONGRESS_FORUM_ID and channel.owner_id != ctx.author.id:
        await send_error(ctx, "Only thread owner can manage thread permissions.")
        return None

    if channel.parent_id == CONGRESS_FORUM_ID:
        if CONGRESS_MEMBER_ROLE in author_roles:
            await send_error(
                ctx,
                f"Members with <@&{CONGRESS_MEMBER_ROLE}> cannot manage thread permissions.",
            )
            return None
        if CONGRESS_MOD_ROLE not in author_roles:
            await send_error(
                ctx,
                f"You need to be <@&{CONGRESS_MOD_ROLE}> to manage thread permissions in this forum.",
            )
            return None
    elif not await can_manage_post(channel, ctx.author):
        await send_error(ctx, f"Failed to manage {action.name.lower()} permissions.")
        return None

    thread_id = str(channel.id)
    user_id = str(member.id)

    if action is ActionType.SHARE_PERMISSIONS:
        model.thread_permissions[thread_id].add(user_id)
        action_name = "shared"
    elif action is ActionType.REVOKE_PERMISSIONS:
        model.thread_permissions[thread_id].discard(user_id)
        if not model.thread_permissions[thread_id]:
            model.thread_permissions.pop(thread_id, None)
        action_name = "revoked"
    else:
        await send_error(ctx, "Failed to process invalid action type.")
        return None

    await model.save_thread_permissions(THREAD_PERMISSIONS_FILE)

    await send_success(
        ctx,
        f"{action_name.capitalize()} permissions for {member.mention}.",
    )

    return ActionDetails(
        action=action,
        reason=f"Permissions {action_name} by {ctx.author.mention}",
        post_name=channel.name or str(channel.id),
        actor=ctx.author,
        target=member,
        channel=channel,
        additional_info={
            "action_type": f"{action_name.capitalize()} permissions",
            "affected_user": str(member),
            "affected_user_id": member.id,
        },
    )


async def ban_unban_user(
    ctx: arc.GatewayContext | miru.ViewContext,
    member: hikari.Member,
    action: ActionType,
) -> ActionDetails | None:
    if not await validate_channel(ctx):
        await send_error(ctx, "This command can only be used in threads.")
        return None

    channel = await plugin.client.rest.fetch_channel(ctx.channel_id)
    if not isinstance(channel, hikari.GuildThreadChannel):
        await send_error(ctx, "Failed to execute command in thread channels only.")
        return None

    guild = await plugin.client.rest.fetch_guild(GUILD_ID)
    author_member = guild.get_member(ctx.author.id)
    target_member = guild.get_member(member.id)

    author_roles = {role.id for role in author_member.get_roles()} if author_member else set()
    target_roles = {role.id for role in target_member.get_roles()} if target_member else set()

    if any(
        role_id in target_roles and channel.parent_id in channels
        for role_id, channels in ROLE_CHANNEL_PERMISSIONS.items()
    ):
        await send_error(ctx, "Failed to ban users with management permissions.")
        return None

    if channel.parent_id == CONGRESS_FORUM_ID:
        if CONGRESS_MEMBER_ROLE in author_roles:
            if action is ActionType.BAN or (action is ActionType.UNBAN and member.id != ctx.author.id):
                await send_error(
                    ctx,
                    f"Failed to unban - only <@&{CONGRESS_MEMBER_ROLE}> can unban themselves.",
                )
                return None
        elif CONGRESS_MOD_ROLE not in author_roles:
            await send_error(
                ctx,
                f"Failed to ban - need <@&{CONGRESS_MOD_ROLE}> to manage bans in this forum.",
            )
            return None
    elif not await can_manage_post(channel, ctx.author):
        await send_error(
            ctx,
            f"Failed to {action.name.lower()} users from threads you manage.",
        )
        return None

    if member.id == channel.owner_id:
        await send_error(ctx, "Failed to ban thread owners from their own threads.")
        return None

    channel_id = str(channel.parent_id or channel.id)
    thread_id = str(channel.id)
    user_id = str(member.id)

    async with ban_lock:
        post_users = model.banned_users[channel_id][thread_id]
        if action is ActionType.BAN:
            post_users.add(user_id)
            action_name = "banned"
        elif action is ActionType.UNBAN:
            post_users.discard(user_id)
            action_name = "unbanned"
        else:
            await send_error(ctx, "Failed to process invalid action.")
            return None

        if not post_users:
            model.banned_users[channel_id].pop(thread_id, None)
            if not model.banned_users[channel_id]:
                model.banned_users.pop(channel_id, None)

        await model.save_banned_users(BANNED_USERS_FILE)

    model.invalidate_ban_cache(channel_id, thread_id, user_id)

    await send_success(
        ctx,
        (
            f"{action_name.capitalize()} user. "
            + (
                "They will no longer be able to participate in this thread."
                if action is ActionType.BAN
                else "They can now participate in this thread again."
            )
        ),
    )

    return ActionDetails(
        action=action,
        reason=f"{action_name.capitalize()} by {ctx.author.mention}",
        post_name=channel.name or str(channel.id),
        actor=ctx.author,
        target=member,
        channel=channel,
        additional_info={
            "action_type": action_name.capitalize(),
            "affected_user": str(member),
            "affected_user_id": member.id,
        },
    )


@threads_group.include
@arc.slash_subcommand("list", "List information for current thread")
async def list_thread_info(
    ctx: arc.GatewayContext,
    list_type: str,
) -> None:
    if not await validate_channel(ctx):
        await send_error(ctx, "This command can only be used in threads.")
        return

    if not await can_manage_post_from_ctx(ctx):
        await send_error(ctx, "Failed to view information in this thread.")
        return

    await defer(ctx)

    channel = await plugin.client.rest.fetch_channel(ctx.channel_id)
    channel_id = str(
        channel.parent_id if isinstance(channel, hikari.GuildThreadChannel) else channel.id,
    )
    post_id = str(channel.id)

    if list_type == "banned":
        banned_users = model.banned_users[channel_id][post_id]
        if not banned_users:
            await send_success(ctx, "Found no banned users in this thread.")
            return

        embeds: list[hikari.Embed] = []
        current = await reply_embed(plugin.client, f"Banned Users in <#{post_id}>", "")
        for user_id in sorted(banned_users):
            user = None
            with contextlib.suppress(Exception):
                user = await plugin.client.rest.fetch_user(int(user_id))
            current.add_field(
                name="Banned User",
                value=f"- User: {user.mention if user else user_id}",
                inline=True,
            )
            if len(current.fields) >= 5:
                embeds.append(current)
                current = await reply_embed(
                    plugin.client,
                    f"Banned Users in <#{post_id}>",
                    "",
                )

        if current.fields:
            embeds.append(current)

        await send_paginated_response(
            ctx,
            embeds,
            "No banned users were found in this thread.",
        )
        return

    if list_type == "permissions":
        users = model.thread_permissions[post_id]
        if not users:
            await send_success(
                ctx,
                "Found no users with special permissions in this thread.",
            )
            return

        embeds = []
        current = await reply_embed(
            plugin.client,
            f"Users with Permissions in <#{post_id}>",
            "",
        )
        for user_id in sorted(users):
            user = None
            with contextlib.suppress(Exception):
                user = await plugin.client.rest.fetch_user(int(user_id))
            current.add_field(
                name="User with Permissions",
                value=f"- User: {user.mention if user else user_id}",
                inline=True,
            )
            if len(current.fields) >= 5:
                embeds.append(current)
                current = await reply_embed(
                    plugin.client,
                    f"Users with Permissions in <#{post_id}>",
                    "",
                )

        if current.fields:
            embeds.append(current)

        await send_paginated_response(
            ctx,
            embeds,
            "No users with special permissions were found in this thread.",
        )
        return

    await send_error(ctx, "Invalid list type.")


@threads_group.include
@arc.slash_subcommand("view", "View configuration files")
async def list_debug_info(
    ctx: arc.GatewayContext,
    view_type: str,
) -> None:
    guild = await plugin.client.rest.fetch_guild(GUILD_ID)
    author_member = guild.get_member(ctx.author.id)
    author_roles = {role.id for role in author_member.get_roles()} if author_member else set()

    if THREADS_ROLE_ID not in author_roles:
        await send_error(ctx, "Failed to use this command. You do not have permission.")
        return

    await defer(ctx)

    if view_type == "banned":
        banned_users = await _get_merged_banned_users()
        embeds = await _create_banned_user_embeds(banned_users)
        await send_paginated_response(ctx, embeds, "No banned users found.")
        return

    if view_type == "permissions":
        permissions = await _get_merged_permissions()
        grouped: defaultdict[str, set[str]] = defaultdict(set)
        for thread_id, user_id in permissions:
            grouped[thread_id].add(user_id)
        embeds = await _create_permission_embeds(grouped)
        await send_paginated_response(ctx, embeds, "No thread permissions found.")
        return

    await send_error(ctx, "Invalid view type.")


async def _get_merged_banned_users() -> set[tuple[str, str, str]]:
    await model.load_banned_users(BANNED_USERS_FILE)
    return {
        (channel_id, post_id, user_id)
        for channel_id, channel_data in model.banned_users.items()
        for post_id, users in channel_data.items()
        for user_id in users
    }


async def _get_merged_permissions() -> set[tuple[str, str]]:
    await model.load_thread_permissions(THREAD_PERMISSIONS_FILE)
    return {(thread_id, user_id) for thread_id, users in model.thread_permissions.items() for user_id in users}


async def _create_banned_user_embeds(
    banned_users: set[tuple[str, str, str]],
) -> list[hikari.Embed]:
    embeds: list[hikari.Embed] = []
    current = await reply_embed(plugin.client, "Banned Users List", "")

    for channel_id, post_id, user_id in sorted(banned_users):
        channel = None
        post = None
        user = None
        with contextlib.suppress(Exception):
            channel = await plugin.client.rest.fetch_channel(int(channel_id))
        with contextlib.suppress(Exception):
            post = await plugin.client.rest.fetch_channel(int(post_id))
        with contextlib.suppress(Exception):
            user = await plugin.client.rest.fetch_user(int(user_id))

        lines = [
            f"- Thread: {post.mention if post and hasattr(post, 'mention') else f'<#{post_id}>'}",
            f"- User: {user.mention if user else user_id}",
            f"- Channel: {channel.mention if channel and hasattr(channel, 'mention') else f'<#{channel_id}>'}",
        ]

        current.add_field(name="Ban Entry", value="\n".join(lines), inline=True)
        if len(current.fields) >= 5:
            embeds.append(current)
            current = await reply_embed(plugin.client, "Banned Users List", "")

    if current.fields:
        embeds.append(current)
    return embeds


async def _create_permission_embeds(
    permissions: defaultdict[str, set[str]],
) -> list[hikari.Embed]:
    embeds: list[hikari.Embed] = []
    current = await reply_embed(plugin.client, "Thread Permissions List", "")

    for post_id, user_ids in permissions.items():
        post = None
        with contextlib.suppress(Exception):
            post = await plugin.client.rest.fetch_channel(int(post_id))

        for user_id in sorted(user_ids):
            user = None
            with contextlib.suppress(Exception):
                user = await plugin.client.rest.fetch_user(int(user_id))
            thread_label = post.mention if post and hasattr(post, "mention") else f"<#{post_id}>"
            user_label = user.mention if user else user_id
            current.add_field(
                name="Permission Entry",
                value=f"- Thread: {thread_label}\n- User: {user_label}",
                inline=True,
            )
            if len(current.fields) >= 5:
                embeds.append(current)
                current = await reply_embed(
                    plugin.client,
                    "Thread Permissions List",
                    "",
                )

    if current.fields:
        embeds.append(current)
    return embeds


async def send_paginated_response(
    ctx: arc.GatewayContext,
    embeds: list[hikari.Embed],
    empty_message: str,
) -> None:
    if not embeds:
        await send_success(ctx, empty_message)
        return

    if len(embeds) == 1:
        await ctx.respond(embed=embeds[0])
        return

    first = embeds[0]
    first.set_footer(text=f"Page 1/{len(embeds)}")

    row = plugin.client.rest.build_message_action_row()
    row.add_interactive_button(hikari.ButtonStyle.PRIMARY, "page:next")
    row.add_interactive_button(hikari.ButtonStyle.PRIMARY, "page:last")
    await ctx.respond(embed=first, components=[row])


@plugin.listen(hikari.MessageCreateEvent)
async def on_message_create_for_moderation(event: hikari.MessageCreateEvent) -> None:
    message = event.message
    if message.author is None or message.author.is_bot or not isinstance(event.channel_id, int):
        return

    channel = await plugin.client.rest.fetch_channel(event.channel_id)
    if not isinstance(channel, (hikari.GuildChannel, hikari.GuildThreadChannel)):
        return

    user_id = str(message.author.id)
    now = datetime.now(UTC).timestamp()
    cooldown_key = f"{user_id}:{message.channel_id}"
    last_warning = model.spam.cooldowns.get(cooldown_key, 0.0)
    if now - last_warning < model.spam_thresholds.warning_cooldown:
        return

    try:
        spam_result = await check_message_spam(message)
    except Exception:
        logger.exception("Failed to detect spam for user=%s", user_id)
        return

    if spam_result is None:
        return

    warning, additional_info = spam_result
    model.spam.cooldowns[cooldown_key] = now

    backup = await reply_embed(
        plugin.client,
        "Backing up message",
        "Deleting message for rule violations - providing backup of content:",
    )

    content = message.content or "Containing no text"
    for index, chunk in enumerate(
        (content[i : i + 1024] for i in range(0, len(content), 1024)),
        start=1,
    ):
        backup.add_field(
            name=f"Message Content (Part {index})",
            value=chunk,
        )

    if message.attachments:
        backup.add_field(
            name="Attachment Links",
            value="\n".join(a.url for a in message.attachments),
        )

    with contextlib.suppress(Exception):
        dm_channel = await plugin.client.rest.create_dm_channel(message.author.id)
        await plugin.client.rest.create_message(dm_channel.id, embed=backup)

    with contextlib.suppress(hikari.NotFoundError):
        await plugin.client.rest.delete_message(message.channel_id, message.id)

    try:
        await log_action_internal(
            ActionDetails(
                action=ActionType.DELETE,
                reason=warning,
                post_name=channel.name if hasattr(channel, "name") and channel.name else str(channel.id),
                actor=await plugin.client.rest.fetch_my_user(),
                target=message.author,
                channel=channel,
                additional_info={
                    "original_content": message.content,
                    "attachments": [a.url for a in message.attachments],
                    **additional_info,
                },
            ),
        )
    except Exception:
        logger.exception("Failed to log moderation action")


def should_process_any_link(event: hikari.MessageCreateEvent) -> bool:
    message = event.message
    return bool(
        message.guild_id
        and message.guild_id == GUILD_ID
        and message.author
        and not message.author.is_bot
        and isinstance(event.channel_id, int)
        and message.content,
    )


def should_process_bilibili_link(event: hikari.MessageCreateEvent) -> bool:
    message = event.message
    if not message.guild_id or not message.author:
        return False
    guild = plugin.client.cache.get_guild(message.guild_id)
    member = guild.get_member(message.author.id) if guild else None
    if guild is None or member is None:
        return False
    return bool(
        guild.id == GUILD_ID
        and message.content
        and not any(role_id == TAIWAN_ROLE_ID for role_id in (member.role_ids or ())),
    )


def bilibili_link(content: str) -> str:
    def sanitize_url(
        url_str: str,
        preserve_params: frozenset[str] = frozenset({"p"}),
    ) -> str:
        url = URL(url_str)
        query_keys = frozenset(url.query.keys())
        return str(
            url.with_query(
                {key: url.query[key] for key in preserve_params & query_keys},
            ),
        )

    patterns: list[tuple[re.Pattern[str], Any]] = [
        (
            re.compile(
                r"https?://(?:www\.)?(?:b23\.tv|bilibili\.com/video/(?:BV\w+|av\d+))",
                flags=re.IGNORECASE,
            ),
            lambda url: sanitize_url(url) if "bilibili.com" in url.lower() else str(URL(url).with_host("b23.tf")),
        ),
    ]

    def replacer(match: re.Match[str]) -> str:
        source = str(match.group(0))
        for pattern, transform in patterns:
            if pattern.match(source):
                try:
                    return str(transform(source))
                except Exception:
                    return source
        return source

    return re.sub(r"https?://\S+", replacer, content, flags=re.IGNORECASE)


async def should_replace_link(original: str, cleaned: str, threshold: int = 2) -> bool:
    if not cleaned:
        return False
    length_diff = abs(len(original) - len(cleaned))
    original_lower = original.lower()
    cleaned_lower = cleaned.lower()
    return length_diff >= threshold and original_lower not in {
        cleaned_lower,
        unquote(cleaned).lower(),
    }


async def clean_query_params(
    query: str,
    provider: dict[str, Any],
) -> list[tuple[str, str]]:
    params = parse_qsl(query)
    rules = [*provider.get("rules", []), *provider.get("referralMarketing", [])]
    return [
        (key, value)
        for key, value in params
        if not any(re.match(rule, key, re.IGNORECASE) for rule in rules if isinstance(rule, str))
    ]


async def handle_redirections(
    url: str,
    provider: dict[str, Any],
    loop: bool,
) -> str | None:
    for redir in provider.get("redirections", []):
        if not isinstance(redir, str):
            continue
        try:
            match = re.match(redir, url, re.IGNORECASE | re.MULTILINE)
            if match:
                group = match.group(1)
                unquoted = unquote(group)
                return await clean_any_url(unquoted, model.rules, False) if loop else unquoted
        except Exception:
            continue
    return url


async def clean_any_url(
    url: str,
    rules: dict[str, Any],
    loop: bool = True,
) -> str | None:
    providers = rules.get("providers", {})
    if not isinstance(providers, dict):
        return url

    for provider in providers.values():
        if not isinstance(provider, dict):
            continue

        url_pattern = provider.get("urlPattern")
        if not isinstance(url_pattern, str):
            continue
        if not re.match(url_pattern, url, re.IGNORECASE):
            continue

        if provider.get("completeProvider"):
            return None

        exceptions = provider.get("exceptions", [])
        if any(re.match(exc, url, re.IGNORECASE) for exc in exceptions if isinstance(exc, str)):
            continue

        redirected = await handle_redirections(url, provider, loop)
        if redirected is None:
            return None

        parsed = urlparse(redirected)
        query_params = await clean_query_params(parsed.query, provider)
        cleaned_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(query_params),
                parsed.fragment,
            ),
        )

        for raw_rule in provider.get("rawRules", []):
            if isinstance(raw_rule, str):
                cleaned_url = re.sub(raw_rule, "", cleaned_url)

        return cleaned_url

    return url


async def handle_modified_content(message: hikari.Message, new_content: str) -> None:
    try:
        embed = await reply_embed(
            plugin.client,
            "Link Cleaned",
            ("The link you sent may expose private tracking identifiers. Your message has been cleaned and reposted."),
            Color.WARNING,
        )

        with contextlib.suppress(Exception):
            dm_channel = await plugin.client.rest.create_dm_channel(message.author.id)
            await plugin.client.rest.create_message(dm_channel.id, embed=embed)

        channel = await plugin.client.rest.fetch_channel(message.channel_id)
        thread_id = channel.id if isinstance(channel, hikari.GuildThreadChannel) else hikari.UNDEFINED
        parent_channel_id = channel.parent_id if isinstance(channel, hikari.GuildThreadChannel) else channel.id

        webhook = await plugin.client.rest.create_webhook(
            parent_channel_id,
            "Link Webhook",
        )
        try:
            if webhook.token:
                await plugin.client.rest.execute_webhook(
                    webhook.id,
                    webhook.token,
                    content=new_content,
                    username=message.author.username if hasattr(message.author, "username") else str(message.author.id),
                    avatar_url=message.author.display_avatar_url
                    if hasattr(message.author, "display_avatar_url")
                    else hikari.UNDEFINED,
                    thread=thread_id,
                )
            with contextlib.suppress(hikari.NotFoundError):
                await plugin.client.rest.delete_message(message.channel_id, message.id)
        finally:
            with contextlib.suppress(Exception):
                await plugin.client.rest.delete_webhook(webhook.id)
    except Exception:
        logger.exception("Failed to handle modified content")


@plugin.listen(hikari.MessageCreateEvent)
async def on_message_create_for_link(event: hikari.MessageCreateEvent) -> None:
    if not should_process_any_link(event):
        return

    message = event.message
    content = message.content or ""
    modified = False

    if should_process_bilibili_link(event):
        transformed = bilibili_link(content)
        if transformed != content:
            content = transformed
            modified = True

    links = set(URL_PATTERN.findall(content))
    if not links:
        if modified:
            await handle_modified_content(message, content)
        return

    rules_local = model.rules
    if not rules_local:
        payload = await model._read_store(SCRUB_RULES_FILE)
        if isinstance(payload, dict):
            rules_local = payload
            model.rules = payload

    for link in links:
        if link.startswith("https://discord.com"):
            continue
        cleaned = await clean_any_url(link, rules_local)
        if cleaned and await should_replace_link(link, cleaned):
            content = content.replace(link, cleaned)
            modified = True

    if modified:
        await handle_modified_content(message, content)


@scrub_group.include
@arc.slash_subcommand("update", "Update Scrub with the latest rules")
async def update_scrub_rules(ctx: arc.GatewayContext) -> None:
    await ctx.defer()

    sources = [
        "https://rules2.clearurls.xyz/data.minify.json",
        "https://rules1.clearurls.xyz/data.minify.json",
    ]

    timeout = aiohttp.ClientTimeout(total=10)
    headers = {"Accept": "application/json"}

    rules_payload: dict[str, Any] | None = None
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        for source in sources:
            try:
                async with session.get(source) as resp:
                    if resp.status != 200:
                        continue
                    payload = await resp.json()
                    if isinstance(payload, dict):
                        rules_payload = payload
                        break
            except Exception:
                continue

    if rules_payload is None:
        await send_error(ctx, "Failed to fetch rules from all sources")
        return

    model.rules = rules_payload
    await model.save_scrub_rules(SCRUB_RULES_FILE)
    await send_success(ctx, "Updating and saving rules locally.")


@plugin.listen(hikari.GuildReactionAddEvent)
async def on_reaction_add(event: hikari.GuildReactionAddEvent) -> None:
    if event.emoji_name not in STAR_EMOJIS or not event.message_id:
        return

    try:
        message = await plugin.client.rest.fetch_message(
            event.channel_id,
            event.message_id,
        )
        if message.author.id == event.user_id:
            return

        reactions = message.reactions or []
        total = sum(
            reaction.count
            for reaction in reactions
            if hasattr(reaction.emoji, "name") and reaction.emoji.name in STAR_EMOJIS
        )

        message_id = str(message.id)
        model.starred_messages[message_id] = total

        now = datetime.now(UTC)
        hour = now.replace(minute=0, second=0, microsecond=0).isoformat()
        day = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        week = (
            (now - timedelta(days=now.weekday()))
            .replace(
                hour=0,
                minute=0,
                second=0,
                microsecond=0,
            )
            .isoformat()
        )

        model.star_stats.hourly[hour] = model.star_stats.hourly.get(hour, 0) + 1
        model.star_stats.daily[day] = model.star_stats.daily.get(day, 0) + 1
        model.star_stats.weekly[week] = model.star_stats.weekly.get(week, 0) + 1

        await model.adjust_star_threshold()

        if total >= model.star_threshold and message_id not in model.starboard_messages:
            await add_to_starboard(message)

        await model.save_starred_messages(STARRED_MESSAGES_FILE)
    except Exception:
        logger.exception("Failed to process reaction add")


@plugin.listen(hikari.GuildReactionDeleteEvent)
async def on_reaction_remove(event: hikari.GuildReactionDeleteEvent) -> None:
    if event.emoji_name not in STAR_EMOJIS or not event.message_id:
        return

    try:
        message = await plugin.client.rest.fetch_message(
            event.channel_id,
            event.message_id,
        )
        reactions = message.reactions or []
        total = sum(
            reaction.count
            for reaction in reactions
            if hasattr(reaction.emoji, "name") and reaction.emoji.name in STAR_EMOJIS
        )

        message_id = str(message.id)
        model.starred_messages[message_id] = total

        if total < model.star_threshold and message_id in model.starboard_messages:
            await remove_from_starboard(message_id)

        await model.save_starred_messages(STARRED_MESSAGES_FILE)
    except Exception:
        logger.exception("Failed to process reaction remove")


async def add_to_starboard(message: hikari.Message) -> None:
    embed = await reply_embed(
        plugin.client,
        "",
        message.content or "",
        Color.WARNING,
    )
    embed.timestamp = message.timestamp

    embed.add_field(
        name="Source",
        value=(f"[Jump to Message](https://discord.com/channels/{message.guild_id}/{message.channel_id}/{message.id})"),
        inline=True,
    )
    embed.add_field(
        name="Author",
        value=message.author.mention,
        inline=True,
    )
    embed.add_field(name="Channel", value=f"<#{message.channel_id}>", inline=True)

    if message.attachments:
        embed.set_image(message.attachments[0].url)

    embed.set_author(
        name=message.author.username,
        icon=message.author.display_avatar_url,
    )

    forum = await plugin.client.rest.fetch_channel(STARBOARD_FORUM_ID)
    post = await plugin.client.rest.fetch_channel(STARBOARD_POST_ID)
    if not isinstance(forum, hikari.GuildForumChannel):
        return
    if not isinstance(post, hikari.GuildThreadChannel):
        return

    starboard_message = await plugin.client.rest.create_message(
        STARBOARD_POST_ID,
        embed=embed,
    )
    model.starboard_messages[str(message.id)] = str(starboard_message.id)
    await model.save_starred_messages(STARRED_MESSAGES_FILE)

    content = message.content or ""
    if message.attachments:
        attachment_links = "\n".join(
            f"[Attachment {index + 1}]({a.url})" for index, a in enumerate(message.attachments)
        )
        content = f"{content}\n\n{attachment_links}" if content else attachment_links

    webhook = await plugin.client.rest.create_webhook(
        STARBOARD_FORUM_ID,
        "Starboard Webhook",
    )
    try:
        if webhook.token:
            await plugin.client.rest.execute_webhook(
                webhook.id,
                webhook.token,
                content=content if content.startswith("# ") else f"# {content}",
                username=message.author.username,
                avatar_url=message.author.display_avatar_url,
                thread=STARBOARD_POST_ID,
            )
    finally:
        with contextlib.suppress(Exception):
            await plugin.client.rest.delete_webhook(webhook.id)


async def remove_from_starboard(message_id: str) -> None:
    starboard_message_id = model.starboard_messages.get(message_id)
    if starboard_message_id is None:
        return

    with contextlib.suppress(hikari.NotFoundError):
        await plugin.client.rest.delete_message(
            STARBOARD_POST_ID,
            int(starboard_message_id),
        )

    model.starboard_messages.pop(message_id, None)
    await model.save_starred_messages(STARRED_MESSAGES_FILE)


@plugin.listen(hikari.GuildThreadCreateEvent)
async def on_new_thread_create_for_poll(event: hikari.GuildThreadCreateEvent) -> None:
    thread = event.thread
    if not isinstance(thread, hikari.GuildThreadChannel):
        return

    parent_id = thread.parent_id
    if parent_id not in POLL_FORUM_ID and parent_id != CONGRESS_FORUM_ID:
        return

    owner_id = thread.owner_id
    if owner_id is None:
        return

    try:
        owner = await plugin.client.rest.fetch_member(GUILD_ID, owner_id)
    except hikari.NotFoundError:
        return

    if owner.is_bot:
        return

    forum_id = parent_id
    skip_tags = {
        POLL_FORUM_ID[0]: {1242530950970216590, 1184022078278602825},
        CONGRESS_FORUM_ID: {1196707934877528075, 1276909294565986438},
    }.get(forum_id, set())

    thread_tags = set(getattr(thread, "applied_tags", ()))
    create_poll = not bool(skip_tags & thread_tags)

    await process_new_post(thread, create_poll=create_poll)


async def process_new_post(
    thread: hikari.GuildThreadChannel,
    create_poll: bool = True,
) -> None:
    timestamp = datetime.now(UTC).strftime("%y%m%d%H%M")
    await plugin.client.rest.edit_channel(
        thread.id,
        name=f"[{timestamp}] {thread.name}",
    )

    if not create_poll:
        return

    poll = PollBuilder(
        question_text="您对此持何意见？What is your position?",
        answers=[
            PollAnswerBuilder(text="正  In Favor"),
            PollAnswerBuilder(text="反  Opposed"),
            PollAnswerBuilder(text="无  Abstain"),
        ],
        duration=48,
        allow_multiselect=False,
    )
    await plugin.client.rest.create_message(thread.id, poll=poll)


@plugin.listen(hikari.MessageCreateEvent)
async def on_message_create_for_banned_users(event: hikari.MessageCreateEvent) -> None:
    message = event.message
    if not message.guild_id or message.author is None:
        return

    channel = await plugin.client.rest.fetch_channel(message.channel_id)
    if not isinstance(channel, hikari.GuildThreadChannel):
        return

    channel_id = str(channel.parent_id or channel.id)
    thread_id = str(channel.id)
    user_id = str(message.author.id)

    if await is_user_banned_cached(channel_id, thread_id, user_id):
        with contextlib.suppress(hikari.NotFoundError):
            await plugin.client.rest.delete_message(message.channel_id, message.id)


@plugin.listen(hikari.StoppingEvent)
async def on_extension_unload(_: hikari.StoppingEvent) -> None:
    model.close()
    pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)


@arc.loader
def load(client: arc.GatewayClient) -> None:
    client.add_plugin(plugin)


@arc.unloader
def unload(client: arc.GatewayClient) -> None:
    client.remove_plugin(plugin)
