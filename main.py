import difflib
import json
import logging
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Set

import aiosqlite
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("CyberSync")

DB_PATH = "cybersync.db"

# ---------- DATABASE ----------


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")

        # Таблица снапшотов (полный текст файла)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                file_path TEXT PRIMARY KEY,
                content TEXT,
                version INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Таблица дельт (история изменений)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                version INTEGER,
                changes_json TEXT,
                client_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(file_path) REFERENCES snapshots(file_path)
            )
        """
        )

        await db.commit()
        logger.info("DB initialized")


# --- HELPERS ---


async def get_file_version(file_path: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT version FROM snapshots WHERE file_path = ?", (file_path,)
        )
        row = await cur.fetchone()
        return row[0] if row else 0


async def get_full_snapshot(file_path: str) -> tuple[str, int] | None:
    """Получить полный текст файла и версию"""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT content, version FROM snapshots WHERE file_path = ?", (file_path,)
        )
        row = await cur.fetchone()
        if not row:
            return None
        return (row[0], row[1])


async def save_update(
    file_path: str, changes: Any, client_id: str, content: str
) -> int:
    """Сохранить обновление и новый снапшот"""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT version FROM snapshots WHERE file_path = ?", (file_path,)
        )
        row = await cur.fetchone()

        if row is None:
            current_version = 0
            await db.execute(
                "INSERT INTO snapshots (file_path, content, version) VALUES (?, ?, 0)",
                (file_path, ""),
            )
        else:
            current_version = row[0]

        new_version = current_version + 1

        await db.execute(
            "INSERT INTO updates (file_path, version, changes_json, client_id) VALUES (?, ?, ?, ?)",
            (file_path, new_version, json.dumps(changes), client_id),
        )

        await db.execute(
            "UPDATE snapshots SET content = ?, version = ?, updated_at = CURRENT_TIMESTAMP WHERE file_path = ?",
            (content, new_version, file_path),
        )
        await db.commit()
        logger.info(f"[DB] Saved v{new_version} for {file_path}")
        return new_version


async def get_missing_updates(file_path: str, client_version: int) -> List[Dict]:
    """Получить все изменения новее чем у клиента"""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT version, changes_json, client_id FROM updates WHERE file_path = ? AND version > ? ORDER BY version ASC",
            (file_path, client_version),
        )
        rows = await cur.fetchall()
        updates = []
        for ver, changes_json, cid in rows:
            try:
                changes = json.loads(changes_json)
                updates.append(
                    {
                        "type": "text_change",
                        "filePath": file_path,
                        "version": ver,
                        "changes": changes,
                        "clientId": cid,
                    }
                )
            except json.JSONDecodeError:
                logger.error(f"[DB] Corrupted JSON in update v{ver}")
        return updates


# ---------- APP SETUP ----------


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}  # client_id -> WebSocket
        self.file_versions: dict[str, int] = {}
        self.last_synced_hashes: dict[str, str] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"[WS] Connected: {client_id}")

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        logger.info(f"[WS] Disconnected: {client_id}")

    async def broadcast(self, payload: dict, exclude_client: str | None = None):
        """Транслировать сообщение всем клиентам"""
        msg = json.dumps(payload)
        for cid, ws in list(self.active_connections.items()):
            if exclude_client and cid == exclude_client:
                continue
            try:
                await ws.send_text(msg)
            except Exception as e:
                logger.error(f"[WS] Broadcast error to {cid}: {e}")


manager = ConnectionManager()


# ---------- WEBSOCKET ENDPOINT ----------


def compute_diff(old_text: str, new_text: str) -> str:
    """Вычисляет diff в стиле Git unified format"""
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines, lineterm="")
    return "\n".join(diff)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    client_id = websocket.query_params.get("client_id")

    if not client_id:
        logger.error("[WS] Connection rejected: Missing client_id")
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, client_id)

    try:
        while True:
            data = await websocket.receive_text()
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                logger.error("[WS] Invalid JSON")
                continue

            msg_type = payload.get("type")

            # --- REQUEST FULL STATE ---
            if msg_type == "request_full_state":
                file_versions = {}
                hashes = {}

                async with aiosqlite.connect(DB_PATH) as db:
                    cur = await db.execute("SELECT file_path, version FROM snapshots")
                    rows = await cur.fetchall()
                    for path, ver in rows:
                        file_versions[path] = ver

                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "full_state",
                            "fileVersions": file_versions,
                            "lastSyncedHashes": hashes,
                        }
                    )
                )
                logger.info(f"[WS] Sent full state to {client_id}")
                continue

            # --- TEXT CHANGE (в реальном времени) ---
            if msg_type == "text_change":
                file_path = payload.get("filePath")
                changes = payload.get("changes")
                version = payload.get("version", 0)

                snap = await get_full_snapshot(file_path)
                server_version = snap[1] if snap else 0

                # Проверяем что клиент актуален
                if version == server_version:
                    # Клиент актуален - применяем изменения и отправляем всем
                    try:
                        from codemirror import ChangeSet  # Имитируем

                        # На сервере просто сохраняем патч и отправляем всем
                        logger.info(
                            f"[WS] Text change for {file_path} from {client_id}"
                        )

                        payload["clientId"] = client_id
                        payload["version"] = server_version + 1

                        # TODO: Здесь нужно применить патч на сервере
                        # Для простоты просто транслируем всем
                        await manager.broadcast(payload, exclude_client=client_id)
                    except Exception as e:
                        logger.error(f"[WS] Text change error: {e}")
                else:
                    logger.warn(
                        f"[WS] Client version mismatch: client={version}, server={server_version}"
                    )
                continue

            # --- FILE CREATED ---
            if msg_type == "file_created":
                file_path = payload.get("filePath")

                # Создаем в БД
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        "INSERT OR IGNORE INTO snapshots (file_path, content, version) VALUES (?, ?, 0)",
                        (file_path, ""),
                    )
                    await db.commit()

                payload["clientId"] = client_id
                await manager.broadcast(payload)
                logger.info(f"[WS] File created: {file_path}")
                continue

            # --- FILE DELETED ---
            if msg_type == "file_deleted":
                file_path = payload.get("filePath")
                payload["clientId"] = client_id
                await manager.broadcast(payload)
                logger.info(f"[WS] File deleted: {file_path}")
                continue

            # --- FILE RENAMED ---
            if msg_type == "file_renamed":
                file_path = payload.get("filePath")
                old_path = payload.get("oldPath")

                # Переименовываем в БД
                async with aiosqlite.connect(DB_PATH) as db:
                    snap = await get_full_snapshot(old_path)
                    if snap:
                        content, version = snap
                        await db.execute(
                            "DELETE FROM snapshots WHERE file_path = ?", (old_path,)
                        )
                        await db.execute(
                            "INSERT INTO snapshots (file_path, content, version) VALUES (?, ?, ?)",
                            (file_path, content, version),
                        )
                        await db.commit()

                payload["clientId"] = client_id
                await manager.broadcast(payload)
                logger.info(f"[WS] File renamed: {old_path} -> {file_path}")
                continue

            # --- CURSOR ---
            if msg_type == "cursor":
                payload["clientId"] = client_id
                await manager.broadcast(payload)
                continue

            # --- SYNC OFFLINE CHANGES ---
            if msg_type == "sync_offline_changes":
                file_path = payload.get("filePath")
                local_content = payload.get("content", "")
                local_version = payload.get("localVersion", 0)

                snap = await get_full_snapshot(file_path)
                if snap:
                    server_content, server_version = snap

                    logger.info(
                        f"[WS] Offline sync for {file_path}: local_v={local_version}, server_v={server_version}"
                    )

                    # СЛУЧАЙ 1: Локально не менялось, но на сервере да
                    if (
                        local_version == server_version
                        and local_content == server_content
                    ):
                        logger.info(f"[WS] Files match, no conflict for {file_path}")
                        continue

                    # СЛУЧАЙ 2: Сервер не менялся, локально менялось
                    elif (
                        local_version == server_version
                        and local_content != server_content
                    ):
                        # Отправляем локальные изменения на сервер
                        new_version = await save_update(
                            file_path, {}, client_id, local_content
                        )

                        await websocket.send_text(
                            json.dumps(
                                {
                                    "type": "ack",
                                    "filePath": file_path,
                                    "version": new_version,
                                }
                            )
                        )

                        # Транслируем всем
                        await manager.broadcast(
                            {
                                "type": "text_change",
                                "filePath": file_path,
                                "version": new_version,
                                "clientId": client_id,
                                "fullContent": local_content,
                            },
                            exclude_client=client_id,
                        )

                        logger.info(f"[WS] Accepted offline changes for {file_path}")

                    # СЛУЧАЙ 3: Менялось и там и там - КОНФЛИКТ
                    elif (
                        local_version < server_version
                        and local_content != server_content
                    ):
                        # Вычисляем diff
                        local_diff = compute_diff(local_content, server_content)

                        await websocket.send_text(
                            json.dumps(
                                {
                                    "type": "conflict",
                                    "filePath": file_path,
                                    "localContent": local_content,
                                    "serverContent": server_content,
                                    "localDiff": local_diff,
                                    "serverDiff": "",
                                }
                            )
                        )

                        logger.warning(f"[WS] Conflict detected for {file_path}")

                    # СЛУЧАЙ 4: Локально не менялось, сервер менялся
                    else:
                        await websocket.send_text(
                            json.dumps(
                                {
                                    "type": "text_change",
                                    "filePath": file_path,
                                    "version": server_version,
                                    "clientId": "server",
                                    "fullContent": server_content,
                                }
                            )
                        )
                        logger.info(f"[WS] Syncing server changes for {file_path}")

    except WebSocketDisconnect:
        logger.info(f"[WS] Client disconnected: {client_id}")
    except Exception as e:
        logger.error(f"[WS] Error: {e}", exc_info=True)
    finally:
        manager.disconnect(client_id)

        # Уведомляем всех что этот клиент отключился
        await manager.broadcast({"type": "disconnect", "clientId": client_id})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
