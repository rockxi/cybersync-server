import json
import logging
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any, Dict, List

import aiosqlite
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Настройка логирования
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

        # 1. Таблица снапшотов (полный текст файла)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                file_id TEXT PRIMARY KEY,
                content TEXT,
                version INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 2. Таблица дельт (история изменений)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT,
                version INTEGER,
                changes_json TEXT,
                client_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(file_id) REFERENCES snapshots(file_id)
            )
        """)

        # 3. НОВАЯ ТАБЛИЦА: Индекс файлов (для синхронизации создания/удаления)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vault_files (
                path TEXT PRIMARY KEY,
                is_deleted BOOLEAN DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await db.commit()
        logger.info("DB initialized with 3 tables")


# --- TEXT SYNC HELPERS ---


async def get_file_version(file_id: str) -> int:
    """Получить текущую версию файла из БД"""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT version FROM snapshots WHERE file_id = ?", (file_id,)
        )
        row = await cur.fetchone()
        return row[0] if row else 0


async def save_update(file_id: str, changes: Any, client_id: str) -> int:
    """Сохранить патч изменений и обновить версию"""
    async with aiosqlite.connect(DB_PATH) as db:
        # Проверяем, есть ли запись в snapshots
        cur = await db.execute(
            "SELECT version FROM snapshots WHERE file_id = ?", (file_id,)
        )
        row = await cur.fetchone()

        if row is None:
            current_version = 0
            # Создаем пустую запись, если файла еще нет
            await db.execute(
                "INSERT INTO snapshots (file_id, content, version) VALUES (?, '', 0)",
                (file_id,),
            )
            logger.info(f"[DB] Created new snapshot row for {file_id}")
        else:
            current_version = row[0]

        new_version = current_version + 1

        # Записываем дельту
        await db.execute(
            "INSERT INTO updates (file_id, version, changes_json, client_id) VALUES (?, ?, ?, ?)",
            (file_id, new_version, json.dumps(changes), client_id),
        )
        # Обновляем версию снапшота
        await db.execute(
            "UPDATE snapshots SET version = ?, updated_at = CURRENT_TIMESTAMP WHERE file_id = ?",
            (new_version, file_id),
        )
        await db.commit()
        logger.info(f"[DB] Saved v{new_version} for {file_id}")
        return new_version


async def get_missing_updates(file_id: str, client_version: int) -> List[Dict]:
    """Получить все пропущенные изменения для клиента"""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT version, changes_json, client_id FROM updates WHERE file_id = ? AND version > ? ORDER BY version ASC",
            (file_id, client_version),
        )
        rows = await cur.fetchall()
        updates = []
        for ver, changes_json, cid in rows:
            try:
                changes = json.loads(changes_json)
                updates.append(
                    {
                        "type": "text_change",
                        "version": ver,
                        "changes": changes,
                        "clientId": cid,
                        "is_history": True,
                    }
                )
            except json.JSONDecodeError:
                logger.error(f"[DB] Corrupted JSON in update v{ver} for {file_id}")
        return updates


async def get_full_snapshot(file_id: str) -> Dict[str, Any] | None:
    """Получить полный текст файла"""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT content, version FROM snapshots WHERE file_id = ?", (file_id,)
        )
        row = await cur.fetchone()
        if not row:
            return None
        return {"content": row[0], "version": row[1]}


async def save_snapshot_hint(file_id: str, ver: int, content: str):
    """Сохранить полный текст (snapshot) от клиента"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO snapshots(file_id, content, version) VALUES(?, ?, ?) "
                "ON CONFLICT(file_id) DO UPDATE SET "
                "content = excluded.content, version = excluded.version, updated_at = CURRENT_TIMESTAMP",
                (file_id, content, ver),
            )
            await db.commit()
    except Exception as e:
        logger.error(f"[DB] Failed to save snapshot hint: {e}")


# --- VAULT SYNC HELPERS (GLOBAL) ---


async def update_vault_index(path: str, is_deleted: bool):
    """Обновить статус файла в глобальном индексе"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO vault_files (path, is_deleted, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(path) DO UPDATE SET is_deleted=excluded.is_deleted, updated_at=CURRENT_TIMESTAMP",
            (path, is_deleted),
        )
        await db.commit()


async def get_all_active_files() -> List[str]:
    """Получить список всех 'живых' файлов"""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT path FROM vault_files WHERE is_deleted = 0")
        rows = await cur.fetchall()
        return [r[0] for r in rows]


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
        self.active_connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, websocket: WebSocket, file_id: str):
        await websocket.accept()
        self.active_connections[file_id].append(websocket)
        logger.info(f"[WS] Connected: file={file_id}")

    def disconnect(self, websocket: WebSocket, file_id: str):
        conns = self.active_connections.get(file_id)
        if conns and websocket in conns:
            conns.remove(websocket)
            if not conns:
                del self.active_connections[file_id]
        logger.info(f"[WS] Disconnected: file={file_id}")

    async def broadcast_update(self, payload: dict, file_id: str, sender: WebSocket):
        if file_id not in self.active_connections:
            return
        msg = json.dumps(payload)
        for ws in list(self.active_connections[file_id]):
            if ws is sender:
                continue
            try:
                await ws.send_text(msg)
            except Exception as e:
                logger.error(f"[WS] Broadcast error: {e}")


manager = ConnectionManager()


# ---------- WEBSOCKET ENDPOINT ----------


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Используем query params для избежания проблем с кодировкой путей
    file_id = websocket.query_params.get("file_id")
    client_id = websocket.query_params.get("client_id")

    if not file_id or not client_id:
        logger.error("[WS] Connection rejected: Missing params")
        await websocket.close(code=1008)
        return

    logger.info(f"[WS] Incoming: file={file_id}, client={client_id}")
    await manager.connect(websocket, file_id)

    try:
        # ==========================================
        # РЕЖИМ 1: ГЛОБАЛЬНАЯ СИНХРОНИЗАЦИЯ ФАЙЛОВ
        # ==========================================
        if file_id == "__global__":
            # 1. Отправляем Initial Sync (список всех файлов)
            try:
                all_files = await get_all_active_files()
                await websocket.send_text(
                    json.dumps({"type": "vault_sync_init", "files": all_files})
                )
                logger.info(
                    f"[VAULT] Sent init sync ({len(all_files)} files) to {client_id}"
                )
            except Exception as e:
                logger.error(f"[VAULT] Init sync failed: {e}")

            # 2. Слушаем события
            while True:
                data = await websocket.receive_text()
                try:
                    payload = json.loads(data)
                except json.JSONDecodeError:
                    continue

                msg_type = payload.get("type")

                # Обработка запроса синхронизации
                if msg_type == "request_sync":
                    try:
                        all_files = await get_all_active_files()
                        await websocket.send_text(
                            json.dumps({"type": "vault_sync_init", "files": all_files})
                        )
                        logger.info(
                            f"[VAULT] Sent re-sync ({len(all_files)} files) to {client_id}"
                        )
                    except Exception as e:
                        logger.error(f"[VAULT] Re-sync failed: {e}")
                    continue

                if msg_type in ["file_created", "file_deleted", "file_renamed"]:
                    path = payload.get("path")

                    if msg_type == "file_created":
                        await update_vault_index(path, False)
                        logger.info(f"[VAULT] Created: {path} by {client_id}")

                    elif msg_type == "file_deleted":
                        await update_vault_index(path, True)
                        logger.info(f"[VAULT] Deleted: {path} by {client_id}")

                    elif msg_type == "file_renamed":
                        old_path = payload.get("oldPath")
                        await update_vault_index(
                            old_path, True
                        )  # Старый помечаем удаленным
                        await update_vault_index(path, False)  # Новый активным
                        logger.info(
                            f"[VAULT] Renamed: {old_path} -> {path} by {client_id}"
                        )

                    # Рассылаем всем остальным
                    payload["clientId"] = client_id
                    await manager.broadcast_update(payload, "__global__", websocket)

        # ==========================================
        # РЕЖИМ 2: СИНХРОНИЗАЦИЯ ТЕКСТА (ОДИН ФАЙЛ)
        # ==========================================
        else:
            while True:
                try:
                    data = await websocket.receive_text()
                except WebSocketDisconnect:
                    break

                try:
                    payload = json.loads(data)
                except json.JSONDecodeError:
                    logger.error("[WS] Invalid JSON")
                    continue

                msg_type = payload.get("type")

                # --- SYNC REQUEST (новая логика синхронизации) ---
                if msg_type == "sync_request":
                    local_changed = payload.get("localChanged", False)
                    local_content = payload.get("localContent")
                    local_version = int(payload.get("localVersion") or 0)
                    server_ver = await get_file_version(file_id)
                    
                    logger.info(
                        f"[WS] Sync request: local_changed={local_changed}, "
                        f"local_ver={local_version}, server_ver={server_ver}"
                    )
                    
                    # Случай 1: Локально не менялось - просто подгрузить с сервера
                    if not local_changed:
                        if server_ver > local_version:
                            # Есть обновления на сервере
                            snap = await get_full_snapshot(file_id)
                            if snap:
                                await websocket.send_text(
                                    json.dumps(
                                        {
                                            "type": "full_sync",
                                            "content": snap["content"],
                                            "version": snap["version"],
                                        }
                                    )
                                )
                                logger.info(f"[WS] Sent server updates to {client_id}")
                        else:
                            # Ничего не менялось - подтвердить
                            await websocket.send_text(
                                json.dumps({"type": "ack", "version": server_ver})
                            )
                    
                    # Случай 2: Локально менялось
                    else:
                        if server_ver == local_version:
                            # На сервере не менялось - отправить локальное на сервер
                            if local_content is not None:
                                new_ver = server_ver + 1
                                await save_snapshot_hint(file_id, new_ver, local_content)
                                await websocket.send_text(
                                    json.dumps({"type": "ack", "version": new_ver})
                                )
                                logger.info(
                                    f"[WS] Accepted local changes from {client_id}, v{new_ver}"
                                )
                        else:
                            # Конфликт! Менялось и на сервере, и локально
                            # Простая стратегия: сервер побеждает
                            snap = await get_full_snapshot(file_id)
                            if snap:
                                await websocket.send_text(
                                    json.dumps(
                                        {
                                            "type": "full_sync",
                                            "content": snap["content"],
                                            "version": snap["version"],
                                            "conflict": True,
                                        }
                                    )
                                )
                                logger.warning(
                                    f"[WS] Conflict detected for {client_id}! "
                                    f"Server version wins (v{snap['version']})"
                                )
                    continue

                # --- HANDSHAKE ---
                if msg_type == "handshake":
                    client_ver = int(payload.get("version") or 0)
                    server_ver = await get_file_version(file_id)
                    logger.info(
                        f"[WS] Handshake {file_id}: client={client_ver}, server={server_ver}"
                    )

                    if server_ver > client_ver:
                        diff = server_ver - client_ver
                        # Если клиент слишком отстал -> Full Sync
                        if diff > 50:
                            logger.info(
                                f"[WS] Client outdated (+{diff}). Sending Full Sync."
                            )
                            snap = await get_full_snapshot(file_id)
                            if snap:
                                await websocket.send_text(
                                    json.dumps(
                                        {
                                            "type": "full_sync",
                                            "content": snap["content"],
                                            "version": snap["version"],
                                        }
                                    )
                                )
                        else:
                            # Иначе шлем патчи
                            updates = await get_missing_updates(file_id, client_ver)
                            logger.info(
                                f"[WS] Sending {len(updates)} patches to {client_id}"
                            )
                            for up in updates:
                                await websocket.send_text(json.dumps(up))

                # --- TEXT CHANGE ---
                elif msg_type == "text_change":
                    changes = payload.get("changes")
                    try:
                        new_ver = await save_update(file_id, changes, client_id)
                        payload["version"] = new_ver
                        payload["clientId"] = client_id

                        # Рассылаем другим
                        await manager.broadcast_update(payload, file_id, websocket)
                        # Подтверждаем автору
                        await websocket.send_text(
                            json.dumps({"type": "ack", "version": new_ver})
                        )
                    except Exception as e:
                        logger.error(f"[WS] Save update failed: {e}")

                # --- ACK / SNAPSHOT HINT ---
                elif msg_type == "ack" or msg_type == "snapshot_hint":
                    ver = int(payload.get("version") or 0)
                    content = payload.get("content", "")
                    if content:
                        await save_snapshot_hint(file_id, ver, content)

                # --- FULL SYNC REQUEST ---
                elif msg_type == "full_sync" or msg_type == "request_full_sync":
                    snap = await get_full_snapshot(file_id)
                    resp = {"type": "full_sync", "content": "", "version": 0}
                    if snap:
                        resp = {
                            "type": "full_sync",
                            "content": snap["content"],
                            "version": snap["version"],
                        }
                    logger.info(f"[WS] Full sync requested by {client_id}, version={resp['version']}")
                    await websocket.send_text(json.dumps(resp))

                # --- CURSOR / DISCONNECT ---
                elif msg_type in ["cursor", "disconnect"]:
                    payload["clientId"] = client_id
                    await manager.broadcast_update(payload, file_id, websocket)

    except WebSocketDisconnect:
        logger.info(f"[WS] Disconnected: {client_id}")
    except Exception as e:
        logger.error(f"[WS] Unexpected error: {e}", exc_info=True)
    finally:
        manager.disconnect(websocket, file_id)
        if file_id != "__global__":
            # Уведомляем других, что курсор ушел
            await manager.broadcast_update(
                {"type": "disconnect", "clientId": client_id}, file_id, websocket
            )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
