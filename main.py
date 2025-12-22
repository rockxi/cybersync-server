import json
import logging
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any, Dict, List

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


# ---------- DB ----------
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                file_id TEXT PRIMARY KEY,
                content TEXT,
                version INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT,
                version INTEGER,
                changes_json TEXT,
                client_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(file_id) REFERENCES snapshots(file_id)
            )
        """
        )
        await db.commit()
        logger.info("DB initialized")


async def get_file_version(file_id: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT version FROM snapshots WHERE file_id = ?", (file_id,)
        )
        row = await cur.fetchone()
        return row[0] if row else 0


async def save_update(file_id: str, changes: Any, client_id: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT version FROM snapshots WHERE file_id = ?", (file_id,)
        )
        row = await cur.fetchone()
        if row is None:
            current_version = 0
            await db.execute(
                "INSERT INTO snapshots (file_id, content, version) VALUES (?, '', 0)",
                (file_id,),
            )
            logger.info(f"[DB] Created snapshot row for {file_id}")
        else:
            current_version = row[0]

        new_version = current_version + 1
        await db.execute(
            "INSERT INTO updates (file_id, version, changes_json, client_id) "
            "VALUES (?, ?, ?, ?)",
            (file_id, new_version, json.dumps(changes), client_id),
        )
        # Мы обновляем версию в snapshots, но контент обновляем только по snapshot_hint
        await db.execute(
            "UPDATE snapshots SET version = ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE file_id = ?",
            (new_version, file_id),
        )
        await db.commit()
        logger.info(f"[DB] Saved update v{new_version} for {file_id} from {client_id}")
        return new_version


async def get_missing_updates(file_id: str, client_version: int) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT version, changes_json, client_id "
            "FROM updates WHERE file_id = ? AND version > ? "
            "ORDER BY version ASC",
            (file_id, client_version),
        )
        rows = await cur.fetchall()
        updates: List[Dict] = []
        for ver, changes_json, cid in rows:
            try:
                changes = json.loads(changes_json)
            except json.JSONDecodeError:
                logger.error(f"[DB] Bad JSON for {file_id} v{ver}, skipping row")
                continue
            updates.append(
                {
                    "type": "text_change",
                    "version": ver,
                    "changes": changes,
                    "clientId": cid,
                    "is_history": True,
                }
            )
        return updates


async def get_full_snapshot(file_id: str) -> Dict[str, Any] | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT content, version FROM snapshots WHERE file_id = ?",
            (file_id,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        return {"content": row[0], "version": row[1]}


# ---------- APP ----------
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


@app.websocket("/ws/{file_id}/{client_id}")
async def websocket_endpoint(websocket: WebSocket, file_id: str, client_id: str):
    logger.info(f"[WS] Incoming: file={file_id}, client={client_id}")
    await manager.connect(websocket, file_id)

    try:
        while True:
            try:
                data = await websocket.receive_text()
            except WebSocketDisconnect:
                logger.info(f"[WS] WebSocketDisconnect from {client_id} ({file_id})")
                break
            except RuntimeError as e:
                logger.warning(f"[WS] RuntimeError on receive from {client_id}: {e}")
                break
            except Exception as e:
                logger.error(f"[WS] receive_text error: {e}", exc_info=True)
                break

            logger.debug(f"[WS] recv from {client_id}: {data}")
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                logger.error("[WS] Invalid JSON received, skipping")
                continue

            msg_type = payload.get("type")

            if msg_type == "handshake":
                client_ver = int(payload.get("version") or 0)
                server_ver = await get_file_version(file_id)
                logger.info(
                    f"[WS] HANDSHAKE file={file_id} "
                    f"client={client_id} cv={client_ver} sv={server_ver}"
                )

                if server_ver > client_ver:
                    diff = server_ver - client_ver
                    # --- ЗАЩИТА ОТ ОГРОМНОЙ ИСТОРИИ ---
                    # Если клиент отстал больше чем на 50 версий, шлем Full Sync
                    if diff > 50:
                        logger.info(
                            f"[WS] Client too far behind ({diff}). Sending FULL SYNC instead of history."
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
                            # Если снапшота нет, придется слать историю
                            updates = await get_missing_updates(file_id, client_ver)
                            for up in updates:
                                await websocket.send_text(json.dumps(up))
                    else:
                        updates = await get_missing_updates(file_id, client_ver)
                        logger.info(
                            f"[WS] Sending {len(updates)} missed updates "
                            f"to {client_id} for {file_id}"
                        )
                        for up in updates:
                            try:
                                await websocket.send_text(json.dumps(up))
                            except Exception as e:
                                logger.error(
                                    f"[WS] Error sending history to {client_id}: {e}"
                                )
                                break

                elif client_ver > server_ver:
                    logger.warning(
                        f"[WS] Client ahead: file={file_id}, "
                        f"client={client_ver}, server={server_ver}"
                    )
                else:
                    logger.info(
                        f"[WS] Versions in sync for file={file_id}, client={client_id}"
                    )

            elif msg_type == "text_change":
                changes = payload.get("changes")
                logger.info(f"[WS] text_change from {client_id} for {file_id}")
                try:
                    new_ver = await save_update(file_id, changes, client_id)
                except Exception as e:
                    logger.error(f"[WS] Failed to save update for {file_id}: {e}")
                    continue

                payload["version"] = new_ver
                payload["clientId"] = client_id

                await manager.broadcast_update(payload, file_id, websocket)
                try:
                    await websocket.send_text(
                        json.dumps({"type": "ack", "version": new_ver})
                    )
                except Exception as e:
                    logger.error(f"[WS] Failed to send ack to {client_id}: {e}")

            elif msg_type == "cursor":
                payload["clientId"] = client_id
                await manager.broadcast_update(payload, file_id, websocket)

            elif msg_type == "snapshot_hint":
                ver = int(payload.get("version") or 0)
                content = payload.get("content", "")
                logger.info(f"[WS] snapshot_hint v{ver} for {file_id} from {client_id}")
                try:
                    async with aiosqlite.connect(DB_PATH) as db:
                        await db.execute(
                            "INSERT INTO snapshots(file_id, content, version) "
                            "VALUES(?, ?, ?) "
                            "ON CONFLICT(file_id) DO UPDATE SET "
                            "content = excluded.content, "
                            "version = excluded.version, "
                            "updated_at = CURRENT_TIMESTAMP",
                            (file_id, content, ver),
                        )
                        await db.commit()
                except Exception as e:
                    logger.error(
                        f"[DB] Failed to write snapshot_hint for {file_id}: {e}"
                    )

            elif msg_type == "full_sync":
                snap = await get_full_snapshot(file_id)
                if snap is None:
                    logger.info(
                        f"[WS] full_sync requested for {file_id}, but no snapshot"
                    )
                    resp = {"type": "full_sync", "content": "", "version": 0}
                else:
                    logger.info(
                        f"[WS] full_sync for {file_id}: v{snap['version']} to {client_id}"
                    )
                    resp = {
                        "type": "full_sync",
                        "content": snap["content"],
                        "version": snap["version"],
                    }
                try:
                    await websocket.send_text(json.dumps(resp))
                except Exception as e:
                    logger.error(f"[WS] Failed to send full_sync to {client_id}: {e}")

            else:
                logger.warning(f"[WS] Unknown message type: {msg_type}")

    finally:
        manager.disconnect(websocket, file_id)
        try:
            await manager.broadcast_update(
                {"type": "disconnect", "clientId": client_id},
                file_id,
                websocket,
            )
        except Exception as e:
            logger.error(f"[WS] Failed to broadcast disconnect: {e}")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
