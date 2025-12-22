import json
import asyncio
import logging
from collections import defaultdict

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешаем все источники (включая app://obsidian.md)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self):
        # file_id -> list of WebSockets
        self.active_connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, websocket: WebSocket, file_id: str):
        await websocket.accept()
        self.active_connections[file_id].append(websocket)
        print(f"Client connected to {file_id}")

    def disconnect(self, websocket: WebSocket, file_id: str):
        if file_id in self.active_connections:
            if websocket in self.active_connections[file_id]:
                self.active_connections[file_id].remove(websocket)
                if not self.active_connections[file_id]:
                    del self.active_connections[file_id]
        print(f"Client disconnected from {file_id}")

    async def broadcast(self, message: str, file_id: str, sender: WebSocket):
        # Отправляем всем в комнате, кроме отправителя
        if file_id in self.active_connections:
            for connection in self.active_connections[file_id]:
                if connection != sender:
                    await connection.send_text(message)


manager = ConnectionManager()


@app.websocket("/ws/{file_id}/{client_id}")
async def websocket_endpoint(websocket: WebSocket, file_id: str, client_id: str):
    await manager.connect(websocket, file_id)
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            payload["clientId"] = client_id  # Гарантируем, что ID проставлен сервером
            logger.info(f"Received message from {client_id}: {payload}")
            await manager.broadcast(json.dumps(payload), file_id, websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket, file_id)
        await manager.broadcast(
            json.dumps({"type": "disconnect", "clientId": client_id}),
            file_id,
            websocket,
        )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
