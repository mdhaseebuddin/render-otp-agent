#!/usr/bin/env python3
"""
Entry point proxy for VeloTest Render OTP Agent
Exposes the FastAPI 'app' instance from app.py.
"""

from app import app

if __name__ == "__main__":
    import os
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)

