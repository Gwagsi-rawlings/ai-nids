"""
AI-NIDS — Database Session Management
db/database.py

Provides async SQLAlchemy engine, session factory, and Base declarative class.
Used by all ORM models and API routers.

April 3, 2026 | Sprint 1, Week 4 | Developer: GWAGSI Rawlings Nshom
"""

import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://nids_user:nids_password@postgres:5432/nids_db",
)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,          # Set True in dev to log SQL
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,  # Recycle stale connections
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async DB session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables():
    """Create all tables on startup (dev convenience — use Alembic in prod)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)