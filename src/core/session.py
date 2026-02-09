"""Session management for Minka."""

import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
import structlog
from sqlalchemy import Column, DateTime, String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import get_settings

logger = structlog.get_logger(__name__)

Base = declarative_base()


class SessionModel(Base):
    """Database model for sessions."""

    __tablename__ = "sessions"

    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    agent_type = Column(String, nullable=False)
    model = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime)
    metadata_json = Column(Text, default="{}")


class SessionManager:
    """Manages conversation sessions and history."""

    def __init__(self) -> None:
        """Initialize session manager."""
        self.settings = get_settings()
        self._redis: Optional[redis.Redis] = None
        self._db_engine = None
        self._session_factory = None

    async def initialize(self) -> None:
        """Initialize database and cache connections."""
        # Initialize Redis
        try:
            self._redis = await redis.from_url(
                self.settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning("Failed to connect to Redis", error=str(e))
            self._redis = None

        # Initialize Database
        try:
            self._db_engine = create_async_engine(
                self.settings.database_url,
                echo=self.settings.minka_log_level == "DEBUG",
            )
            self._session_factory = sessionmaker(
                self._db_engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )

            # Create tables
            async with self._db_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            logger.info("Database connection established")
        except Exception as e:
            logger.warning("Failed to connect to database", error=str(e))
            self._db_engine = None

    def create_session_id(self) -> str:
        """Generate a unique session ID."""
        return f"minka_{uuid.uuid4().hex[:12]}"

    async def save_session(
        self,
        session_id: str,
        agent_type: str,
        model: str,
        user_id: str = "anonymous",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Save session information.

        Args:
            session_id: Unique session identifier
            agent_type: Type of agent (vuln_researcher, red_team, etc.)
            model: LLM model used
            user_id: User identifier
            metadata: Additional session metadata
        """
        session_data = {
            "id": session_id,
            "user_id": user_id,
            "agent_type": agent_type,
            "model": model,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (
                datetime.utcnow() + timedelta(seconds=self.settings.copilot_session_timeout)
            ).isoformat(),
            "metadata": metadata or {},
        }

        # Save to Redis (fast access)
        if self._redis:
            try:
                await self._redis.setex(
                    f"session:{session_id}",
                    self.settings.copilot_session_timeout,
                    json.dumps(session_data),
                )
            except Exception as e:
                logger.error("Failed to save to Redis", error=str(e))

        # Save to Database (persistent)
        if self._db_engine:
            try:
                async with self._session_factory() as db_session:
                    db_record = SessionModel(
                        id=session_id,
                        user_id=user_id,
                        agent_type=agent_type,
                        model=model,
                        expires_at=datetime.utcnow()
                        + timedelta(seconds=self.settings.copilot_session_timeout),
                        metadata_json=json.dumps(metadata or {}),
                    )
                    db_session.add(db_record)
                    await db_session.commit()
            except Exception as e:
                logger.error("Failed to save to database", error=str(e))

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session information.

        Args:
            session_id: Session identifier

        Returns:
            Session data or None if not found/expired
        """
        # Try Redis first
        if self._redis:
            try:
                data = await self._redis.get(f"session:{session_id}")
                if data:
                    return json.loads(data)
            except Exception as e:
                logger.error("Failed to get from Redis", error=str(e))

        # Fall back to database
        if self._db_engine:
            try:
                async with self._session_factory() as db_session:
                    result = await db_session.execute(
                        select(SessionModel).where(SessionModel.id == session_id)
                    )
                    record = result.scalar_one_or_none()

                    if record and record.expires_at > datetime.utcnow():
                        return {
                            "id": record.id,
                            "user_id": record.user_id,
                            "agent_type": record.agent_type,
                            "model": record.model,
                            "created_at": record.created_at.isoformat(),
                            "metadata": json.loads(record.metadata_json),
                        }
            except Exception as e:
                logger.error("Failed to get from database", error=str(e))

        return None

    async def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a message to session history.

        Args:
            session_id: Session identifier
            role: Message role (user, assistant, system)
            content: Message content
            metadata: Additional metadata
        """
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }

        if self._redis:
            try:
                key = f"history:{session_id}"
                await self._redis.lpush(key, json.dumps(message))
                await self._redis.ltrim(key, 0, 99)  # Keep last 100 messages
                await self._redis.expire(key, self.settings.copilot_session_timeout)
            except Exception as e:
                logger.error("Failed to add message to Redis", error=str(e))

    async def get_history(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get conversation history for a session.

        Args:
            session_id: Session identifier
            limit: Maximum number of messages to retrieve

        Returns:
            List of messages
        """
        if not self._redis:
            return []

        try:
            messages = await self._redis.lrange(f"history:{session_id}", 0, limit - 1)
            return [json.loads(m) for m in messages[::-1]]  # Reverse to get chronological order
        except Exception as e:
            logger.error("Failed to get history", error=str(e))
            return []

    async def delete_session(self, session_id: str) -> None:
        """Delete a session and its history.

        Args:
            session_id: Session identifier
        """
        # Delete from Redis
        if self._redis:
            try:
                await self._redis.delete(f"session:{session_id}")
                await self._redis.delete(f"history:{session_id}")
            except Exception as e:
                logger.error("Failed to delete from Redis", error=str(e))

        # Mark as deleted in database
        if self._db_engine:
            try:
                async with self._session_factory() as db_session:
                    result = await db_session.execute(
                        select(SessionModel).where(SessionModel.id == session_id)
                    )
                    record = result.scalar_one_or_none()
                    if record:
                        record.expires_at = datetime.utcnow()
                        await db_session.commit()
            except Exception as e:
                logger.error("Failed to update database", error=str(e))

    async def cleanup_expired(self) -> int:
        """Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        count = 0

        if self._db_engine:
            try:
                async with self._session_factory() as db_session:
                    result = await db_session.execute(
                        select(SessionModel).where(SessionModel.expires_at < datetime.utcnow())
                    )
                    expired = result.scalars().all()

                    for record in expired:
                        await db_session.delete(record)
                        count += 1

                    await db_session.commit()

                    if count > 0:
                        logger.info("Cleaned up expired sessions", count=count)

            except Exception as e:
                logger.error("Failed to cleanup expired sessions", error=str(e))

        return count
