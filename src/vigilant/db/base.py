from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models. Import subclasses in `db.models` so
    Alembic's autogenerate can discover them via `Base.metadata`."""
