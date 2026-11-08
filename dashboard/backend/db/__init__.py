# SPDX-License-Identifier: AGPL-3.0-only
from backend.db.models import init, session


def engine():
    """Return the initialized SQLAlchemy engine (or raise if init() wasn't called)."""
    from backend.db import models
    if models._engine is None:
        raise RuntimeError("db.init() not called")
    return models._engine
