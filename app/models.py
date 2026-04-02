from sqlalchemy import Column, Integer, String, Text, Boolean
from app.db import Base


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(128), primary_key=True, nullable=False)
    value = Column(Text, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)


class Zone(Base):
    __tablename__ = "zones"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    # "forward" or "reverse"
    zone_type = Column(String(16), nullable=False, default="forward")
    description = Column(String(255), nullable=False, default="")
