import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# DATA_DIR can be overridden (e.g. /data in Docker) so the DB lives on the host.
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)
DATABASE_FILE = os.path.join(DATA_DIR, "settings.db")
DATABASE_URI = f"sqlite:///{DATABASE_FILE}"

engine = create_engine(
    DATABASE_URI,
    connect_args={"check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()
