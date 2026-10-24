from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from backend.app.config import settings

db_url = settings.DATABASE_URL
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(
    db_url,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in db_url else {}
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    import backend.app.db.models  # Ensure all model tables are registered in Base.metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Ensure sbx-seeddemo1 is seeded for fresh runs
    from backend.app.db.models import RunRecord
    async with AsyncSessionLocal() as session:
        try:
            stmt = select(RunRecord).where(RunRecord.sandbox_name == "sbx-seeddemo1")
            result = await session.execute(stmt)
            if not result.scalars().first():
                seed_run = RunRecord(
                    run_id="run-seeddemo1",
                    sandbox_name="sbx-seeddemo1",
                    problem_id="problem-email-quarantine",
                    state="deleted",
                    execution_target="celesto_sandbox",
                )
                session.add(seed_run)
                await session.commit()
        except Exception:
            await session.rollback()
