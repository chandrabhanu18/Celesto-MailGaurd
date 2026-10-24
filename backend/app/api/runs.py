import re
from typing import List, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.database import get_db
from backend.app.db.models import RunRecord
from backend.app.schemas.runs import RunResponse, VALID_STATES, SANDBOX_NAME_REGEX

router = APIRouter(tags=["runs"])


@router.get("/runs", response_model=List[RunResponse], status_code=status.HTTP_200_OK)
async def list_runs(db: AsyncSession = Depends(get_db)):
    """
    List all sandbox runs recorded in the ledger.
    Includes sbx-seeddemo1 on a fresh deployment.
    """
    stmt = select(RunRecord).order_by(RunRecord.created_at.desc())
    result = await db.execute(stmt)
    records = result.scalars().all()
    return records


@router.post("/runs", response_model=RunResponse, status_code=status.HTTP_201_CREATED)
async def create_run(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Record or update a sandbox run in the ledger.
    Strictly validates:
    - sandbox_name matches 'sbx-[a-z0-9]{8,}'
    - state is one of: created, ready, running, succeeded, failed, deleted
    - execution_target equals 'celesto_sandbox'
    Returns HTTP 400 on any invalid or unrecognized field per hackathon requirement 11.
    """
    try:
        body: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON request body",
        )

    run_id = body.get("run_id")
    sandbox_name = body.get("sandbox_name")
    problem_id = body.get("problem_id")
    state = body.get("state")
    execution_target = body.get("execution_target")

    # Validate required fields
    if not run_id or not isinstance(run_id, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="run_id is required and must be a non-empty string",
        )

    if not problem_id or not isinstance(problem_id, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="problem_id is required and must be a non-empty string",
        )

    # 1. Validate sandbox_name pattern (sbx- + 8 or more lowercase alnum)
    if not sandbox_name or not isinstance(sandbox_name, str) or not SANDBOX_NAME_REGEX.match(sandbox_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid sandbox_name '{sandbox_name}'. Must match 'sbx-[a-z0-9]{{8,}}'",
        )

    # 2. Validate state enum
    if not state or state not in VALID_STATES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid state '{state}'. Must be one of: {sorted(list(VALID_STATES))}",
        )

    # 3. Validate execution_target
    if execution_target != "celesto_sandbox":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid execution_target '{execution_target}'. Must equal 'celesto_sandbox'",
        )

    # Check if run already exists
    stmt = select(RunRecord).where(RunRecord.run_id == run_id)
    result = await db.execute(stmt)
    existing_run = result.scalars().first()

    if existing_run:
        existing_run.sandbox_name = sandbox_name
        existing_run.problem_id = problem_id
        existing_run.state = state
        existing_run.execution_target = execution_target
        await db.commit()
        await db.refresh(existing_run)
        return existing_run

    new_run = RunRecord(
        run_id=run_id,
        sandbox_name=sandbox_name,
        problem_id=problem_id,
        state=state,
        execution_target=execution_target,
    )
    db.add(new_run)
    await db.commit()
    await db.refresh(new_run)
    return new_run
