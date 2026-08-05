from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app import models, schemas
from app.crud import dependency

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Rule Dependency Tracker")


@app.get("/")
def home():
    return {"message": "Rule Dependency Tracker is running "}


@app.post("/dependencies", response_model=schemas.RuleDependencyResponse)
def create_dependency(
    dependency_data: schemas.RuleDependencyCreate,
    db: Session = Depends(get_db)
):
    return dependency.create_dependency(db, dependency_data)


@app.get("/dependencies")
def get_dependencies(db: Session = Depends(get_db)):
    return dependency.get_all_dependencies(db)


@app.get("/dependencies/{rule_id}")
def get_dependency(rule_id: str, db: Session = Depends(get_db)):
    return dependency.get_dependency_by_rule(db, rule_id)