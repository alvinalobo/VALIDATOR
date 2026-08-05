from sqlalchemy.orm import Session

from app import models, schemas


def create_dependency(db: Session, dependency: schemas.RuleDependencyCreate):
    db_dependency = models.RuleDependency(
        rule_id=dependency.rule_id,
        depends_on_rule_id=dependency.depends_on_rule_id,
    )

    db.add(db_dependency)
    db.commit()
    db.refresh(db_dependency)

    return db_dependency


def get_all_dependencies(db: Session):
    return db.query(models.RuleDependency).all()


def get_dependency_by_rule(db: Session, rule_id: str):
    return (
        db.query(models.RuleDependency)
        .filter(models.RuleDependency.rule_id == rule_id)
        .all()
    )