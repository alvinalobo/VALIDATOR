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


def check_rule_dependencies(db: Session, rule_id: str):
    dependencies = (
        db.query(models.RuleDependency)
        .filter(models.RuleDependency.depends_on_rule_id == rule_id)
        .all()
    )

    if dependencies:
        return {
            "can_delete": False,
            "message": f"{rule_id} is used by other rules.",
            "dependent_rules": [d.rule_id for d in dependencies],
        }

    return {
        "can_delete": True,
        "message": "No dependencies found.",
        "dependent_rules": [],
    }


def delete_dependency(db: Session, dependency_id: int):
    dependency = (
        db.query(models.RuleDependency)
        .filter(models.RuleDependency.id == dependency_id)
        .first()
    )

    if not dependency:
        return {"message": "Dependency not found"}

    db.delete(dependency)
    db.commit()

    return {"message": "Dependency deleted successfully"}