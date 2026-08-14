from sqlalchemy.orm import Session

from app import models, schemas


def create_rule(db: Session, rule: schemas.RuleCreate):
    db_rule = models.Rule(
        rule_id=rule.rule_id,
        name=rule.name,
        description=rule.description,
    )

    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)

    return db_rule


def get_all_rules(db: Session):
    return db.query(models.Rule).all()


def get_rule_by_id(db: Session, rule_id: str):
    return (
        db.query(models.Rule)
        .filter(models.Rule.rule_id == rule_id)
        .first()
    )