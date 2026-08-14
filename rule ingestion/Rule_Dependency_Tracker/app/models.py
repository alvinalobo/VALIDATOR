from sqlalchemy import Column, Integer, String
from app.database import Base


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)


class RuleDependency(Base):
    __tablename__ = "rule_dependencies"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, nullable=False)
    depends_on_rule_id = Column(String, nullable=False)