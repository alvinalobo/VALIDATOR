from sqlalchemy import Column, Integer, String, ForeignKey
from app.database import Base


class RuleDependency(Base):
    __tablename__ = "rule_dependencies"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, nullable=False)
    depends_on_rule_id = Column(String, nullable=False)