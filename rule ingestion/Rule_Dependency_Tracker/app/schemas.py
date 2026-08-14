from pydantic import BaseModel


class RuleCreate(BaseModel):
    rule_id: str
    name: str
    description: str | None = None


class RuleResponse(BaseModel):
    id: int
    rule_id: str
    name: str
    description: str | None = None

    class Config:
        from_attributes = True


class RuleDependencyCreate(BaseModel):
    rule_id: str
    depends_on_rule_id: str


class RuleDependencyResponse(BaseModel):
    id: int
    rule_id: str
    depends_on_rule_id: str

    class Config:
        from_attributes = True