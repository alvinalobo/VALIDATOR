from pydantic import BaseModel


class RuleDependencyCreate(BaseModel):
    rule_id: str
    depends_on_rule_id: str


class RuleDependencyResponse(BaseModel):
    id: int
    rule_id: str
    depends_on_rule_id: str

    class Config:
        from_attributes = True