from dataclasses import dataclass

from marshmallow_dataclass import add_schema


@add_schema
@dataclass(eq=True, frozen=True)
class Rule:
    name: str
    brand: str
    tlds: list[str]
    sub_domains: list[str]

    class Meta:
        ordered = True
