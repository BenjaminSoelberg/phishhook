from dataclasses import dataclass

from marshmallow_dataclass import add_schema


@add_schema
@dataclass(eq=True, frozen=True)
class Brand:
    brand: str
    names: list[str]
    known_domains: list[str]
    enabled: bool = True

    class Meta:
        ordered = True
