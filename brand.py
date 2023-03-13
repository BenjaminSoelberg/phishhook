from dataclasses import dataclass

from marshmallow_dataclass import add_schema


@add_schema
@dataclass(eq=True, frozen=True)
class Brand:
    brand: str
    known_domains: list[str]
    trigger_words: list[str]
    score_words: list[str]
    enabled: bool = True

    class Meta:
        ordered = True
