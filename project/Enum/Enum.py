from enum import Enum


class RelationType(Enum):
    HOSTS = "hosts"
    USES = "uses"
    PROVIDES = "provides"
    CONNECTS = "connects"

    @classmethod
    def choices(cls):
        print(tuple((i.name, i.value) for i in cls))
        return tuple((i.name, i.value) for i in cls)


