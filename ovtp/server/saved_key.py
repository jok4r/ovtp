from dataclasses import dataclass
from datetime import datetime
from rsa import PublicKey


@dataclass
class SavedKey:
    key: PublicKey
    expire: datetime
    verification_string: str = ''
    auth: bool = False
