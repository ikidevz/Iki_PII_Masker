import re
from dataclasses import dataclass
from typing import ClassVar, Optional


@dataclass
class PIIType:
    name:         str
    patterns:     list[str]
    redact_label: str
    faker_method: str


class PIIRegistry:
    """
    Registry Pattern — central catalogue of every PII type the tool knows.

    Usage
    -----
    PIIRegistry.detect(columns)  → {col: PIIType}
    PIIRegistry.guess(col_name)  → PIIType | None
    PIIRegistry.register(pii)    → add a custom PIIType at runtime
    """

    _types: ClassVar[list[PIIType]] = [
        PIIType("email",       [r"\bemail\b", r"\bemail_address\b", r"\bmail\b", r"\be_mail\b"],
                "[EMAIL]",       "email"),
        PIIType("phone",       [r"\bphone\b", r"\bmobile\b", r"\bcell\b",
                                r"\btelephone\b", r"\btel\b", r"\bcontact_number\b"],
                "[PHONE]",       "phone_number"),
        PIIType("name",        [r"\bfull_name\b", r"\bfirst_name\b", r"\blast_name\b",
                                r"\bsurname\b", r"\bforename\b",
                                r"\buser_name\b", r"\busername\b", r"\bname\b"],
                "[NAME]",        "name"),
        PIIType("address",     [r"\baddress\b", r"\bstreet\b", r"\bcity\b",
                                r"\bstate\b", r"\bzip\b", r"\bpostal_code\b", r"\bcountry\b"],
                "[ADDRESS]",     "address"),
        PIIType("ssn",         [r"\bssn\b", r"\bsocial_security\b", r"\bnational_id\b"],
                "[SSN]",         "ssn"),
        PIIType("dob",         [r"\bdob\b", r"\bdate_of_birth\b", r"\bbirthdate\b", r"\bbirthday\b"],
                "[DOB]",         "date_of_birth"),
        PIIType("ip",          [r"\bip_address\b", r"\bip\b", r"\bipv4\b", r"\bipv6\b"],
                "[IP]",          "ipv4"),
        PIIType("credit_card", [r"\bcredit_card\b", r"\bcard_number\b",
                                r"\bcc_number\b", r"\bpan\b"],
                "[CARD]",        "credit_card_number"),
        PIIType("user_id",     [r"\buser_id\b", r"\buserid\b",
                                r"\baccount_id\b", r"\bcustomer_id\b"],
                "[ID]",          "uuid4"),
        PIIType("password",    [r"\bpassword\b", r"\bpasswd\b", r"\bhash\b", r"\bpwd\b"],
                "[REDACTED]",    "password"),
    ]

    _by_name: ClassVar[dict[str, PIIType]] = {t.name: t for t in _types}

    @classmethod
    def register(cls, pii: PIIType) -> None:
        """Extend the registry at runtime."""
        cls._types.append(pii)
        cls._by_name[pii.name] = pii

    @classmethod
    def detect(cls, columns: list[str]) -> dict[str, PIIType]:
        """Return {column_name: PIIType} for every column matching a pattern."""
        result: dict[str, PIIType] = {}
        for col in columns:
            col_lower = col.lower()
            for pii in cls._types:
                if any(re.search(p, col_lower) for p in pii.patterns):
                    result[col] = pii
                    break
        return result

    @classmethod
    def guess(cls, col_name: str) -> Optional[PIIType]:
        col_lower = col_name.lower()
        for pii in cls._types:
            if any(re.search(p, col_lower) for p in pii.patterns):
                return pii
        return None

    @classmethod
    def get(cls, name: str) -> Optional[PIIType]:
        return cls._by_name.get(name)
