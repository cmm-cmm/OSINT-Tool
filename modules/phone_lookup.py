"""
Phone Number Intelligence Module
Uses the `phonenumbers` library (offline) for number plan data analysis.
All analysis is based on publicly available number plan data.
"""
import phonenumbers
from phonenumbers import geocoder, carrier, timezone, NumberParseException
from rich.console import Console
from rich.table import Table
import requests

console = Console()
HEADERS = {"User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)"}

# Vietnamese carrier prefix map (E.164 national number without country code)
# Source: VNPT/Viettel/MobiFone number plan published by BTTTT
_VN_CARRIER_MAP = {
    # Viettel
    "032": "Viettel", "033": "Viettel", "034": "Viettel", "035": "Viettel",
    "036": "Viettel", "037": "Viettel", "038": "Viettel", "039": "Viettel",
    "086": "Viettel", "096": "Viettel", "097": "Viettel", "098": "Viettel",
    # Mobifone
    "070": "Mobifone", "076": "Mobifone", "077": "Mobifone", "078": "Mobifone",
    "079": "Mobifone", "089": "Mobifone", "090": "Mobifone", "093": "Mobifone",
    # Vinaphone (VNPT)
    "081": "Vinaphone", "082": "Vinaphone", "083": "Vinaphone", "084": "Vinaphone",
    "085": "Vinaphone", "091": "Vinaphone", "094": "Vinaphone",
    # Vietnamobile
    "052": "Vietnamobile", "056": "Vietnamobile", "058": "Vietnamobile",
    "092": "Vietnamobile",
    # Gmobile
    "059": "Gmobile", "099": "Gmobile",
    # Reddi (Indochina Telecom)
    "055": "Reddi",
    # Fixed lines VNPT
    "024": "VNPT (Hà Nội landline)", "028": "VNPT (TP.HCM landline)",
}


def _detect_vn_carrier(national_number: str) -> str | None:
    """Map Vietnamese national number (without +84) to carrier name."""
    # Convert 0xxx format or 84xxx format to prefix
    num = national_number.replace(" ", "").replace("-", "")
    if num.startswith("84"):
        num = "0" + num[2:]
    prefix = num[:3]
    return _VN_CARRIER_MAP.get(prefix)


def analyze_phone(phone_number: str, default_region: str = "VN") -> dict:
    """Offline analysis using E.164 number plan data."""
    result = {"input": phone_number, "error": None}
    try:
        parsed = phonenumbers.parse(phone_number, default_region)
        national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        lib_carrier = carrier.name_for_number(parsed, "en")

        # VN carrier override — phonenumbers lib has incomplete VN carrier data
        vn_carrier = None
        if parsed.country_code == 84:
            vn_carrier = _detect_vn_carrier(national)

        result.update({
            "valid": phonenumbers.is_valid_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
            "e164_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": national,
            "country_code": parsed.country_code,
            "country": geocoder.description_for_number(parsed, "en"),
            "carrier": vn_carrier or lib_carrier or "Unknown",
            "timezones": list(timezone.time_zones_for_number(parsed)),
            "number_type": _get_number_type(parsed),
        })
    except NumberParseException as e:
        result["error"] = str(e)
    return result


def _get_number_type(parsed) -> str:
    type_map = {
        phonenumbers.PhoneNumberType.MOBILE: "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        phonenumbers.PhoneNumberType.VOIP: "VoIP",
        phonenumbers.PhoneNumberType.PAGER: "Pager",
        phonenumbers.PhoneNumberType.UAN: "UAN",
        phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
    }
    return type_map.get(phonenumbers.number_type(parsed), "Unknown")


def generate_phone_search_links(phone_e164: str) -> dict:
    clean = phone_e164.replace("+", "").replace(" ", "")
    encoded_full = requests.utils.quote(phone_e164)
    return {
        "Google": f"https://www.google.com/search?q=%22{encoded_full}%22",
        "Truecaller": f"https://www.truecaller.com/search/vn/{clean}",
        "PhoneBook.cz": f"https://phonebook.cz/?q={clean}&s=phonenumber",
        "Sync.me": f"https://sync.me/search/?number={clean}",
        "NumLookup": f"https://www.numlookup.com/?number={encoded_full}",
    }


def phone_lookup(phone_number: str, region: str = "VN") -> dict:
    data = analyze_phone(phone_number, default_region=region)
    if data.get("error"):
        return data

    data["search_links"] = generate_phone_search_links(data["e164_format"])
    return data


def print_phone_results(data: dict):
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        return

    console.print(f"\n[bold cyan]═══ PHONE INTELLIGENCE: {data['input']} ═══[/bold cyan]")

    valid_icon = "[green]✓ Valid[/green]" if data.get("valid") else "[red]✗ Invalid[/red]"
    console.print(f"  Status      : {valid_icon}")
    console.print(f"  E.164       : {data.get('e164_format', 'N/A')}")
    console.print(f"  International: {data.get('international', 'N/A')}")
    console.print(f"  Country     : {data.get('country', 'N/A')} (+{data.get('country_code', '')})")
    console.print(f"  Type        : {data.get('number_type', 'N/A')}")
    if data.get("carrier"):
        console.print(f"  Carrier     : {data['carrier']}")
    if data.get("timezones"):
        console.print(f"  Timezones   : {', '.join(data['timezones'])}")

    console.print("\n  [bold]Search Links:[/bold]")
    for name, url in data.get("search_links", {}).items():
        console.print(f"    {name:16}: [link]{url}[/link]")
