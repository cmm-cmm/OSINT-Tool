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


def check_veriphone(phone_e164: str) -> dict:
    """Query Veriphone.io for live carrier & line-type (100/day free, no API key needed)."""
    try:
        resp = requests.get(
            "https://api.veriphone.io/v2/verify",
            params={"phone": phone_e164},
            headers=HEADERS,
            timeout=10,
        )
        if resp.status_code == 200:
            d = resp.json()
            if d.get("status") == "success":
                return {
                    "success": True,
                    "valid": d.get("phone_valid", False),
                    "country": d.get("country"),
                    "country_code": d.get("country_code"),
                    "carrier": d.get("carrier"),
                    "line_type": d.get("phone_type"),
                    "local_format": d.get("phone"),
                    "international_format": d.get("international_number"),
                }
            return {"success": False, "error": d.get("message", "Invalid number")}
        return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_numverify(phone_e164: str, api_key: str) -> dict:
    """Query APILayer Number Verification API for live carrier and line-type data (1000 free req/month)."""
    url = "https://api.apilayer.com/number_verification/validate"
    try:
        resp = requests.get(
            url,
            params={"number": phone_e164},
            headers={**HEADERS, "apikey": api_key},
            timeout=10,
        )
        if resp.status_code == 200:
            d = resp.json()
            if not d.get("valid"):
                return {"success": True, "valid": False, "error": "Number invalid or not found"}
            return {
                "success": True,
                "valid": True,
                "local_format": d.get("local_format"),
                "international_format": d.get("international_format"),
                "country_prefix": d.get("country_prefix"),
                "country_code": d.get("country_code"),
                "country_name": d.get("country_name"),
                "location": d.get("location"),
                "carrier": d.get("carrier"),
                "line_type": d.get("line_type"),
            }
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def generate_phone_search_links(phone_e164: str, country_code: int = None) -> dict:
    clean = phone_e164.replace("+", "").replace(" ", "")
    encoded_full = requests.utils.quote(phone_e164)
    is_vn = country_code == 84

    links: dict = {
        "Google": f"https://www.google.com/search?q=%22{encoded_full}%22",
        "Bing": f"https://www.bing.com/search?q=%22{encoded_full}%22",
        "Truecaller": (
            f"https://www.truecaller.com/search/vn/{clean}"
            if is_vn else
            f"https://www.truecaller.com/search/{clean}"
        ),
        "GetContact": f"https://web.getcontact.com/search/{clean}",
        "PhoneBook.cz": f"https://phonebook.cz/?q={clean}&s=phonenumber",
        "Sync.me": f"https://sync.me/search/?number={clean}",
        "NumLookup": f"https://www.numlookup.com/?number={encoded_full}",
        "WhoCalledMe": f"https://www.whocalledme.com/PhoneNumber/{clean}",
        "SpamCalls": f"https://www.spamcalls.net/en/search?phone={clean}&provider=spam",
    }
    if is_vn:
        # Convert to national format 0xxxxxxxxx
        national = clean.lstrip("84")
        if not national.startswith("0"):
            national = "0" + national
        links["Zalo Search"] = (
            f"https://www.google.com/search?q=%22{requests.utils.quote(national)}%22"
            "+site%3Azalo.me+OR+site%3Afacebook.com"
        )
        links["1900.com.vn"] = f"https://1900.com.vn/so-dien-thoai/{national}"
        links["DanTri"] = (
            f"https://www.google.com/search?q=%22{requests.utils.quote(national)}%22"
            "+site%3Adantri.com.vn+OR+site%3Avnexpress.net"
        )
    return links


def phone_lookup(phone_number: str, region: str = "VN", numverify_key: str = None) -> dict:
    data = analyze_phone(phone_number, default_region=region)
    if data.get("error"):
        return data

    cc = data.get("country_code")
    data["search_links"] = generate_phone_search_links(data["e164_format"], country_code=cc)

    # Veriphone — free 100/day, no key
    data["veriphone"] = check_veriphone(data["e164_format"])

    if numverify_key:
        data["numverify"] = check_numverify(data["e164_format"], numverify_key)

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

    # Veriphone live enrichment (free)
    vp = data.get("veriphone", {})
    if vp.get("success") and vp.get("valid"):
        console.print(f"\n  [bold]Veriphone.io (live, free):[/bold]")
        if vp.get("line_type"):
            console.print(f"    Line Type : [cyan]{vp['line_type']}[/cyan]")
        if vp.get("carrier"):
            console.print(f"    Carrier   : {vp['carrier']}")
        if vp.get("country"):
            console.print(f"    Country   : {vp['country']}")
    elif vp.get("error"):
        console.print(f"\n  [dim]Veriphone: {vp['error']}[/dim]")

    # NumVerify live enrichment
    nv = data.get("numverify", {})
    if nv:
        if nv.get("success") and nv.get("valid"):
            console.print(f"\n  [bold]NumVerify (live):[/bold]")
            if nv.get("line_type"):
                console.print(f"    Line Type : [cyan]{nv['line_type']}[/cyan]")
            if nv.get("carrier") and nv.get("carrier") != data.get("carrier"):
                console.print(f"    Carrier   : {nv['carrier']}")
            if nv.get("location"):
                console.print(f"    Location  : {nv['location']}")
            if nv.get("country_name"):
                console.print(f"    Country   : {nv['country_name']}")
        elif nv.get("error"):
            console.print(f"\n  [dim]NumVerify: {nv['error']}[/dim]")

    console.print("\n  [bold]Search Links:[/bold]")
    for name, url in data.get("search_links", {}).items():
        console.print(f"    {name:16}: [link]{url}[/link]")
