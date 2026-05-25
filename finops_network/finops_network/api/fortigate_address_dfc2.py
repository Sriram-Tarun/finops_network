import frappe
import requests
import urllib3
urllib3.disable_warnings()

FIREWALL_IP = "45.198.225.153"
API_TOKEN   = "qxNNdGy3fg7d0ks0fhw99qNtkGgzpy"

def get_headers():
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }

COUNTRY_MAP = {
    "AF": "Afghanistan|AF", "AL": "Albania|AL", "DZ": "Algeria|DZ",
    "AD": "Andorra|AD", "AO": "Angola|AO", "AG": "Antigua and Barbuda|AG",
    "AR": "Argentina|AR", "AM": "Armenia|AM", "AU": "Australia|AU",
    "AT": "Austria|AT", "AZ": "Azerbaijan|AZ", "BS": "Bahamas|BS",
    "BH": "Bahrain|BH", "BD": "Bangladesh|BD", "BB": "Barbados|BB",
    "BY": "Belarus|BY", "BE": "Belgium|BE", "BZ": "Belize|BZ",
    "BJ": "Benin|BJ", "BT": "Bhutan|BT", "BO": "Bolivia|BO",
    "BA": "Bosnia and Herzegovina|BA", "BW": "Botswana|BW", "BR": "Brazil|BR",
    "BN": "Brunei|BN", "BG": "Bulgaria|BG", "BF": "Burkina Faso|BF",
    "BI": "Burundi|BI", "CV": "Cabo Verde|CV", "KH": "Cambodia|KH",
    "CM": "Cameroon|CM", "CA": "Canada|CA", "CF": "Central African Republic|CF",
    "TD": "Chad|TD", "CL": "Chile|CL", "CN": "China|CN", "CO": "Colombia|CO",
    "KM": "Comoros|KM", "CG": "Congo|CG", "CR": "Costa Rica|CR",
    "HR": "Croatia|HR", "CU": "Cuba|CU", "CY": "Cyprus|CY",
    "CZ": "Czech Republic|CZ", "DK": "Denmark|DK", "DJ": "Djibouti|DJ",
    "DM": "Dominica|DM", "DO": "Dominican Republic|DO", "EC": "Ecuador|EC",
    "EG": "Egypt|EG", "SV": "El Salvador|SV", "GQ": "Equatorial Guinea|GQ",
    "ER": "Eritrea|ER", "EE": "Estonia|EE", "SZ": "Eswatini|SZ",
    "ET": "Ethiopia|ET", "FJ": "Fiji|FJ", "FI": "Finland|FI",
    "FR": "France|FR", "GA": "Gabon|GA", "GM": "Gambia|GM",
    "GE": "Georgia|GE", "DE": "Germany|DE", "GH": "Ghana|GH",
    "GR": "Greece|GR", "GD": "Grenada|GD", "GT": "Guatemala|GT",
    "GN": "Guinea|GN", "GW": "Guinea-Bissau|GW", "GY": "Guyana|GY",
    "HT": "Haiti|HT", "HN": "Honduras|HN", "HU": "Hungary|HU",
    "IS": "Iceland|IS", "IN": "India|IN", "ID": "Indonesia|ID",
    "IR": "Iran|IR", "IQ": "Iraq|IQ", "IE": "Ireland|IE",
    "IL": "Israel|IL", "IT": "Italy|IT", "JM": "Jamaica|JM",
    "JP": "Japan|JP", "JO": "Jordan|JO", "KZ": "Kazakhstan|KZ",
    "KE": "Kenya|KE", "KI": "Kiribati|KI", "KW": "Kuwait|KW",
    "KG": "Kyrgyzstan|KG", "LA": "Laos|LA", "LV": "Latvia|LV",
    "LB": "Lebanon|LB", "LS": "Lesotho|LS", "LR": "Liberia|LR",
    "LY": "Libya|LY", "LI": "Liechtenstein|LI", "LT": "Lithuania|LT",
    "LU": "Luxembourg|LU", "MG": "Madagascar|MG", "MW": "Malawi|MW",
    "MY": "Malaysia|MY", "MV": "Maldives|MV", "ML": "Mali|ML",
    "MT": "Malta|MT", "MH": "Marshall Islands|MH", "MR": "Mauritania|MR",
    "MU": "Mauritius|MU", "MX": "Mexico|MX", "FM": "Micronesia|FM",
    "MD": "Moldova|MD", "MC": "Monaco|MC", "MN": "Mongolia|MN",
    "ME": "Montenegro|ME", "MA": "Morocco|MA", "MZ": "Mozambique|MZ",
    "MM": "Myanmar|MM", "NA": "Namibia|NA", "NR": "Nauru|NR",
    "NP": "Nepal|NP", "NL": "Netherlands|NL", "NZ": "New Zealand|NZ",
    "NI": "Nicaragua|NI", "NE": "Niger|NE", "NG": "Nigeria|NG",
    "NO": "Norway|NO", "OM": "Oman|OM", "PK": "Pakistan|PK",
    "PW": "Palau|PW", "PA": "Panama|PA", "PG": "Papua New Guinea|PG",
    "PY": "Paraguay|PY", "PE": "Peru|PE", "PH": "Philippines|PH",
    "PL": "Poland|PL", "PT": "Portugal|PT", "QA": "Qatar|QA",
    "RO": "Romania|RO", "RU": "Russia|RU", "RW": "Rwanda|RW",
    "KN": "Saint Kitts and Nevis|KN", "LC": "Saint Lucia|LC",
    "VC": "Saint Vincent and the Grenadines|VC", "WS": "Samoa|WS",
    "SM": "San Marino|SM", "ST": "Sao Tome and Principe|ST",
    "SA": "Saudi Arabia|SA", "SN": "Senegal|SN", "RS": "Serbia|RS",
    "SC": "Seychelles|SC", "SL": "Sierra Leone|SL", "SG": "Singapore|SG",
    "SK": "Slovakia|SK", "SI": "Slovenia|SI", "SB": "Solomon Islands|SB",
    "SO": "Somalia|SO", "ZA": "South Africa|ZA", "SS": "South Sudan|SS",
    "ES": "Spain|ES", "LK": "Sri Lanka|LK", "SD": "Sudan|SD",
    "SR": "Suriname|SR", "SE": "Sweden|SE", "CH": "Switzerland|CH",
    "SY": "Syria|SY", "TW": "Taiwan|TW", "TJ": "Tajikistan|TJ",
    "TZ": "Tanzania|TZ", "TH": "Thailand|TH", "TL": "Timor-Leste|TL",
    "TG": "Togo|TG", "TO": "Tonga|TO", "TT": "Trinidad and Tobago|TT",
    "TN": "Tunisia|TN", "TR": "Turkey|TR", "TM": "Turkmenistan|TM",
    "TV": "Tuvalu|TV", "UG": "Uganda|UG", "UA": "Ukraine|UA",
    "AE": "United Arab Emirates|AE", "GB": "United Kingdom|GB",
    "US": "United States|US", "UY": "Uruguay|UY", "UZ": "Uzbekistan|UZ",
    "VU": "Vanuatu|VU", "VE": "Venezuela|VE", "VN": "Vietnam|VN",
    "YE": "Yemen|YE", "ZM": "Zambia|ZM", "ZW": "Zimbabwe|ZW"
}

SKIP_NAMES = {"all", "none", "broadcat", "multicast", "224.0.0.0", "255.255.255.255"}


# ---------------------------------------------
# GET VDOMs
# ---------------------------------------------
@frappe.whitelist()
def get_vdoms():
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
    try:
        response = requests.get(url, headers=get_headers(), verify=False, timeout=15)
        if response.status_code == 200:
            vdoms = [v.get("name") for v in response.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error DFC2 Address")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# BUILD PAYLOAD
# ---------------------------------------------
def build_payload(doc):
    payload = {"name": doc.name1}
    if doc.type == "Subnet":
        payload["subnet"] = doc.ipnetmask
    elif doc.type == "FQDN":
        payload["type"] = "fqdn"
        payload["fqdn"] = doc.custom_fqdn
    elif doc.type == "Geography":
        payload["type"] = "geography"
        country = doc.custom_country__region or ""
        if "|" in country:
            country = country.split("|")[1]
        payload["country"] = country
    return payload


# ---------------------------------------------
# COMPOSITE UNIQUENESS CHECK
# ---------------------------------------------
@frappe.whitelist()
def validate_address_uniqueness(docname, name1, vdom):
    vdom = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 2 Address",
        {"name1": name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != docname:
        return {"status": "duplicate", "message": f"Address '{name1}' already exists in VDOM '{vdom}'"}
    return {"status": "ok"}


# ---------------------------------------------
# FRAPPE VALIDATE HOOK
# ---------------------------------------------
def validate(doc, method=None):
    vdom = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 2 Address",
        {"name1": doc.name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != doc.name:
        frappe.throw(
            f"Address <b>{doc.name1}</b> already exists in VDOM <b>{vdom}</b>.",
            title="Duplicate Address"
        )


# ---------------------------------------------
# CREATE ADDRESS
# ---------------------------------------------
@frappe.whitelist()
def create_address(docname):
    doc = frappe.get_doc("DFC 2 Address", docname)
    vdom = doc.custom_virtual_domain or "root"
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address?vdom={vdom}"
    try:
        response = requests.post(url, headers=get_headers(), json=build_payload(doc), verify=False, timeout=20)
        if response.status_code == 200:
            return {"status": "success", "message": f"Address created successfully in FortiGate (VDOM: {vdom})"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Address Create Error DFC2")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# UPDATE ADDRESS
# ---------------------------------------------
@frappe.whitelist()
def update_address(docname):
    doc = frappe.get_doc("DFC 2 Address", docname)
    vdom = doc.custom_virtual_domain or "root"
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address/{doc.name1}?vdom={vdom}"
    try:
        response = requests.put(url, headers=get_headers(), json=build_payload(doc), verify=False, timeout=20)
        if response.status_code == 200:
            return {"status": "success", "message": f"Address updated successfully in FortiGate (VDOM: {vdom})"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Address Update Error DFC2")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# RESOLVE COUNTRY CODE
# ---------------------------------------------
def resolve_country(country_code):
    if not country_code:
        return ""
    if "|" in country_code:
        return country_code
    if len(country_code) == 2:
        return COUNTRY_MAP.get(country_code.upper(), "")
    for code, value in COUNTRY_MAP.items():
        if value.split("|")[0].upper() == country_code.upper():
            return value
    return ""


# ---------------------------------------------
# PROCESS ONE ADDRESS RECORD
# ---------------------------------------------
def process_address(addr, vdom, created_ref, updated_ref, skipped_ref):
    name = (addr.get("name") or "").strip()

    if not name or name in SKIP_NAMES or name.startswith("FABRIC_"):
        skipped_ref[0] += 1
        return

    addr_type    = addr.get("type", "ipmask")
    ip           = addr.get("subnet", "").replace(" ", "/")
    fqdn         = addr.get("fqdn", "")
    country_code = addr.get("country", "")

    if addr_type == "fqdn":
        frappe_type = "FQDN"
    elif addr_type == "geography":
        frappe_type = "Geography"
        country = resolve_country(country_code)
        if not country:
            skipped_ref[0] += 1
            return
    else:
        frappe_type = "Subnet"
        country = ""

    if addr_type == "geography":
        country = resolve_country(country_code)
    else:
        country = ""

    existing = frappe.db.get_value(
        "DFC 2 Address",
        {"name1": name, "custom_virtual_domain": vdom},
        "name"
    )

    if existing:
        try:
            update_data = {"type": frappe_type, "custom_virtual_domain": vdom}
            if frappe_type == "Subnet":
                update_data["ipnetmask"] = ip
            elif frappe_type == "FQDN":
                update_data["custom_fqdn"] = fqdn
            elif frappe_type == "Geography":
                update_data["custom_country__region"] = country
            frappe.db.set_value("DFC 2 Address", existing, update_data)
            updated_ref[0] += 1
        except Exception as e:
            frappe.log_error(str(e), f"DFC2 Address Update Error: {existing}")
    else:
        try:
            new_doc = {
                "doctype": "DFC 2 Address",
                "name1": name,
                "type": frappe_type,
                "custom_virtual_domain": vdom
            }
            if frappe_type == "Subnet":
                new_doc["ipnetmask"] = ip
            elif frappe_type == "FQDN":
                new_doc["custom_fqdn"] = fqdn
            elif frappe_type == "Geography":
                new_doc["custom_country__region"] = country
            frappe.get_doc(new_doc).insert(ignore_permissions=True, ignore_mandatory=True)
            created_ref[0] += 1
        except Exception as e:
            frappe.log_error(str(e), f"DFC2 Address Insert Error: {name} / {vdom}")


# ---------------------------------------------
# SYNC — loop all VDOMs (7.6.2 address endpoint
# DOES filter by vdom, unlike interfaces)
# ---------------------------------------------
@frappe.whitelist()
def sync_addresses_from_fortigate():
    created  = [0]
    updated  = [0]
    skipped  = [0]
    vdoms_synced = []

    try:
        # Step 1: get all VDOMs
        vdom_resp = requests.get(
            f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom",
            headers=get_headers(), verify=False, timeout=15
        )
        if vdom_resp.status_code == 200:
            vdom_list = [v.get("name") for v in vdom_resp.json().get("results", []) if v.get("name")]
        else:
            vdom_list = ["root"]

        # Step 2: fetch addresses per VDOM
        for vdom in vdom_list:
            try:
                resp = requests.get(
                    f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address?vdom={vdom}",
                    headers=get_headers(), verify=False, timeout=20
                )
                if resp.status_code != 200:
                    frappe.log_error(f"HTTP {resp.status_code}: {resp.text[:200]}", f"DFC2 Address Sync VDOM: {vdom}")
                    continue

                results = resp.json().get("results", [])
                for addr in results:
                    process_address(addr, vdom, created, updated, skipped)

                vdoms_synced.append(vdom)

            except Exception as e:
                frappe.log_error(str(e), f"DFC2 Address Sync Error VDOM: {vdom}")
                continue

        frappe.db.commit()
        return {
            "status": "success",
            "created": created[0],
            "updated": updated[0],
            "skipped": skipped[0],
            "vdoms_synced": vdoms_synced
        }

    except Exception as e:
        frappe.log_error(str(e), "FortiGate Address Sync Fatal Error DFC2")
        return {"status": "error", "message": str(e)}
