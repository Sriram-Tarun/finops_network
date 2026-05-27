import frappe
import requests
import urllib3
urllib3.disable_warnings()

FIREWALL_IP = "45.198.225.33"
API_TOKEN   = "ryGrNswGtt7cqj577fNr0x7fqGH5j1"

def get_headers():
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }


# ---------------------------------------------
# GET VDOMs FROM FORTIGATE
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
        frappe.log_error(str(e), "FortiGate Get VDOMs Error DFC1 Address")
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
        country = doc.custom_country__region
        if "|" in country:
            country = country.split("|")[1]
        payload["country"] = country

    return payload


# ---------------------------------------------
# COMPOSITE UNIQUENESS CHECK (server-side)
# ---------------------------------------------
@frappe.whitelist()
def validate_address_uniqueness(docname, name1, vdom):
    vdom = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 1 Address",
        {"name1": name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != docname:
        return {
            "status": "duplicate",
            "message": f"Address '{name1}' already exists in VDOM '{vdom}'"
        }
    return {"status": "ok"}


# ---------------------------------------------
# FRAPPE VALIDATE HOOK — blocks duplicate save
# ---------------------------------------------
def validate(doc, method=None):
    vdom = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 1 Address",
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
    doc = frappe.get_doc("DFC 1 Address", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address?vdom={vdom}"
    try:
        response = requests.post(url, headers=get_headers(), json=build_payload(doc), verify=False, timeout=20)
        if response.status_code == 200:
            return {"status": "success", "message": f"Address created successfully in FortiGate (VDOM: {vdom})"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Address Create Error DFC1")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# UPDATE ADDRESS
# ---------------------------------------------
@frappe.whitelist()
def update_address(docname):
    doc  = frappe.get_doc("DFC 1 Address", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address/{doc.name}?vdom={vdom}"
    try:
        response = requests.put(url, headers=get_headers(), json=build_payload(doc), verify=False, timeout=20)
        if response.status_code == 200:
            return {"status": "success", "message": f"Address updated successfully in FortiGate (VDOM: {vdom})"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Address Update Error DFC1")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# SYNC ADDRESSES FROM FORTIGATE (ALL VDOMs)
# ---------------------------------------------
@frappe.whitelist()
def sync_addresses_from_fortigate():

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

    created = 0
    updated = 0
    skipped = 0
    vdoms_synced = []

    try:
        vdom_url      = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
        vdom_response = requests.get(vdom_url, headers=get_headers(), verify=False, timeout=15)

        if vdom_response.status_code == 200:
            vdom_list = [v.get("name") for v in vdom_response.json().get("results", []) if v.get("name")]
        else:
            vdom_list = ["root"]

        for vdom in vdom_list:
            addr_url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address?vdom={vdom}"
            try:
                response = requests.get(addr_url, headers=get_headers(), verify=False, timeout=15)
                data     = response.json()
            except Exception as e:
                frappe.log_error(str(e), f"DFC1 Address Sync Error - VDOM: {vdom}")
                continue

            vdoms_synced.append(vdom)

            for addr in data.get("results", []):
                name = addr.get("name", "").strip()

                if not name:
                    skipped += 1
                    continue

                if name.startswith("FABRIC_") or name in [
                    "all", "none", "broadcat", "multicast",
                    "224.0.0.0", "255.255.255.255"
                ]:
                    skipped += 1
                    continue

                addr_type    = addr.get("type", "ipmask")
                ip           = addr.get("subnet", "").replace(" ", "/")
                fqdn         = addr.get("fqdn", "")
                country_code = addr.get("country", "")

                country = ""
                if "|" in country_code:
                    country = country_code
                elif len(country_code) == 2:
                    country = COUNTRY_MAP.get(country_code.upper(), "")
                else:
                    for code, value in COUNTRY_MAP.items():
                        if value.split("|")[0].upper() == country_code.upper():
                            country = value
                            break

                if addr_type == "fqdn":
                    frappe_type = "FQDN"
                elif addr_type == "geography":
                    frappe_type = "Geography"
                    if not country:
                        skipped += 1
                        continue
                else:
                    frappe_type = "Subnet"

                existing = frappe.db.get_value(
                    "DFC 1 Address",
                    {"name1": name, "custom_virtual_domain": vdom},
                    "name"
                )

                if existing:
                    doc = frappe.get_doc("DFC 1 Address", existing)
                    doc.type                  = frappe_type
                    doc.custom_virtual_domain = vdom
                    if frappe_type == "Subnet":
                        doc.ipnetmask = ip
                    elif frappe_type == "FQDN":
                        doc.custom_fqdn = fqdn
                    elif frappe_type == "Geography":
                        doc.custom_country__region = country
                    doc.flags.ignore_validate = True
                    doc.save(ignore_permissions=True)
                    updated += 1
                else:
                    new_doc = {
                        "doctype":              "DFC 1 Address",
                        "name1":                name,
                        "type":                 frappe_type,
                        "custom_virtual_domain": vdom
                    }
                    if frappe_type == "Subnet":
                        new_doc["ipnetmask"] = ip
                    elif frappe_type == "FQDN":
                        new_doc["custom_fqdn"] = fqdn
                    elif frappe_type == "Geography":
                        new_doc["custom_country__region"] = country

                    doc = frappe.get_doc(new_doc)
                    doc.flags.ignore_validate = True
                    doc.insert(ignore_permissions=True)
                    created += 1

        frappe.db.commit()
        return {
            "status":       "success",
            "created":      created,
            "updated":      updated,
            "skipped":      skipped,
            "vdoms_synced": vdoms_synced
        }

    except Exception as e:
        frappe.log_error(str(e), "FortiGate Address Sync Error DFC1")
        return {"status": "error", "message": str(e)}
