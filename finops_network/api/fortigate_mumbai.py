import frappe
import requests
import time

FIREWALL_IP = "103.216.92.148"
API_TOKEN   = "G8mqG51fQbgN5tk1Nnmy4mGtHwhxc0"


def get_headers():
    return {"Authorization": f"Bearer {API_TOKEN}"}


def get_headers_json():
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type":  "application/json"
    }


def get_raw_name(doc_name):
    if "(" in doc_name and doc_name.endswith(")"):
        return doc_name[doc_name.rfind("(") + 1:-1]
    return doc_name


# ---------------------------------------------
# CREATE INTERFACE
# ---------------------------------------------
@frappe.whitelist()
def create_interface(docname):
    doc         = frappe.get_doc("DFC 1 Mumbai Interface", docname)
    target_vdom = doc.virtual_domain or "root"
    url         = f"https://{FIREWALL_IP}/api/v2/cmdb/system/interface?vdom={target_vdom}"

    raw_name     = get_raw_name(doc.name)
    ip_formatted = (doc.ipnetmask or "").replace("/", " ")

    payload = {
        "name":         raw_name,
        "type":         "vlan",
        "interface":    doc.interface,
        "vlanid":       int(doc.vlan_id),
        "role":         "lan",
        "vlan_protocol":"8021q",
        "ip":           ip_formatted,
        "allowaccess":  "ping",
        "vdom":         target_vdom
    }
    if doc.alias:
        payload["alias"] = doc.alias

    try:
        response = requests.post(url, headers=get_headers_json(), json=payload, verify=False, timeout=10)
        return {"status_code": response.status_code, "response": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate API Error Mumbai")
        return str(e)


# ---------------------------------------------
# UPDATE INTERFACE
# ---------------------------------------------
@frappe.whitelist()
def update_interface(docname):
    doc            = frappe.get_doc("DFC 1 Mumbai Interface", docname)
    target_vdom    = doc.virtual_domain or "root"
    raw_name       = get_raw_name(doc.name)
    url            = f"https://{FIREWALL_IP}/api/v2/cmdb/system/interface/{raw_name}?vdom={target_vdom}"

    payload = {"ip": doc.ipnetmask, "allowaccess": "ping"}
    payload["alias"] = doc.alias if doc.alias else ""

    try:
        response = requests.put(url, headers=get_headers_json(), json=payload, verify=False, timeout=10)
        return {"status_code": response.status_code, "response": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate Update Error Mumbai")
        return str(e)


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
        frappe.log_error(str(e), "FortiGate Get VDOMs Error Mumbai")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# GET INTERFACES FROM FORTIGATE
# ---------------------------------------------
@frappe.whitelist()
def get_interfaces_from_fortigate(vdom="root"):
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/system/interface?vdom={vdom}"
    try:
        response = requests.get(url, headers=get_headers(), verify=False, timeout=15)
        data     = response.json()
        return [
            {"name": iface.get("name"), "type": iface.get("type")}
            for iface in data.get("results", [])
        ]
    except Exception as e:
        frappe.log_error(str(e), "Fetch Interface List Error Mumbai")
        return []


# ---------------------------------------------
# SYNC INTERFACES FROM FORTIGATE
# ---------------------------------------------
@frappe.whitelist()
def sync_interfaces_from_fortigate():
    created = 0
    updated = 0

    try:
        # Fetch all interfaces in one call (no vdom filter) — same as DFC 2 pattern
        response = requests.get(
            f"https://{FIREWALL_IP}/api/v2/cmdb/system/interface",
            headers=get_headers(), verify=False, timeout=30
        )
        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}", "body": response.text[:200]}

        data    = response.json()
        results = data.get("results", []) if isinstance(data, dict) else []

        for iface in results:
            if iface.get("type") != "vlan":
                continue

            raw_name   = iface.get("name") or ""
            alias_val  = iface.get("alias") or ""
            parent     = iface.get("interface") or ""
            vlan_id    = iface.get("vlanid")
            iface_vdom = iface.get("vdom") or "root"

            if not raw_name or not parent or not vlan_id or int(vlan_id) == 0:
                continue

            name = f"{alias_val} ({raw_name})" if alias_val else raw_name

            ip = iface.get("ip", "")
            if isinstance(ip, str) and " " in ip:
                ip = ip.replace(" ", "/")

            existing = frappe.db.exists("DFC 1 Mumbai Interface", {
                "interface":      parent,
                "vlan_id":        vlan_id,
                "virtual_domain": iface_vdom
            })

            if existing:
                doc = frappe.get_doc("DFC 1 Mumbai Interface", existing)

                if not doc.name1 or doc.name1 != name:
                    # Name changed — delete and re-insert
                    try:
                        doc.delete(ignore_permissions=True)
                        frappe.get_doc({
                            "doctype":        "DFC 1 Mumbai Interface",
                            "name1":          name,
                            "alias":          alias_val,
                            "interface":      parent,
                            "vlan_id":        vlan_id,
                            "ipnetmask":      ip,
                            "virtual_domain": iface_vdom
                        }).insert(ignore_permissions=True, ignore_mandatory=True)
                        updated += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"Mumbai Reinsert Error: {existing} -> {name}")
                else:
                    # Name unchanged — use db.set_value to bypass mandatory
                    try:
                        frappe.db.set_value("DFC 1 Mumbai Interface", existing, {
                            "alias":          alias_val,
                            "interface":      parent,
                            "vlan_id":        vlan_id,
                            "ipnetmask":      ip,
                            "virtual_domain": iface_vdom
                        })
                        updated += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"Mumbai Update Error: {existing}")
            else:
                try:
                    frappe.get_doc({
                        "doctype":        "DFC 1 Mumbai Interface",
                        "name1":          name,
                        "alias":          alias_val,
                        "interface":      parent,
                        "vlan_id":        vlan_id,
                        "ipnetmask":      ip,
                        "virtual_domain": iface_vdom
                    }).insert(ignore_permissions=True, ignore_mandatory=True)
                    created += 1
                except Exception as e:
                    frappe.log_error(str(e), f"Mumbai Insert Error: {name}")

        frappe.db.commit()
        return {"created": created, "updated": updated}

    except Exception as e:
        frappe.log_error(str(e), "FortiGate Sync Error Mumbai")
        return str(e)


# =============================================
# ADDRESS FUNCTIONS
# =============================================

def build_address_payload(doc):
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


@frappe.whitelist()
def validate_address_uniqueness(docname, name1, vdom):
    vdom     = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 1 Mumbai Address",
        {"name1": name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != docname:
        return {
            "status":  "duplicate",
            "message": f"Address '{name1}' already exists in VDOM '{vdom}'"
        }
    return {"status": "ok"}


def validate_address(doc, method=None):
    vdom     = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 1 Mumbai Address",
        {"name1": doc.name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != doc.name:
        frappe.throw(
            f"Address <b>{doc.name1}</b> already exists in VDOM <b>{vdom}</b>.",
            title="Duplicate Address"
        )


@frappe.whitelist()
def create_address(docname):
    doc  = frappe.get_doc("DFC 1 Mumbai Address", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address?vdom={vdom}"
    try:
        response = requests.post(
            url, headers=get_headers_json(),
            json=build_address_payload(doc), verify=False, timeout=20
        )
        if response.status_code == 200:
            return {"status": "success", "message": f"Address created successfully in FortiGate (VDOM: {vdom})"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Address Create Error Mumbai")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def update_address(docname):
    doc  = frappe.get_doc("DFC 1 Mumbai Address", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address/{doc.name}?vdom={vdom}"
    try:
        response = requests.put(
            url, headers=get_headers_json(),
            json=build_address_payload(doc), verify=False, timeout=20
        )
        if response.status_code == 200:
            return {"status": "success", "message": f"Address updated successfully in FortiGate (VDOM: {vdom})"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Address Update Error Mumbai")
        return {"status": "error", "message": str(e)}


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

    created      = 0
    updated      = 0
    skipped      = 0
    vdoms_synced = []

    try:
        vdom_url      = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
        vdom_response = requests.get(vdom_url, headers=get_headers_json(), verify=False, timeout=15)

        vdom_list = (
            [v.get("name") for v in vdom_response.json().get("results", []) if v.get("name")]
            if vdom_response.status_code == 200
            else ["root"]
        )

        for vdom in vdom_list:
            addr_url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address?vdom={vdom}"
            try:
                response = requests.get(addr_url, headers=get_headers_json(), verify=False, timeout=15)
                data     = response.json()
            except Exception as e:
                frappe.log_error(str(e), f"Mumbai Address Sync Error - VDOM: {vdom}")
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
                    "DFC 1 Mumbai Address",
                    {"name1": name, "custom_virtual_domain": vdom},
                    "name"
                )

                if existing:
                    # Use db.set_value to bypass mandatory validation
                    update_data = {
                        "type":                 frappe_type,
                        "custom_virtual_domain": vdom
                    }
                    if frappe_type == "Subnet":
                        update_data["ipnetmask"] = ip
                    elif frappe_type == "FQDN":
                        update_data["custom_fqdn"] = fqdn
                    elif frappe_type == "Geography":
                        update_data["custom_country__region"] = country

                    frappe.db.set_value("DFC 1 Mumbai Address", existing, update_data)
                    updated += 1

                else:
                    new_doc = {
                        "doctype":              "DFC 1 Mumbai Address",
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

                    try:
                        doc = frappe.get_doc(new_doc)
                        doc.flags.ignore_validate = True
                        doc.insert(ignore_permissions=True, ignore_mandatory=True)
                        created += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"Mumbai Address Insert Error: {name}")
                        skipped += 1

        frappe.db.commit()
        return {
            "status":       "success",
            "created":      created,
            "updated":      updated,
            "skipped":      skipped,
            "vdoms_synced": vdoms_synced
        }

    except Exception as e:
        frappe.log_error(str(e), "FortiGate Address Sync Error Mumbai")
        return {"status": "error", "message": str(e)}


# =============================================
# POLICY FUNCTIONS
# =============================================
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = f"https://{FIREWALL_IP}/api/v2/cmdb"


def extract_raw_interface_name(display_name):
    if display_name and "(" in display_name and display_name.endswith(")"):
        return display_name[display_name.rfind("(") + 1:-1].strip()
    return (display_name or "").strip()


def _build_interface_map_mumbai(vdom):
    try:
        r = requests.get(
            f"{BASE_URL}/system/interface?vdom={vdom}",
            headers=get_headers(), verify=False, timeout=15
        )
        iface_map = {}
        for iface in r.json().get("results", []):
            raw_name  = iface.get("name") or ""
            alias_val = iface.get("alias") or ""
            if not raw_name:
                continue
            display = f"{alias_val} ({raw_name})" if alias_val else raw_name
            iface_map[raw_name] = display
        return iface_map
    except Exception:
        return {}


def _fetch_policies_mumbai(vdom):
    try:
        r = requests.get(
            f"{BASE_URL}/firewall/policy?vdom={vdom}",
            headers=get_headers(), verify=False, timeout=30
        )
        return r.json().get("results", [])
    except Exception:
        return []


def _fetch_one_address_endpoint_mumbai(url):
    try:
        r = requests.get(url, headers=get_headers(), verify=False, timeout=15)
        if r.status_code == 200:
            return [
                item.get("name") for item in r.json().get("results", [])
                if item.get("name")
            ]
    except Exception:
        pass
    return []


@frappe.whitelist()
def get_policy_vdoms():
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
    try:
        r = requests.get(url, headers=get_headers(), verify=False, timeout=15)
        if r.status_code == 200:
            vdoms = [v.get("name") for v in r.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": r.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error Mumbai Policy")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def get_policy_interfaces(vdom="root"):
    try:
        r = requests.get(
            f"{BASE_URL}/system/interface?vdom={vdom}",
            headers=get_headers(), verify=False, timeout=15
        )
        result = []
        for i in r.json().get("results", []):
            raw_name   = i.get("name") or ""
            alias_val  = i.get("alias") or ""
            iface_vdom = i.get("vdom") or ""
            if not raw_name or iface_vdom != vdom:
                continue
            display = f"{alias_val} ({raw_name})" if alias_val else raw_name
            result.append(display)
        return result
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Interface Fetch Error Mumbai Policy")
        return []


@frappe.whitelist()
def get_policy_addresses(vdom="root"):
    endpoints = [
        f"{BASE_URL}/firewall/address?vdom={vdom}",
        f"{BASE_URL}/firewall/addrgrp?vdom={vdom}",
        f"{BASE_URL}/firewall/vip?vdom={vdom}",
        f"{BASE_URL}/firewall/vipgrp?vdom={vdom}",
    ]
    all_names = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_fetch_one_address_endpoint_mumbai, url): url for url in endpoints}
        for future in as_completed(futures):
            try:
                all_names.extend(future.result())
            except Exception as e:
                frappe.log_error(str(e), "Fortigate Address Fetch Error Mumbai Policy")

    seen   = set()
    result = []
    for name in all_names:
        if not name or name.strip().lower() == "all":
            continue
        if name not in seen:
            seen.add(name)
            result.append(name)
    return sorted(result)


@frappe.whitelist()
def get_policy_ip_pools(vdom="root"):
    try:
        r = requests.get(
            f"{BASE_URL}/firewall/ippool?vdom={vdom}",
            headers=get_headers(), verify=False, timeout=15
        )
        return [p.get("name") for p in r.json().get("results", []) if p.get("name")]
    except Exception as e:
        frappe.log_error(str(e), "Fortigate IP Pool Fetch Error Mumbai Policy")
        return []


@frappe.whitelist()
def get_policy_services(vdom="root"):
    services = []
    endpoints = [
        f"{BASE_URL}/firewall.service/custom?vdom={vdom}",
        f"{BASE_URL}/firewall.service/group?vdom={vdom}",
    ]
    try:
        for ep in endpoints:
            r = requests.get(ep, headers=get_headers(), verify=False, timeout=15)
            for svc in r.json().get("results", []):
                if svc.get("name"):
                    services.append(svc["name"])

        r = requests.get(
            f"{BASE_URL}/firewall.service/category?vdom={vdom}",
            headers=get_headers(), verify=False, timeout=15
        )
        for cat in r.json().get("results", []):
            for m in cat.get("member", []):
                if m.get("name"):
                    services.append(m["name"])

        services = sorted(set(filter(None, services)))

        for svc_name in services:
            unique_name = f"{svc_name}-{vdom}"
            if frappe.db.exists("DFC 1 Mumbai Service", unique_name):
                continue
            if frappe.db.exists("DFC 1 Mumbai Service", svc_name):
                continue
            try:
                svc_doc                       = frappe.new_doc("DFC 1 Mumbai Service")
                svc_doc.name                  = unique_name
                svc_doc.service_name          = svc_name
                svc_doc.custom_virtual_domain = vdom
                svc_doc.insert(ignore_permissions=True)
            except Exception as e:
                frappe.log_error(str(e), f"Mumbai Service Insert: {unique_name}")

        frappe.db.commit()
        return services

    except Exception as e:
        frappe.log_error(str(e), "Fortigate Services Fetch Error Mumbai Policy")
        return []


@frappe.whitelist()
def validate_policy_uniqueness(docname, policy_name, vdom):
    vdom     = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 1 Mumbai Policy",
        {"policy_name": policy_name, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != docname:
        return {
            "status":  "duplicate",
            "message": f"Policy '{policy_name}' already exists in VDOM '{vdom}'"
        }
    return {"status": "ok"}


def validate_policy(doc, method=None):
    vdom     = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 1 Mumbai Policy",
        {"policy_name": doc.policy_name, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != doc.name:
        frappe.throw(
            f"Policy <b>{doc.policy_name}</b> already exists in VDOM <b>{vdom}</b>.",
            title="Duplicate Policy"
        )


@frappe.whitelist()
def create_policy(docname):
    doc  = frappe.get_doc("DFC 1 Mumbai Policy", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"{BASE_URL}/firewall/policy?vdom={vdom}"

    nat_value    = "enable" if doc.nat else "disable"
    status_value = "enable" if doc.enable_this_policy else "disable"
    services     = [{"name": row.service} for row in doc.custom_services]

    payload = {
        "name":     doc.policy_name,
        "srcintf":  [{"name": extract_raw_interface_name(doc.incoming_interface)}],
        "dstintf":  [{"name": extract_raw_interface_name(doc.outgoing_interface)}],
        "srcaddr":  [{"name": doc.source}],
        "dstaddr":  [{"name": doc.destination}],
        "service":  services,
        "schedule": "always",
        "action":   "accept",
        "nat":      nat_value,
        "status":   status_value
    }

    if doc.ip_pool_configuration == "Use Dynamic IP Pool" and doc.custom_ip_pool:
        payload["ippool"]   = "enable"
        payload["poolname"] = [{"name": doc.custom_ip_pool}]

    try:
        response = requests.post(url, headers=get_headers_json(), json=payload, verify=False, timeout=20)
        if response.status_code == 200:
            result    = response.json()
            policy_id = result.get("mkey")
            if policy_id:
                doc.custom_firewall_policy_id = policy_id
                doc.save(ignore_permissions=True)
            return {"status": "success", "message": f"Policy created (ID: {policy_id}) in VDOM: {vdom}"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Policy Create Error Mumbai")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def update_policy(docname):
    doc = frappe.get_doc("DFC 1 Mumbai Policy", docname)
    if not doc.custom_firewall_policy_id:
        frappe.throw("Policy not created in FortiGate yet")

    vdom = doc.custom_virtual_domain or "root"
    url  = f"{BASE_URL}/firewall/policy/{doc.custom_firewall_policy_id}?vdom={vdom}"

    nat_value    = "enable" if doc.nat else "disable"
    status_value = "enable" if doc.enable_this_policy else "disable"

    services = []
    for row in doc.custom_services:
        if row.service:
            svc_doc     = frappe.db.get_value("DFC 1 Mumbai Service", row.service, "service_name", as_dict=True)
            actual_name = svc_doc.service_name if svc_doc else row.service
            services.append({"name": actual_name})

    payload = {
        "name":     doc.policy_name,
        "srcintf":  [{"name": extract_raw_interface_name(doc.incoming_interface)}],
        "dstintf":  [{"name": extract_raw_interface_name(doc.outgoing_interface)}],
        "srcaddr":  [{"name": doc.source}],
        "dstaddr":  [{"name": doc.destination}],
        "service":  services,
        "schedule": "always",
        "action":   "accept",
        "nat":      nat_value,
        "status":   status_value
    }

    if doc.ip_pool_configuration == "Use Dynamic IP Pool" and doc.custom_ip_pool:
        payload["ippool"]   = "enable"
        payload["poolname"] = [{"name": doc.custom_ip_pool}]

    try:
        response = requests.put(url, headers=get_headers_json(), json=payload, verify=False, timeout=20)
        if response.status_code == 200:
            return {"status": "success", "message": f"Policy updated successfully (VDOM: {vdom})"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Policy Update Error Mumbai")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def sync_policies_from_fortigate():
    vdom_list = []
    try:
        r = requests.get(
            f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom",
            headers=get_headers(), verify=False, timeout=15
        )
        vdom_list = [v.get("name") for v in r.json().get("results", []) if v.get("name")]
    except Exception:
        pass
    if not vdom_list:
        vdom_list = ["root"]

    def fetch_vdom_data(vdom):
        return {
            "vdom":      vdom,
            "policies":  _fetch_policies_mumbai(vdom),
            "iface_map": _build_interface_map_mumbai(vdom),
        }

    vdom_data_list = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_vdom_data, v): v for v in vdom_list}
        for future in as_completed(futures):
            try:
                vdom_data_list.append(future.result())
            except Exception as e:
                frappe.log_error(str(e), "FortiGate Fetch VDOM Data Error Mumbai Policy")

    created = updated = skipped = 0

    for vd in vdom_data_list:
        vdom      = vd["vdom"]
        iface_map = vd["iface_map"]

        for pol in vd["policies"]:
            policy_id = pol.get("policyid")
            if not policy_id:
                skipped += 1
                continue

            try:
                name = pol.get("name") or f"Policy-{policy_id}"

                incoming_raw       = pol.get("srcintf", [{}])[0].get("name", "")
                outgoing_raw       = pol.get("dstintf", [{}])[0].get("name", "")
                incoming_interface = iface_map.get(incoming_raw, incoming_raw)
                outgoing_interface = iface_map.get(outgoing_raw, outgoing_raw)

                source      = pol.get("srcaddr", [{}])[0].get("name", "")
                destination = pol.get("dstaddr", [{}])[0].get("name", "")
                services    = [s.get("name") for s in pol.get("service", []) if s.get("name")]
                nat           = pol.get("nat") == "enable"
                enable_policy = pol.get("status") == "enable"

                ip_pool               = ""
                ip_pool_configuration = "Use Outgoing Interface Address"
                if pol.get("ippool") in ["enable", 1, True]:
                    ip_pool_configuration = "Use Dynamic IP Pool"
                    pool_list = pol.get("poolname", [])
                    if pool_list:
                        ip_pool = pool_list[0].get("name", "")

                existing = frappe.db.exists("DFC 1 Mumbai Policy", {
                    "custom_firewall_policy_id": str(policy_id),
                    "custom_virtual_domain":     vdom
                })
                if not existing:
                    existing = frappe.db.exists("DFC 1 Mumbai Policy", {
                        "policy_name":           name,
                        "custom_virtual_domain": vdom
                    })

                doc = frappe.get_doc("DFC 1 Mumbai Policy", existing) if existing else frappe.new_doc("DFC 1 Mumbai Policy")

                doc.policy_name               = name
                doc.custom_firewall_policy_id = str(policy_id)
                doc.custom_virtual_domain     = vdom
                doc.incoming_interface        = incoming_interface
                doc.outgoing_interface        = outgoing_interface
                doc.source                    = source
                doc.destination               = destination
                doc.nat                       = nat
                doc.enable_this_policy        = enable_policy
                doc.ip_pool_configuration     = ip_pool_configuration
                doc.custom_ip_pool            = ip_pool
                doc.custom_services           = []

                for svc in services:
                    if svc:
                        doc.append("custom_services", {"service": svc})

                if existing:
                    doc.save(ignore_permissions=True, ignore_links=True)
                    updated += 1
                else:
                    doc.insert(ignore_permissions=True, ignore_links=True)
                    created += 1

            except Exception as row_error:
                frappe.log_error(
                    str(row_error),
                    f"Policy Sync Error Mumbai - VDOM: {vdom} Policy ID: {policy_id}"
                )
                skipped += 1

    frappe.db.commit()
    return {
        "status":       "success",
        "created":      created,
        "updated":      updated,
        "skipped":      skipped,
        "vdoms_synced": vdom_list
    }
