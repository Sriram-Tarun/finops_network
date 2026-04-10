import frappe
import requests
import urllib3
urllib3.disable_warnings()

FIREWALL_IP = "154.210.151.180"
API_TOKEN = "H1yt7w4Q0g6r3nyc1kzg504k7bnQHm"

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
        response = requests.get(
            url,
            headers=get_headers(),
            verify=False,
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            vdoms = [v.get("name") for v in data.get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        else:
            return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# BUILD PAYLOAD (shared between create/update)
# ---------------------------------------------
def build_payload(doc):
    payload = {"name": doc.name}

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
# CREATE ADDRESS
# ---------------------------------------------
@frappe.whitelist()
def create_address(docname):
    doc = frappe.get_doc("Fortigate Address", docname)

    vdom = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address?vdom={vdom}"

    try:
        response = requests.post(
            url,
            headers=get_headers(),
            json=build_payload(doc),
            verify=False,
            timeout=20
        )
        if response.status_code == 200:
            return {"status": "success", "message": f"Address created successfully in FortiGate (VDOM: {vdom})"}
        else:
            return {"status": "error", "message": response.text}

    except Exception as e:
        frappe.log_error(str(e), "Fortigate Address Create Error")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# UPDATE ADDRESS
# ---------------------------------------------
@frappe.whitelist()
def update_address(docname):
    doc = frappe.get_doc("Fortigate Address", docname)

    vdom = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address/{doc.name}?vdom={vdom}"

    try:
        response = requests.put(
            url,
            headers=get_headers(),
            json=build_payload(doc),
            verify=False,
            timeout=20
        )
        if response.status_code == 200:
            return {"status": "success", "message": f"Address updated successfully in FortiGate (VDOM: {vdom})"}
        else:
            return {"status": "error", "message": response.text}

    except Exception as e:
        frappe.log_error(str(e), "Fortigate Address Update Error")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# SYNC ADDRESSES FROM FORTIGATE (ALL VDOMs)
# ---------------------------------------------
@frappe.whitelist()
def sync_addresses_from_fortigate():

    COUNTRY_MAP = {
        "AF": "Afghanistan|AF", "AL": "Albania|AL", "DZ": "Algeria|DZ",
        "IN": "India|IN",
        "US": "United States|US"
        # keep your full map as-is
    }

    created = 0
    updated = 0
    skipped = 0

    try:
        # -- STEP 1: Get all VDOMs --------------------------------------
        vdom_url = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
        vdom_response = requests.get(vdom_url, headers=get_headers(), verify=False, timeout=15)

        if vdom_response.status_code == 200:
            vdom_data = vdom_response.json()
            vdom_list = [v.get("name") for v in vdom_data.get("results", []) if v.get("name")]
        else:
            # Fallback to root only if VDOM fetch fails
            vdom_list = ["root"]

        # -- STEP 2: Loop through each VDOM ----------------------------
        for vdom in vdom_list:
            addr_url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/address?vdom={vdom}"

            try:
                response = requests.get(addr_url, headers=get_headers(), verify=False, timeout=15)
                data = response.json()
            except Exception as e:
                frappe.log_error(str(e), f"FortiGate Sync Error - VDOM: {vdom}")
                continue

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

                addr_type = addr.get("type", "ipmask")
                ip = addr.get("subnet", "").replace(" ", "/")
                fqdn = addr.get("fqdn", "")
                country_code = addr.get("country", "")

                # -- Country resolution ---------------------------------
                country = ""
                if "|" in country_code:
                    country = country_code
                elif len(country_code) == 2:
                    country = COUNTRY_MAP.get(country_code.upper(), "")
                else:
                    for code, value in COUNTRY_MAP.items():
                        country_name = value.split("|")[0].upper()
                        if country_name == country_code.upper():
                            country = value
                            break

                # -- Type mapping ---------------------------------------
                if addr_type == "fqdn":
                    frappe_type = "FQDN"
                elif addr_type == "geography":
                    frappe_type = "Geography"
                    if not country:
                        skipped += 1
                        continue
                else:
                    frappe_type = "Subnet"

                # -- Save to Frappe -------------------------------------
                existing = frappe.db.exists("Fortigate Address", {"name1": name})

                if existing:
                    doc = frappe.get_doc("Fortigate Address", existing)
                    doc.type = frappe_type
                    doc.custom_virtual_domain = vdom  # ? Save VDOM

                    if frappe_type == "Subnet":
                        doc.ipnetmask = ip
                    elif frappe_type == "FQDN":
                        doc.custom_fqdn = fqdn
                    elif frappe_type == "Geography":
                        doc.custom_country__region = country

                    doc.save(ignore_permissions=True)
                    updated += 1

                else:
                    new_doc = {
                        "doctype": "Fortigate Address",
                        "name1": name,
                        "type": frappe_type,
                        "custom_virtual_domain": vdom  # ? Save VDOM
                    }

                    if frappe_type == "Subnet":
                        new_doc["ipnetmask"] = ip
                    elif frappe_type == "FQDN":
                        new_doc["custom_fqdn"] = fqdn
                    elif frappe_type == "Geography":
                        new_doc["custom_country__region"] = country

                    doc = frappe.get_doc(new_doc)
                    doc.insert(ignore_permissions=True)
                    created += 1

        frappe.db.commit()
        return {
            "status": "success",
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "vdoms_synced": vdom_list
        }

    except Exception as e:
        frappe.log_error(str(e), "FortiGate Address Sync Error")
        return {"status": "error", "message": str(e)}