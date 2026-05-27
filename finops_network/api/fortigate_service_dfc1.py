import frappe
import requests
import urllib3

urllib3.disable_warnings()

FIREWALL_IP = "45.198.225.33"
API_TOKEN   = "ryGrNswGtt7cqj577fNr0x7fqGH5j1"


def get_headers():
    return {"Authorization": f"Bearer {API_TOKEN}"}


# ---------------------------------------------
# GET VDOMs
# ---------------------------------------------
@frappe.whitelist()
def get_vdom_list_for_service():
    try:
        url      = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
        response = requests.get(url, headers=get_headers(), verify=False, timeout=15)

        if response.status_code != 200:
            return {"status": "error", "message": "Failed to fetch VDOMs"}

        vdoms = [
            v.get("name")
            for v in response.json().get("results", [])
            if v.get("name")
        ]
        return {"status": "success", "vdoms": vdoms}

    except Exception as e:
        frappe.log_error(str(e), "VDOM Fetch Error DFC1 Service")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# CREATE SERVICE IN FORTIGATE
# ---------------------------------------------
@frappe.whitelist()
def create_service_in_firewall(service_name, protocol, low, high, vdom=None):
    if not vdom:
        frappe.throw("Virtual Domain (VDOM) is required to create a service.")

    url     = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall.service/custom?vdom={vdom}"
    headers = {**get_headers(), "Content-Type": "application/json"}

    payload = {"name": service_name}

    if protocol == "TCP":
        payload["tcp-portrange"] = f"{low}-{high}"
    elif protocol == "UDP":
        payload["udp-portrange"] = f"{low}-{high}"

    try:
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=20)
        result   = response.json()

        if result.get("status") != "success":
            frappe.throw(f"FortiGate Error: {str(result)}")

        return f"Service '{service_name}' created in FortiGate (VDOM: {vdom})"

    except Exception as e:
        frappe.log_error(str(e), "Fortigate Service Error DFC1")
        frappe.throw(str(e))


# ---------------------------------------------
# SYNC SERVICES FROM FORTIGATE
# ---------------------------------------------
@frappe.whitelist()
def sync_services_from_fortigate():
    headers = get_headers()
    created = 0
    updated = 0
    skipped = 0

    try:
        vdom_url      = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
        vdom_response = requests.get(vdom_url, headers=headers, verify=False, timeout=15)

        if vdom_response.status_code != 200:
            frappe.throw("Failed to fetch VDOM list")

        vdom_list = [v.get("name") for v in vdom_response.json().get("results", []) if v.get("name")]
        if not vdom_list:
            vdom_list = ["root"]

        for vdom in vdom_list:
            url      = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall.service/custom?vdom={vdom}"
            response = requests.get(url, headers=headers, verify=False, timeout=20)

            if response.status_code != 200:
                frappe.log_error(response.text, f"DFC1 Service Fetch Error - {vdom}")
                continue

            for svc in response.json().get("results", []):
                name = svc.get("name")
                if not name:
                    skipped += 1
                    continue

                doc_name   = name
                protocol   = ""
                port_range = ""

                if svc.get("tcp-portrange"):
                    protocol   = "TCP"
                    port_range = svc.get("tcp-portrange")
                elif svc.get("udp-portrange"):
                    protocol   = "UDP"
                    port_range = svc.get("udp-portrange")

                low  = 0
                high = 0

                if port_range:
                    try:
                        parts = str(port_range).replace(" ", "-").split("-")
                        parts = [p for p in parts if p]
                        if len(parts) == 1:
                            low = high = int(parts[0])
                        else:
                            low  = int(parts[0])
                            high = int(parts[-1])
                    except Exception:
                        low  = 0
                        high = 0

                exists = frappe.db.get_value("DFC 1 Service", {"name": doc_name}, "name")

                if exists:
                    current = frappe.db.get_value(
                        "DFC 1 Service",
                        {"name": doc_name},
                        ["service_name", "destination_port", "low", "high", "custom_virtual_domain"],
                        as_dict=True
                    )

                    changed = (
                        current.service_name          != name
                        or current.destination_port   != protocol
                        or int(current.low  or 0)     != int(low  or 0)
                        or int(current.high or 0)     != int(high or 0)
                        or current.custom_virtual_domain != vdom
                    )

                    if changed:
                        frappe.db.sql("""
                            UPDATE `tabDFC 1 Service`
                            SET service_name = %s,
                                destination_port = %s,
                                low = %s,
                                high = %s,
                                custom_virtual_domain = %s,
                                modified = NOW(),
                                modified_by = %s
                            WHERE name = %s
                        """, (name, protocol, low, high, vdom, frappe.session.user, doc_name))
                        updated += 1
                    else:
                        skipped += 1

                else:
                    try:
                        frappe.db.sql("""
                            INSERT INTO `tabDFC 1 Service`
                                (name, service_name, destination_port, low, high,
                                 custom_virtual_domain, owner, creation, modified,
                                 modified_by, docstatus)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s, 0)
                        """, (
                            doc_name, name, protocol, low, high,
                            vdom, frappe.session.user, frappe.session.user
                        ))
                        created += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC1 Service Insert Failed: {doc_name}")
                        skipped += 1

        frappe.db.commit()

        return {
            "status":  "success",
            "created": created,
            "updated": updated,
            "total":   frappe.db.count("DFC 1 Service")
        }

    except Exception as e:
        frappe.log_error(str(e), "Fortigate DFC1 Service Sync Error")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# COMPOSITE UNIQUENESS CHECK
# ---------------------------------------------
@frappe.whitelist()
def validate_service_uniqueness(docname, service_name, vdom):
    vdom     = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 1 Service",
        {"service_name": service_name, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != docname:
        return {
            "status":  "duplicate",
            "message": f"Service '{service_name}' already exists in VDOM '{vdom}'"
        }
    return {"status": "ok"}


# ---------------------------------------------
# VALIDATE HOOK
# ---------------------------------------------
def validate(doc, method=None):
    vdom     = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 1 Service",
        {"service_name": doc.service_name, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != doc.name:
        frappe.throw(
            f"Service <b>{doc.service_name}</b> already exists in VDOM <b>{vdom}</b>.",
            title="Duplicate Service"
        )
