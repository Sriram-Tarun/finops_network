import frappe
import requests
import urllib3

urllib3.disable_warnings()

FIREWALL_IP = "45.198.225.153"
API_TOKEN   = "qxNNdGy3fg7d0ks0fhw99qNtkGgzpy"


def get_headers():
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type":  "application/json"
    }


def get_headers_plain():
    return {"Authorization": f"Bearer {API_TOKEN}"}


@frappe.whitelist()
def get_vdoms():
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
    try:
        response = requests.get(url, headers=get_headers_plain(), verify=False, timeout=15)
        if response.status_code == 200:
            vdoms = [v.get("name") for v in response.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error DFC2 VIP")
        return {"status": "error", "message": str(e)}


def build_payload(doc):
    mapped_ip = str(doc.ipv4_addressrange or "").replace(" ", "").strip()

    payload = {
        "name":    doc.name1,
        "type":    "static-nat",
        "extip":   str(doc.external_ip_addressrange or "").replace(" ", "").strip(),
        "extintf": "any",
        "mappedip": [{"range": mapped_ip}]
    }

    if doc.port_forwarding:
        payload["portforward"] = "enable"
        payload["protocol"]    = "tcp"

        ext_port = str(doc.external_service_port or "").replace(" ", "").strip()
        map_port = str(doc.map_to_ipv4_port      or "").replace(" ", "").strip()

        port_mapping_normalized = str(doc.port_mapping_type or "").strip().lower()

        if port_mapping_normalized == "many to many":
            if "-" not in ext_port or "-" not in map_port:
                frappe.throw("Many to many requires BOTH ports as range (e.g. 3000-5000)")
            payload["portmapping-type"] = "m-to-n"
            payload["extport"]          = ext_port
            payload["mappedport"]       = map_port
        else:
            payload["portmapping-type"] = "1-to-1"
            payload["extport"]          = ext_port
            payload["mappedport"]       = map_port if map_port else ext_port
    else:
        payload["portforward"] = "disable"

    return payload


def delete_virtual_ip_on_fortigate(name, vdom):
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip/{name}?vdom={vdom}"
    try:
        response = requests.delete(url, headers=get_headers(), verify=False, timeout=20)
        if response.status_code in [200, 404]:
            return True, "Deleted successfully"
        return False, response.text
    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Delete Error DFC2")
        return False, str(e)


@frappe.whitelist()
def create_virtual_ip(docname):
    doc  = frappe.get_doc("DFC 2 Virtual IP", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip?vdom={vdom}"

    try:
        response = requests.post(
            url, headers=get_headers(),
            json=build_payload(doc), verify=False, timeout=20
        )
        if response.status_code == 200:
            return {"status": "success", "message": f"Virtual IP created successfully in VDOM '{vdom}'"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Create Error DFC2")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def update_virtual_ip(docname):
    doc  = frappe.get_doc("DFC 2 Virtual IP", docname)
    vdom = doc.custom_virtual_domain or "root"

    payload                 = build_payload(doc)
    port_mapping_normalized = str(doc.port_mapping_type or "").strip().lower()

    # Many-to-many: delete + recreate
    if doc.port_forwarding and port_mapping_normalized == "many to many":
        deleted, msg = delete_virtual_ip_on_fortigate(doc.name1, vdom)
        if not deleted:
            return {"status": "error", "message": f"Delete failed before recreate: {msg}"}

        url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip?vdom={vdom}"
        try:
            response = requests.post(url, headers=get_headers(), json=payload, verify=False, timeout=20)
            if response.status_code == 200:
                return {"status": "success", "message": f"VIP updated (recreated) in VDOM '{vdom}'"}
            return {"status": "error", "message": response.text}
        except Exception as e:
            frappe.log_error(str(e), "VIP Update Recreate Error DFC2")
            return {"status": "error", "message": str(e)}

    # Normal update
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip/{doc.name1}?vdom={vdom}"
    try:
        response = requests.put(url, headers=get_headers(), json=payload, verify=False, timeout=20)
        if response.status_code == 200:
            return {"status": "success", "message": f"VIP updated successfully in VDOM '{vdom}'"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "VIP Update Error DFC2")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def sync_virtual_ips_from_fortigate():
    try:
        result = get_vdoms()
        if result.get("status") != "success":
            return {"status": "error", "message": "Failed to fetch VDOMs"}

        vdoms   = result.get("vdoms", [])
        created = 0
        updated = 0
        skipped = 0

        for vdom in vdoms:
            url      = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip?vdom={vdom}"
            response = requests.get(url, headers=get_headers_plain(), verify=False, timeout=20)
            vips     = response.json().get("results", [])

            for v in vips:
                name = (v.get("name") or "").strip()
                if not name:
                    skipped += 1
                    continue

                ext_ip    = (v.get("extip") or "").strip()
                mapped_ip = ""
                mapped_list = v.get("mappedip", [])
                if mapped_list:
                    mapped_ip = (mapped_list[0].get("range") or "").strip()

                portforward = v.get("portforward") == "enable"

                port_mapping_type = ""
                ext_port          = ""
                mapped_port       = ""

                if portforward:
                    raw_type = (v.get("portmapping-type") or "").lower()
                    port_mapping_type = "Many to many" if raw_type == "m-to-n" else "One to one"
                    ext_port    = str(v.get("extport")    or "").strip()
                    mapped_port = str(v.get("mappedport") or "").strip()

                existing = frappe.db.exists(
                    "DFC 2 Virtual IP",
                    {"name1": name, "custom_virtual_domain": vdom}
                )

                if existing:
                    try:
                        frappe.db.set_value("DFC 2 Virtual IP", existing, {
                            "external_ip_addressrange": ext_ip,
                            "ipv4_addressrange":        mapped_ip,
                            "port_forwarding":          1 if portforward else 0,
                            "port_mapping_type":        port_mapping_type,
                            "external_service_port":    ext_port,
                            "map_to_ipv4_port":         mapped_port,
                            "custom_virtual_domain":    vdom
                        })
                        updated += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC2 VIP Update Error: {name}")
                        skipped += 1
                else:
                    try:
                        frappe.get_doc({
                            "doctype":                  "DFC 2 Virtual IP",
                            "name1":                    name,
                            "external_ip_addressrange": ext_ip,
                            "ipv4_addressrange":        mapped_ip,
                            "port_forwarding":          1 if portforward else 0,
                            "port_mapping_type":        port_mapping_type,
                            "external_service_port":    ext_port,
                            "map_to_ipv4_port":         mapped_port,
                            "custom_virtual_domain":    vdom
                        }).insert(ignore_permissions=True, ignore_mandatory=True)
                        created += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC2 VIP Insert Error: {name}")
                        skipped += 1

        frappe.db.commit()
        return {
            "status":  "success",
            "created": created,
            "updated": updated,
            "skipped": skipped
        }

    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Sync Error DFC2")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# COMPOSITE UNIQUENESS CHECK
# ---------------------------------------------
@frappe.whitelist()
def validate_vip_uniqueness(docname, name1, vdom):
    vdom = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 2 Virtual IP",
        {"name1": name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != docname:
        return {
            "status":  "duplicate",
            "message": f"Virtual IP '{name1}' already exists in VDOM '{vdom}'"
        }
    return {"status": "ok"}


# ---------------------------------------------
# VALIDATE HOOK
# ---------------------------------------------
def validate_vip(doc, method=None):
    vdom = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 2 Virtual IP",
        {"name1": doc.name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != doc.name:
        frappe.throw(
            f"Virtual IP <b>{doc.name1}</b> already exists in VDOM <b>{vdom}</b>.",
            title="Duplicate Virtual IP"
        )
