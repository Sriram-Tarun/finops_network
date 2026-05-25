import frappe
import requests


def get_raw_name(doc_name):
    if "(" in doc_name and doc_name.endswith(")"):
        return doc_name[doc_name.rfind("(") + 1:-1]
    return doc_name


@frappe.whitelist()
def create_interface(docname):
    doc = frappe.get_doc("DFC 2 Interface", docname)
    fortigate_ip = "45.198.225.153"
    api_token = "qxNNdGy3fg7d0ks0fhw99qNtkGgzpy"
    target_vdom = doc.virtual_domain or "root"
    url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface?vdom={target_vdom}"
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    raw_name = get_raw_name(doc.name)
    ip_formatted = (doc.ipnetmask or "").replace("/", " ")
    payload = {
        "name": raw_name,
        "type": "vlan",
        "interface": doc.interface,
        "vlanid": int(doc.vlan_id),
        "role": "lan",
        "vlan_protocol": "8021q",
        "ip": ip_formatted,
        "allowaccess": "ping",
        "vdom": target_vdom
    }
    if doc.alias:
        payload["alias"] = doc.alias
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        return {"status_code": response.status_code, "response": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate API Error DFC2")
        return str(e)


@frappe.whitelist()
def update_interface(docname):
    doc = frappe.get_doc("DFC 2 Interface", docname)
    fortigate_ip = "45.198.225.153"
    api_token = "qxNNdGy3fg7d0ks0fhw99qNtkGgzpy"
    raw_name = get_raw_name(doc.name)
    target_vdom = doc.virtual_domain or "root"
    url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface/{raw_name}?vdom={target_vdom}"
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    payload = {"ip": doc.ipnetmask, "allowaccess": "ping"}
    payload["alias"] = doc.alias if doc.alias else ""
    try:
        response = requests.put(url, headers=headers, json=payload, verify=False, timeout=10)
        return {"status_code": response.status_code, "response": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate Update Error DFC2")
        return str(e)


@frappe.whitelist()
def sync_interfaces_from_fortigate():
    fortigate_ip = "45.198.225.153"
    api_token = "qxNNdGy3fg7d0ks0fhw99qNtkGgzpy"
    headers = {"Authorization": f"Bearer {api_token}"}
    created = 0
    updated = 0

    try:
        response = requests.get(
            f"https://{fortigate_ip}/api/v2/cmdb/system/interface",
            headers=headers, verify=False, timeout=30
        )
        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}", "body": response.text[:200]}

        data = response.json()
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

            existing = frappe.db.exists("DFC 2 Interface", {
                "interface": parent,
                "vlan_id": vlan_id,
                "virtual_domain": iface_vdom
            })

            if existing:
                doc = frappe.get_doc("DFC 2 Interface", existing)

                if not doc.name1 or doc.name1 != name:
                    # Name changed — delete and re-insert so record ID (title) updates too
                    try:
                        doc.delete(ignore_permissions=True)
                        frappe.get_doc({
                            "doctype": "DFC 2 Interface",
                            "name1": name,
                            "alias": alias_val,
                            "interface": parent,
                            "vlan_id": vlan_id,
                            "ipnetmask": ip,
                            "virtual_domain": iface_vdom
                        }).insert(ignore_permissions=True, ignore_mandatory=True)
                        updated += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC2 Reinsert Error: {existing} -> {name}")
                else:
                    # Name unchanged — use db.set_value to bypass mandatory
                    try:
                        frappe.db.set_value("DFC 2 Interface", existing, {
                            "alias": alias_val,
                            "interface": parent,
                            "vlan_id": vlan_id,
                            "ipnetmask": ip,
                            "virtual_domain": iface_vdom
                        })
                        updated += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC2 Update Error: {existing}")
            else:
                try:
                    frappe.get_doc({
                        "doctype": "DFC 2 Interface",
                        "name1": name,
                        "alias": alias_val,
                        "interface": parent,
                        "vlan_id": vlan_id,
                        "ipnetmask": ip,
                        "virtual_domain": iface_vdom
                    }).insert(ignore_permissions=True, ignore_mandatory=True)
                    created += 1
                except Exception as e:
                    frappe.log_error(str(e), f"DFC2 Insert Error: {name}")

        frappe.db.commit()
        return {"created": created, "updated": updated}

    except Exception as e:
        frappe.log_error(str(e), "FortiGate Sync Error DFC2")
        return str(e)


@frappe.whitelist()
def get_vdoms():
    fortigate_ip = "45.198.225.153"
    api_token = "qxNNdGy3fg7d0ks0fhw99qNtkGgzpy"
    url = f"https://{fortigate_ip}/api/v2/cmdb/system/vdom"
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            vdoms = [v.get("name") for v in response.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error DFC2")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def get_interfaces_from_fortigate(vdom="root"):
    fortigate_ip = "45.198.225.153"
    api_token = "qxNNdGy3fg7d0ks0fhw99qNtkGgzpy"
    url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface?vdom={vdom}"
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        data = response.json()
        return [
            {"name": iface.get("name"), "type": iface.get("type")}
            for iface in data.get("results", [])
        ]
    except Exception as e:
        frappe.log_error(str(e), "Fetch Interface List Error DFC2")
        return []
