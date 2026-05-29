import frappe
import requests
import urllib3

urllib3.disable_warnings()

FIREWALL_IP = "182.18.140.152"


def get_raw_name(doc_name):
    if "(" in doc_name and doc_name.endswith(")"):
        return doc_name[doc_name.rfind("(") + 1:-1]
    return doc_name
API_TOKEN   = "4fpQ4j0wNQN7b4bwQsNzQkcn0wkhH7"


@frappe.whitelist()
def create_interface(docname):
    doc = frappe.get_doc("DFC 1 Bangalore Interface", docname)

    target_vdom    = doc.virtual_domain or "root"
    url            = f"https://{FIREWALL_IP}/api/v2/cmdb/system/interface?vdom={target_vdom}"
    headers        = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
    interface_name = get_raw_name(doc.name)
    ip_formatted   = (doc.ipnetmask or "").replace("/", " ")

    payload = {
        "name":         interface_name,
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
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        return {"status_code": response.status_code, "response": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate Bangalore Create Interface Error")
        return str(e)


@frappe.whitelist()
def update_interface(docname):
    doc = frappe.get_doc("DFC 1 Bangalore Interface", docname)

    target_vdom    = doc.virtual_domain or "root"
    interface_name = get_raw_name(doc.name)
    url            = f"https://{FIREWALL_IP}/api/v2/cmdb/system/interface/{interface_name}?vdom={target_vdom}"
    headers        = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}

    payload = {
        "ip":          doc.ipnetmask,
        "allowaccess": "ping"
    }
    payload["alias"] = doc.alias if doc.alias else ""

    try:
        response = requests.put(url, headers=headers, json=payload, verify=False, timeout=10)
        return {"status_code": response.status_code, "response": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate Bangalore Update Interface Error")
        return str(e)


@frappe.whitelist()
def sync_interfaces_from_fortigate():
    import time

    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    created = 0
    updated = 0

    try:
        vdoms_response = requests.get(
            f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom",
            headers=headers, verify=False, timeout=15
        )
        vdoms = [v["name"] for v in vdoms_response.json().get("results", []) if v.get("name")]
        if not vdoms:
            vdoms = ["root"]

        for vdom in vdoms:
            url = f"https://{FIREWALL_IP}/api/v2/cmdb/system/interface?vdom={vdom}"

            for attempt in range(3):
                response = requests.get(url, headers=headers, verify=False, timeout=15)
                if response.status_code == 429:
                    time.sleep(2)
                    continue
                break

            if response.status_code == 429:
                continue
            if response.status_code != 200:
                frappe.log_error(response.text, f"FortiGate Bangalore Error VDOM={vdom}")
                continue
            if not response.text.strip():
                continue

            data = response.json()

            for iface in data.get("results", []):
                if iface.get("type") != "vlan":
                    continue

                raw_name  = iface.get("name") or ""
                alias_val = iface.get("alias") or ""

                if alias_val:
                    name = f"{alias_val} ({raw_name})"
                else:
                    name = raw_name

                alias      = alias_val
                parent     = iface.get("interface")
                vlan_id    = iface.get("vlanid")
                iface_vdom = iface.get("vdom") or vdom

                if not raw_name or not parent or not vlan_id or int(vlan_id) == 0:
                    continue

                ip = iface.get("ip", "")
                if isinstance(ip, str) and " " in ip:
                    ip = ip.replace(" ", "/")

                existing = frappe.db.exists("DFC 1 Bangalore Interface", {
                    "interface":      parent,
                    "vlan_id":        vlan_id,
                    "virtual_domain": iface_vdom
                })

                if existing:
                    doc = frappe.get_doc("DFC 1 Bangalore Interface", existing)

                    if not doc.name1 or doc.name1 != name:
                        try:
                            doc.delete(ignore_permissions=True)
                            new_doc = frappe.get_doc({
                                "doctype":        "DFC 1 Bangalore Interface",
                                "name1":          name,
                                "alias":          alias,
                                "interface":      parent,
                                "vlan_id":        vlan_id,
                                "ipnetmask":      ip,
                                "virtual_domain": iface_vdom
                            })
                            new_doc.insert(ignore_permissions=True, ignore_mandatory=True)
                            updated += 1
                        except Exception as e:
                            frappe.log_error(str(e), f"Bangalore Delete+Reinsert Error: {existing} → {name}")
                    else:
                        try:
                            frappe.db.set_value("DFC 1 Bangalore Interface", existing, {
                                "alias":          alias,
                                "interface":      parent,
                                "vlan_id":        vlan_id,
                                "ipnetmask":      ip,
                                "virtual_domain": iface_vdom
                            })
                            updated += 1
                        except Exception as e:
                            frappe.log_error(str(e), f"Bangalore Update Error: {existing}")
                else:
                    try:
                        doc = frappe.get_doc({
                            "doctype":        "DFC 1 Bangalore Interface",
                            "name1":          name,
                            "alias":          alias,
                            "interface":      parent,
                            "vlan_id":        vlan_id,
                            "ipnetmask":      ip,
                            "virtual_domain": iface_vdom
                        })
                        doc.insert(ignore_permissions=True, ignore_mandatory=True)
                        created += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"Bangalore Insert Error: {name}")

        frappe.db.commit()
        return {"created": created, "updated": updated}

    except Exception as e:
        frappe.log_error(str(e), "FortiGate Bangalore Sync Error")
        return str(e)


@frappe.whitelist()
def get_vdoms():
    url     = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            vdoms = [v.get("name") for v in response.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Bangalore Get VDOMs Error")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def get_interfaces_from_fortigate(vdom="root"):
    url     = f"https://{FIREWALL_IP}/api/v2/cmdb/system/interface?vdom={vdom}"
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        data     = response.json()
        return [{"name": i.get("name"), "type": i.get("type")} for i in data.get("results", [])]
    except Exception as e:
        frappe.log_error(str(e), "Bangalore Fetch Interface List Error")
        return []
