import frappe
import requests


@frappe.whitelist()
def create_interface(docname):
    doc = frappe.get_doc("DFC 3-2 Interface", docname)
    fortigate_ip = "45.198.61.6"
    api_token = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"
    target_vdom = doc.virtual_domain or "root"
    url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface?vdom={target_vdom}"
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    ip_formatted = (doc.ipnetmask or "").replace("/", " ")
    payload = {
        "name": doc.name, "type": "vlan", "interface": doc.interface,
        "vlanid": int(doc.vlan_id), "role": "lan", "vlan_protocol": "8021q",
        "ip": ip_formatted, "allowaccess": "ping", "vdom": target_vdom
    }
    if doc.alias:
        payload["alias"] = doc.alias
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        return {"status_code": response.status_code, "response": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate DFC32 API Error")
        return str(e)


@frappe.whitelist()
def update_interface(docname):
    doc = frappe.get_doc("DFC 3-2 Interface", docname)
    fortigate_ip = "45.198.61.6"
    api_token = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"
    target_vdom = doc.virtual_domain or "root"
    url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface/{doc.name}?vdom={target_vdom}"
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    payload = {"ip": doc.ipnetmask, "allowaccess": "ping", "alias": doc.alias or ""}
    try:
        response = requests.put(url, headers=headers, json=payload, verify=False, timeout=10)
        return {"status_code": response.status_code, "response": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate DFC32 Update Error")
        return str(e)


@frappe.whitelist()
def sync_interfaces_from_fortigate():
    import time
    fortigate_ip = "45.198.61.6"
    api_token = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"
    headers = {"Authorization": f"Bearer {api_token}"}
    created = 0
    updated = 0
    try:
        vdoms_response = requests.get(
            f"https://{fortigate_ip}/api/v2/cmdb/system/vdom",
            headers=headers, verify=False, timeout=15
        )
        vdoms = [v["name"] for v in vdoms_response.json().get("results", []) if v.get("name")]
        if not vdoms:
            vdoms = ["root"]
        for vdom in vdoms:
            url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface?vdom={vdom}"
            for attempt in range(3):
                response = requests.get(url, headers=headers, verify=False, timeout=15)
                if response.status_code == 429:
                    time.sleep(2)
                    continue
                break
            if response.status_code != 200 or not response.text.strip():
                continue
            for iface in response.json().get("results", []):
                if iface.get("type") != "vlan":
                    continue
                raw_name   = iface.get("name") or ""
                alias_val  = iface.get("alias") or ""
                name       = f"{alias_val} ({raw_name})" if alias_val else raw_name.replace("_", " ").replace("-", " ")
                parent     = iface.get("interface")
                vlan_id    = iface.get("vlanid")
                iface_vdom = iface.get("vdom") or vdom
                if not raw_name or not parent or not vlan_id or int(vlan_id) == 0:
                    continue
                ip = iface.get("ip", "")
                if isinstance(ip, str) and " " in ip:
                    ip = ip.replace(" ", "/")
                existing = frappe.db.exists("DFC 3-2 Interface", {
                    "interface": parent, "vlan_id": vlan_id, "virtual_domain": iface_vdom
                })
                if existing:
                    doc = frappe.get_doc("DFC 3-2 Interface", existing)
                    if not doc.name1 or doc.name1 != name:
                        try:
                            doc.delete(ignore_permissions=True)
                            frappe.get_doc({
                                "doctype": "DFC 3-2 Interface", "name1": name,
                                "alias": alias_val, "interface": parent,
                                "vlan_id": vlan_id, "ipnetmask": ip, "virtual_domain": iface_vdom
                            }).insert(ignore_permissions=True)
                        except Exception as e:
                            frappe.log_error(str(e)[:200], "DFC32 Reinsert Error")
                    else:
                        doc.alias = alias_val
                        doc.ipnetmask = ip
                        doc.save(ignore_permissions=True)
                    updated += 1
                else:
                    try:
                        frappe.get_doc({
                            "doctype": "DFC 3-2 Interface", "name1": name,
                            "alias": alias_val, "interface": parent,
                            "vlan_id": vlan_id, "ipnetmask": ip, "virtual_domain": iface_vdom
                        }).insert(ignore_permissions=True)
                        created += 1
                    except Exception as e:
                        frappe.log_error(str(e)[:200], "DFC32 Insert Error")
        frappe.db.commit()
        return {"created": created, "updated": updated}
    except Exception as e:
        frappe.log_error(str(e)[:200], "FortiGate DFC32 Sync Error")
        return str(e)


@frappe.whitelist()
def get_vdoms():
    fortigate_ip = "45.198.61.6"
    api_token = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(
            f"https://{fortigate_ip}/api/v2/cmdb/system/vdom",
            headers=headers, verify=False, timeout=15
        )
        if response.status_code == 200:
            vdoms = [v.get("name") for v in response.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:200], "FortiGate DFC32 Get VDOMs Error")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def get_interfaces_from_fortigate(vdom="root"):
    fortigate_ip = "45.198.61.6"
    api_token = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(
            f"https://{fortigate_ip}/api/v2/cmdb/system/interface?vdom={vdom}",
            headers=headers, verify=False, timeout=15
        )
        return [{"name": i.get("name"), "type": i.get("type")} for i in response.json().get("results", [])]
    except Exception as e:
        frappe.log_error(str(e)[:200], "DFC32 Fetch Interface List Error")
        return []
