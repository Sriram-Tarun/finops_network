import frappe
import requests


@frappe.whitelist()
def create_interface(docname):
    doc = frappe.get_doc("DFC 4 Interface", docname)

    fortigate_ip = "45.198.61.167"
    api_token = "9dmj7bcNcw4f6rzQbm908jmfj77f1x"

    target_vdom = doc.virtual_domain or "root"

    url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface?vdom={target_vdom}"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    interface_name = doc.name
    ip_formatted = (doc.ipnetmask or "").replace("/", " ")
    payload = {
        "name": interface_name,
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
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=False,
            timeout=10
        )
        return {
            "status_code": response.status_code,
            "response": response.text
        }
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate DFC4 API Error")
        return str(e)


@frappe.whitelist()
def update_interface(docname):
    doc = frappe.get_doc("DFC 4 Interface", docname)

    fortigate_ip = "45.198.61.167"
    api_token = "9dmj7bcNcw4f6rzQbm908jmfj77f1x"

    interface_name = doc.name
    target_vdom = doc.virtual_domain or "root"

    url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface/{interface_name}?vdom={target_vdom}"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "ip": doc.ipnetmask,
        "allowaccess": "ping"
    }

    if doc.alias:
        payload["alias"] = doc.alias
    else:
        payload["alias"] = ""

    try:
        response = requests.put(
            url,
            headers=headers,
            json=payload,
            verify=False,
            timeout=10
        )
        return {
            "status_code": response.status_code,
            "response": response.text
        }
    except Exception as e:
        frappe.log_error(str(e)[:120], "Fortigate DFC4 Update Error")
        return str(e)


@frappe.whitelist()
def sync_interfaces_from_fortigate():
    import time

    fortigate_ip = "45.198.61.167"
    api_token = "9dmj7bcNcw4f6rzQbm908jmfj77f1x"

    headers = {
        "Authorization": f"Bearer {api_token}"
    }

    created = 0
    updated = 0

    try:
        vdoms_response = requests.get(
            f"https://{fortigate_ip}/api/v2/cmdb/system/vdom",
            headers=headers,
            verify=False,
            timeout=15
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

            if response.status_code == 429:
                continue

            if response.status_code != 200:
                frappe.log_error(response.text, f"FortiGate DFC4 Error VDOM={vdom}")
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
                    name = raw_name.replace("_", " ").replace("-", " ")

                alias      = alias_val
                parent     = iface.get("interface")
                vlan_id    = iface.get("vlanid")
                iface_vdom = iface.get("vdom") or vdom

                if not raw_name or not parent or not vlan_id or int(vlan_id) == 0:
                    continue

                ip = iface.get("ip", "")
                if isinstance(ip, str) and " " in ip:
                    ip = ip.replace(" ", "/")

                existing = frappe.db.exists("DFC 4 Interface", {
                    "interface": parent,
                    "vlan_id": vlan_id,
                    "virtual_domain": iface_vdom
                })

                if existing:
                    doc = frappe.get_doc("DFC 4 Interface", existing)

                    if not doc.name1 or doc.name1 != name:
                        try:
                            doc.delete(ignore_permissions=True)
                            new_doc = frappe.get_doc({
                                "doctype": "DFC 4 Interface",
                                "name1": name,
                                "alias": alias,
                                "interface": parent,
                                "vlan_id": vlan_id,
                                "ipnetmask": ip,
                                "virtual_domain": iface_vdom
                            })
                            new_doc.insert(ignore_permissions=True)
                            updated += 1
                        except Exception as e:
                            frappe.log_error(str(e)[:200], f"DFC4 Delete+Reinsert Error: {existing}")
                    else:
                        doc.alias = alias
                        doc.interface = parent
                        doc.vlan_id = vlan_id
                        doc.ipnetmask = ip
                        doc.virtual_domain = iface_vdom
                        doc.save(ignore_permissions=True)
                        updated += 1
                else:
                    try:
                        doc = frappe.get_doc({
                            "doctype": "DFC 4 Interface",
                            "name1": name,
                            "alias": alias,
                            "interface": parent,
                            "vlan_id": vlan_id,
                            "ipnetmask": ip,
                            "virtual_domain": iface_vdom
                        })
                        doc.insert(ignore_permissions=True)
                        created += 1
                    except Exception as e:
                        frappe.log_error(str(e)[:200], f"DFC4 Insert Error: {name}")

        frappe.db.commit()
        return {"created": created, "updated": updated}

    except Exception as e:
        frappe.log_error(str(e)[:200], "FortiGate DFC4 Sync Error")
        return str(e)


@frappe.whitelist()
def get_vdoms():
    fortigate_ip = "45.198.61.167"
    api_token = "9dmj7bcNcw4f6rzQbm908jmfj77f1x"
    url = f"https://{fortigate_ip}/api/v2/cmdb/system/vdom"
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            vdoms = [v.get("name") for v in response.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e)[:200], "FortiGate DFC4 Get VDOMs Error")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def get_interfaces_from_fortigate(vdom="root"):
    fortigate_ip = "45.198.61.167"
    api_token = "9dmj7bcNcw4f6rzQbm908jmfj77f1x"
    url = f"https://{fortigate_ip}/api/v2/cmdb/system/interface?vdom={vdom}"
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        data = response.json()
        return [{"name": i.get("name"), "type": i.get("type")} for i in data.get("results", [])]
    except Exception as e:
        frappe.log_error(str(e)[:200], "DFC4 Fetch Interface List Error")
        return []
