import frappe
import requests
import urllib3

urllib3.disable_warnings()


def build_payload(doc):

    # CLEAN IP (allow single OR range)
    mapped_ip = str(doc.ipv4_addressrange or "").replace(" ", "").strip()

    payload = {
        "name":    doc.name1,
        "type":    "static-nat",
        "extip":   str(doc.external_ip_addressrange or "").replace(" ", "").strip(),
        "extintf": "any",
        "mappedip": [
            {"range": mapped_ip}
        ]
    }

    if doc.port_forwarding:

        payload["portforward"] = "enable"
        payload["protocol"]    = "tcp"

        # CLEAN PORT VALUES
        ext_port = str(doc.external_service_port or "").replace(" ", "").strip()
        map_port = str(doc.map_to_ipv4_port      or "").replace(" ", "").strip()

        # ENHANCED DEBUG LOG - captures exact value and repr for whitespace/case issues
        frappe.log_error(
            message=(
                f"=== VIP BUILD PAYLOAD DEBUG ===\n"
                f"port_mapping_type = '{doc.port_mapping_type}'\n"
                f"port_mapping_type repr = {repr(doc.port_mapping_type)}\n"
                f"port_mapping_type lower = '{str(doc.port_mapping_type or '').strip().lower()}'\n"
                f"ext_port = '{ext_port}'\n"
                f"map_port = '{map_port}'\n"
                f"mapped_ip = '{mapped_ip}'\n"
                f"ext_port has '-' = {'-' in ext_port}\n"
                f"map_port has '-' = {'-' in map_port}\n"
                f"condition 'Many to many' match = {str(doc.port_mapping_type or '').strip().lower() == 'many to many'}\n"
                f"condition 'One to one' match = {str(doc.port_mapping_type or '').strip().lower() == 'one to one'}\n"
            ),
            title="VIP DEBUG VALUES"
        )

        # NORMALIZE for safe comparison (handles case/whitespace issues)
        port_mapping_normalized = str(doc.port_mapping_type or "").strip().lower()

        # -- MANY TO MANY (NO IP RANGE RESTRICTION) ------------------------
        if port_mapping_normalized == "many to many":

            # only ports must be range
            if "-" not in ext_port or "-" not in map_port:
                frappe.throw("Many to many requires BOTH ports as range (e.g. 3000-5000)")

            payload["portmapping-type"] = "m-to-n"
            payload["extport"]          = ext_port
            payload["mappedport"]       = map_port

            # DEBUG LOG - confirm many-to-many branch was taken
            frappe.log_error(
                message=(
                    f"=== MANY-TO-MANY BRANCH TAKEN ===\n"
                    f"portmapping-type = m-to-n\n"
                    f"extport = '{ext_port}'\n"
                    f"mappedport = '{map_port}'\n"
                    f"full payload = {payload}"
                ),
                title="VIP DEBUG MANY-TO-MANY"
            )

        # -- ONE TO ONE ----------------------------------------------------
        else:

            payload["portmapping-type"] = "1-to-1"
            payload["extport"]          = ext_port

            # FIX: Use the actual map_to_ipv4_port value entered by the user.
            # Old code always set mappedport = ext_port which completely ignored
            # the "Map to IPv4 port" field — so different ext/mapped ports never worked.
            # FortiGate handles 1-to-1 proportional mapping itself when ranges are given.
            # If map_port is empty, fall back to ext_port (same-port passthrough).
            if map_port:
                payload["mappedport"] = map_port
            else:
                payload["mappedport"] = ext_port

            # DEBUG LOG - confirm one-to-one branch was taken
            frappe.log_error(
                message=(
                    f"=== ONE-TO-ONE BRANCH TAKEN ===\n"
                    f"portmapping-type = 1-to-1\n"
                    f"extport = '{ext_port}'\n"
                    f"mappedport = '{payload['mappedport']}'\n"
                    f"NOTE: If you expected many-to-many, check port_mapping_type value above!\n"
                    f"full payload = {payload}"
                ),
                title="VIP DEBUG ONE-TO-ONE"
            )

    else:
        payload["portforward"] = "disable"

    return payload


def delete_virtual_ip_on_fortigate(name, firewall_ip, api_token, vdom):

    url = f"https://{firewall_ip}/api/v2/cmdb/firewall/vip/{name}?vdom={vdom}"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type":  "application/json"
    }

    try:
        response = requests.delete(url, headers=headers, verify=False, timeout=20)

        frappe.log_error(
            message=f"DELETE VIP | VDOM={vdom} | URL={url} | RESPONSE={response.text}",
            title="VIP DELETE DEBUG"
        )

        if response.status_code in [200, 404]:
            return True, "Deleted successfully"
        else:
            return False, response.text

    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Delete Error")
        return False, str(e)


@frappe.whitelist()
def create_virtual_ip(docname):

    doc         = frappe.get_doc("Fortigate Virtual IP", docname)
    firewall_ip = "154.210.151.180"
    api_token   = "H1yt7w4Q0g6r3nyc1kzg504k7bnQHm"

    # USE SELECTED VDOM
    vdom = doc.custom_virtual_domain or "root"

    url = f"https://{firewall_ip}/api/v2/cmdb/firewall/vip?vdom={vdom}"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type":  "application/json"
    }

    payload = build_payload(doc)

    frappe.log_error(
        message=f"CREATE VIP | VDOM={vdom} | URL={url} | PAYLOAD={payload}",
        title="VIP CREATE DEBUG"
    )

    try:
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=20)

        if response.status_code == 200:
            return {
                "status":  "success",
                "message": f"Virtual IP created successfully in VDOM '{vdom}'"
            }
        else:
            return {
                "status":  "error",
                "message": response.text
            }

    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Create Error")
        return {
            "status":  "error",
            "message": str(e)
        }


@frappe.whitelist()
def update_virtual_ip(docname):

    doc         = frappe.get_doc("Fortigate Virtual IP", docname)
    firewall_ip = "154.210.151.180"
    api_token   = "H1yt7w4Q0g6r3nyc1kzg504k7bnQHm"

    # USE SELECTED VDOM
    vdom = doc.custom_virtual_domain or "root"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type":  "application/json"
    }

    payload = build_payload(doc)

    port_mapping_normalized = str(doc.port_mapping_type or "").strip().lower()

    # -- MANY-TO-MANY ? DELETE + CREATE -----------------------------------
    if doc.port_forwarding and port_mapping_normalized == "many to many":

        deleted, msg = delete_virtual_ip_on_fortigate(
            doc.name1,
            firewall_ip,
            api_token,
            vdom
        )

        if not deleted:
            return {
                "status":  "error",
                "message": f"Delete failed before recreate: {msg}"
            }

        create_url = f"https://{firewall_ip}/api/v2/cmdb/firewall/vip?vdom={vdom}"

        frappe.log_error(
            message=f"RECREATE VIP | VDOM={vdom} | PAYLOAD={payload}",
            title="VIP UPDATE DEBUG"
        )

        try:
            response = requests.post(
                create_url,
                headers=headers,
                json=payload,
                verify=False,
                timeout=20
            )

            if response.status_code == 200:
                return {
                    "status":  "success",
                    "message": f"VIP updated (recreated) in VDOM '{vdom}'"
                }
            else:
                return {
                    "status":  "error",
                    "message": response.text
                }

        except Exception as e:
            frappe.log_error(str(e), "VIP Update Recreate Error")
            return {
                "status":  "error",
                "message": str(e)
            }

    # -- NORMAL UPDATE -----------------------------------------------------
    else:

        update_url = f"https://{firewall_ip}/api/v2/cmdb/firewall/vip/{doc.name1}?vdom={vdom}"

        frappe.log_error(
            message=f"UPDATE VIP | VDOM={vdom} | PAYLOAD={payload}",
            title="VIP UPDATE DEBUG"
        )

        try:
            response = requests.put(
                update_url,
                headers=headers,
                json=payload,
                verify=False,
                timeout=20
            )

            if response.status_code == 200:
                return {
                    "status":  "success",
                    "message": f"VIP updated successfully in VDOM '{vdom}'"
                }
            else:
                return {
                    "status":  "error",
                    "message": response.text
                }

        except Exception as e:
            frappe.log_error(str(e), "VIP Update Error")
            return {
                "status":  "error",
                "message": str(e)
            }


@frappe.whitelist()
def sync_virtual_ips_from_fortigate():

    firewall_ip = "154.210.151.180"
    api_token   = "H1yt7w4Q0g6r3nyc1kzg504k7bnQHm"
    headers     = {"Authorization": f"Bearer {api_token}"}

    try:
        # GET ALL VDOMs
        result = get_vdoms()
        if result.get("status") != "success":
            return {"status": "error", "message": "Failed to fetch VDOMs"}

        vdoms   = result.get("vdoms", [])
        created = 0
        updated = 0
        skipped = 0

        for vdom in vdoms:

            url      = f"https://{firewall_ip}/api/v2/cmdb/firewall/vip?vdom={vdom}"
            response = requests.get(url, headers=headers, verify=False, timeout=20)
            vips     = response.json().get("results", [])

            for v in vips:

                name = (v.get("name") or "").strip()
                if not name:
                    skipped += 1
                    continue

                ext_ip      = (v.get("extip") or "").strip()
                mapped_ip   = ""
                mapped_list = v.get("mappedip", [])
                if mapped_list:
                    mapped_ip = (mapped_list[0].get("range") or "").strip()

                portforward = v.get("portforward") == "enable"

                port_mapping_type = ""
                ext_port          = ""
                mapped_port       = ""

                if portforward:
                    raw_type = (v.get("portmapping-type") or "").lower()

                    if raw_type == "m-to-n":
                        port_mapping_type = "Many to many"
                    else:
                        port_mapping_type = "One to one"

                    ext_port    = str(v.get("extport")    or "").strip()
                    mapped_port = str(v.get("mappedport") or "").strip()

                existing = frappe.db.exists(
                    "Fortigate Virtual IP",
                    {"name1": name, "custom_virtual_domain": vdom}
                )

                if existing:
                    doc = frappe.get_doc("Fortigate Virtual IP", existing)

                    doc.external_ip_addressrange = ext_ip
                    doc.ipv4_addressrange         = mapped_ip
                    doc.port_forwarding           = 1 if portforward else 0
                    doc.port_mapping_type         = port_mapping_type
                    doc.external_service_port     = ext_port
                    doc.map_to_ipv4_port          = mapped_port
                    doc.custom_virtual_domain     = vdom

                    doc.save(ignore_permissions=True)
                    updated += 1

                else:
                    doc = frappe.get_doc({
                        "doctype":                   "Fortigate Virtual IP",
                        "name1":                     name,
                        "external_ip_addressrange":  ext_ip,
                        "ipv4_addressrange":         mapped_ip,
                        "port_forwarding":           1 if portforward else 0,
                        "port_mapping_type":         port_mapping_type,
                        "external_service_port":     ext_port,
                        "map_to_ipv4_port":          mapped_port,
                        "custom_virtual_domain":     vdom
                    })

                    try:
                        doc.insert(ignore_permissions=True)
                        created += 1
                    except Exception:
                        skipped += 1

        frappe.db.commit()

        return {
            "status":  "success",
            "created": created,
            "updated": updated,
            "skipped": skipped
        }

    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Sync Error")
        return {
            "status":  "error",
            "message": str(e)
        }


@frappe.whitelist()
def get_vdoms():

    firewall_ip = "154.210.151.180"
    api_token   = "H1yt7w4Q0g6r3nyc1kzg504k7bnQHm"
    url         = f"https://{firewall_ip}/api/v2/cmdb/system/vdom"
    headers     = {"Authorization": f"Bearer {api_token}"}

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        if response.status_code == 200:
            vdoms = [v.get("name") for v in response.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error")
        return {"status": "error", "message": str(e)}
