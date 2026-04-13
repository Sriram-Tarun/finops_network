import frappe
import requests
import urllib.parse
import urllib3

urllib3.disable_warnings()

FIREWALL_IP = "154.210.151.180"
API_TOKEN = "H1yt7w4Q0g6r3nyc1kzg504k7bnQHm"


def get_headers():
    return {"Authorization": f"Bearer {API_TOKEN}"}


def get_valid_members(doc):
    """Extract and format members from the child table for FortiGate API."""
    members = []
    for row in doc.get("members", []):
        service = (row.service or "").strip()
        if service:
            members.append({"name": service})
    return members


@frappe.whitelist()
def get_vdom_list():
    headers = get_headers()
    try:
        url = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
        response = requests.get(url, headers=headers, verify=False, timeout=15)

        if response.status_code != 200:
            return {"status": "error", "message": "Failed to fetch VDOMs"}

        vdoms = [
            v.get("name")
            for v in response.json().get("results", [])
            if v.get("name")
        ]

        return {"status": "success", "vdoms": vdoms}

    except Exception as e:
        frappe.log_error(str(e), "VDOM Fetch Error")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def create_service_group(docname):
    doc = frappe.get_doc("DFC 3 Service Group", docname)

    vdom = doc.custom_virtual_domain or "root"

    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall.service/group?vdom={vdom}"
    headers = {**get_headers(), "Content-Type": "application/json"}

    members = get_valid_members(doc)

    if not members:
        frappe.throw("Please add at least one member service before creating the group.")

    payload = {
        "name": doc.group_name.strip(),
        "member": members
    }

    try:
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=20)
        result = response.json()

        if result.get("status") != "success":
            cli_error = result.get("cli_error", "")
            if "not found in datasource" in cli_error or "value parse error" in cli_error:
                member_names = [m["name"] for m in members]
                frappe.throw(
                    f"One or more services do not exist in FortiGate under VDOM '<b>{vdom}</b>':<br>"
                    f"<b>{', '.join(member_names)}</b><br><br>"
                    f"Please ensure these services exist in FortiGate under the correct VDOM."
                )
            frappe.throw(f"FortiGate Error: {str(result)}")

        frappe.db.set_value("DFC 3 Service Group", docname, "custom_firewall_created", 1)
        frappe.db.commit()

        return f"Service Group '{doc.group_name.strip()}' created in FortiGate (VDOM: {vdom})"

    except Exception as e:
        frappe.log_error(str(e), "Fortigate Service Group Error")
        frappe.throw(str(e))


@frappe.whitelist()
def update_service_group(docname):
    doc = frappe.get_doc("DFC 3 Service Group", docname)

    if not doc.custom_virtual_domain:
        frappe.throw("VDOM is required to update service group.")

    vdom = doc.custom_virtual_domain
    group_name = doc.group_name.strip()
    encoded_name = urllib.parse.quote(group_name)

    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall.service/group/{encoded_name}?vdom={vdom}"
    headers = {**get_headers(), "Content-Type": "application/json"}

    members = get_valid_members(doc)

    if not members:
        frappe.throw("Please add at least one member service before updating the group.")

    payload = {
        "name": group_name,
        "member": members
    }

    try:
        response = requests.put(url, headers=headers, json=payload, verify=False, timeout=20)

        try:
            result = response.json()
        except Exception:
            frappe.throw(f"Invalid response from FortiGate: {response.text}")

        if response.status_code == 404:
            frappe.throw(
                f"Service Group '{group_name}' not found in FortiGate (VDOM: {vdom}). "
                f"Please create it first."
            )

        if result.get("status") != "success":
            frappe.throw(f"FortiGate Error: {str(result)}")

        return f"Service Group '{group_name}' updated successfully (VDOM: {vdom})"

    except Exception as e:
        frappe.log_error(str(e), "Fortigate Update Service Group Error")
        frappe.throw(str(e))


@frappe.whitelist()
def sync_service_groups_from_fortigate():
    headers = get_headers()
    child_table = "tabService Group Member"

    created = 0
    updated = 0

    try:
        vdom_url = f"https://{FIREWALL_IP}/api/v2/cmdb/system/vdom"
        vdom_response = requests.get(vdom_url, headers=headers, verify=False, timeout=15)

        if vdom_response.status_code != 200:
            frappe.throw("Failed to fetch VDOM list from FortiGate.")

        vdom_list = [
            v.get("name")
            for v in vdom_response.json().get("results", [])
            if v.get("name")
        ]
        if not vdom_list:
            vdom_list = ["root"]

        for vdom in vdom_list:
            url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall.service/group?vdom={vdom}"
            response = requests.get(url, headers=headers, verify=False, timeout=20)

            if response.status_code != 200:
                continue

            for grp in response.json().get("results", []):
                group_name = grp.get("name")
                if not group_name:
                    continue

                group_name = group_name.strip()

                member_names = [
                    m.get("name")
                    for m in grp.get("member", [])
                    if m.get("name")
                ]

                # ? Find existing doc by group_name + vdom (NOT by the old unique_name pattern)
                doc_name = frappe.db.get_value(
                    "DFC 3 Service Group",
                    {
                        "group_name": group_name,
                        "custom_virtual_domain": vdom
                    },
                    "name"
                )

                if doc_name:
                    # --- UPDATE existing record ---
                    current_members = frappe.db.sql(
                        f"SELECT service FROM `{child_table}` WHERE parent = %s ORDER BY idx",
                        (doc_name,),
                        as_dict=True
                    )
                    current_member_names = [r.service for r in current_members]

                    changed = set(current_member_names) != set(member_names)

                    if changed:
                        frappe.db.sql("""
                            UPDATE `tabDFC 3 Service Group`
                            SET custom_firewall_created = 1,
                                modified = NOW(),
                                modified_by = %s
                            WHERE name = %s
                        """, (frappe.session.user, doc_name))

                        frappe.db.sql(
                            f"DELETE FROM `{child_table}` WHERE parent = %s",
                            (doc_name,)
                        )

                        for idx, svc_name in enumerate(member_names, start=1):
                            frappe.db.sql(f"""
                                INSERT INTO `{child_table}`
                                (name, parent, parenttype, parentfield, idx, service)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (
                                frappe.generate_hash(length=10),
                                doc_name,
                                "DFC 3 Service Group",
                                "members",
                                idx,
                                svc_name
                            ))

                        updated += 1

                else:
                    # --- CREATE new record ---
                    # Use group_name as doc name; if duplicate exists (same name diff vdom),
                    # append vdom to make it unique
                    new_doc_name = group_name
                    if frappe.db.exists("DFC 3 Service Group", new_doc_name):
                        new_doc_name = f"{group_name}-{vdom}"

                    frappe.db.sql("""
                        INSERT INTO `tabDFC 3 Service Group`
                        (name, group_name, custom_virtual_domain,
                         custom_firewall_created, owner, creation,
                         modified, modified_by, docstatus)
                        VALUES (%s, %s, %s, 1, %s, NOW(), NOW(), %s, 0)
                    """, (
                        new_doc_name,
                        group_name,
                        vdom,
                        frappe.session.user,
                        frappe.session.user
                    ))

                    for idx, svc_name in enumerate(member_names, start=1):
                        frappe.db.sql(f"""
                            INSERT INTO `{child_table}`
                            (name, parent, parenttype, parentfield, idx, service)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (
                            frappe.generate_hash(length=10),
                            new_doc_name,
                            "DFC 3 Service Group",
                            "members",
                            idx,
                            svc_name
                        ))

                    created += 1

        frappe.db.commit()

        return {
            "status": "success",
            "created": created,
            "updated": updated,
            "total": frappe.db.count("DFC 3 Service Group")
        }

    except Exception as e:
        frappe.log_error(str(e), "Sync Service Group Error")
        return {"status": "error", "message": str(e)}

@frappe.whitelist()
def get_services_by_vdom(vdom):
    """Fetch all custom services and service groups from FortiGate for a given VDOM."""
    headers = get_headers()
    services = []

    try:
        # Fetch custom services
        custom_url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall.service/custom?vdom={vdom}"
        custom_response = requests.get(custom_url, headers=headers, verify=False, timeout=15)
        if custom_response.status_code == 200:
            for s in custom_response.json().get("results", []):
                name = s.get("name", "").strip()
                if name:
                    services.append(name)

        # Fetch predefined services
        predefined_url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall.service/predefined?vdom={vdom}"
        predefined_response = requests.get(predefined_url, headers=headers, verify=False, timeout=15)
        if predefined_response.status_code == 200:
            for s in predefined_response.json().get("results", []):
                name = s.get("name", "").strip()
                if name:
                    services.append(name)

        services = sorted(set(services))
        return {"status": "success", "services": services}

    except Exception as e:
        frappe.log_error(str(e), "Get Services By VDOM Error")
        return {"status": "error", "message": str(e)}

@frappe.whitelist()
def search_services_by_vdom(doctype, txt, searchfield, start, page_len, filters):
    vdom = filters.get("vdom", "root")
    result = get_services_by_vdom(vdom)
    
    if result.get("status") != "success":
        return []
    
    services = result.get("services", [])
    txt = (txt or "").lower()
    
    matched = [
        [s] for s in services
        if txt in s.lower()
        and s.strip().upper() != "ALL"  # ? block exact ALL only
    ]
    
    return matched[int(start): int(start) + int(page_len)]