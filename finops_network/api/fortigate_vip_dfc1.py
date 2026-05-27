import frappe
import requests
import urllib3

urllib3.disable_warnings()

FIREWALL_IP = "45.198.225.33"
API_TOKEN   = "ryGrNswGtt7cqj577fNr0x7fqGH5j1"


def get_headers():
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type":  "application/json"
    }


def get_headers_plain():
    return {"Authorization": f"Bearer {API_TOKEN}"}


# ---------------------------------------------
# BUILD PAYLOAD
# ---------------------------------------------
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


# ---------------------------------------------
# DELETE VIP ON FORTIGATE
# ---------------------------------------------
def delete_virtual_ip_on_fortigate(name, vdom):
    url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip/{name}?vdom={vdom}"
    try:
        response = requests.delete(url, headers=get_headers(), verify=False, timeout=20)
        if response.status_code in [200, 404]:
            return True, "Deleted successfully"
        return False, response.text
    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Delete Error DFC1")
        return False, str(e)


# ---------------------------------------------
# GET VDOMs
# ---------------------------------------------
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
        frappe.log_error(str(e), "FortiGate Get VDOMs Error DFC1 VIP")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# CREATE VIRTUAL IP
# ---------------------------------------------
@frappe.whitelist()
def create_virtual_ip(docname):
    doc  = frappe.get_doc("DFC 1 Virtual IP", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip?vdom={vdom}"

    payload = build_payload(doc)

    try:
        response = requests.post(url, headers=get_headers(), json=payload, verify=False, timeout=20)
        if response.status_code == 200:
            return {"status": "success", "message": f"Virtual IP created successfully in VDOM '{vdom}'"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Create Error DFC1")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# UPDATE VIRTUAL IP
# ---------------------------------------------
@frappe.whitelist()
def update_virtual_ip(docname):
    doc  = frappe.get_doc("DFC 1 Virtual IP", docname)
    vdom = doc.custom_virtual_domain or "root"

    payload                 = build_payload(doc)
    port_mapping_normalized = str(doc.port_mapping_type or "").strip().lower()

    # Many-to-many: delete + recreate
    if doc.port_forwarding and port_mapping_normalized == "many to many":
        deleted, msg = delete_virtual_ip_on_fortigate(doc.name1, vdom)
        if not deleted:
            return {"status": "error", "message": f"Delete failed before recreate: {msg}"}

        create_url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip?vdom={vdom}"
        try:
            response = requests.post(create_url, headers=get_headers(), json=payload, verify=False, timeout=20)
            if response.status_code == 200:
                return {"status": "success", "message": f"VIP updated (recreated) in VDOM '{vdom}'"}
            return {"status": "error", "message": response.text}
        except Exception as e:
            frappe.log_error(str(e), "VIP Update Recreate Error DFC1")
            return {"status": "error", "message": str(e)}

    # Normal PUT update
    update_url = f"https://{FIREWALL_IP}/api/v2/cmdb/firewall/vip/{doc.name1}?vdom={vdom}"
    try:
        response = requests.put(update_url, headers=get_headers(), json=payload, verify=False, timeout=20)
        if response.status_code == 200:
            return {"status": "success", "message": f"VIP updated successfully in VDOM '{vdom}'"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "VIP Update Error DFC1")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# SYNC VIRTUAL IPs FROM FORTIGATE
# ---------------------------------------------
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
                    "DFC 1 Virtual IP",
                    {"name1": name, "custom_virtual_domain": vdom}
                )

                if existing:
                    doc = frappe.get_doc("DFC 1 Virtual IP", existing)
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
                    try:
                        frappe.get_doc({
                            "doctype":                  "DFC 1 Virtual IP",
                            "name1":                    name,
                            "external_ip_addressrange": ext_ip,
                            "ipv4_addressrange":        mapped_ip,
                            "port_forwarding":          1 if portforward else 0,
                            "port_mapping_type":        port_mapping_type,
                            "external_service_port":    ext_port,
                            "map_to_ipv4_port":         mapped_port,
                            "custom_virtual_domain":    vdom
                        }).insert(ignore_permissions=True)
                        created += 1
                    except Exception:
                        skipped += 1

        frappe.db.commit()
        return {"status": "success", "created": created, "updated": updated, "skipped": skipped}

    except Exception as e:
        frappe.log_error(str(e), "Fortigate VIP Sync Error DFC1")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------
# SSH RENAME
# ---------------------------------------------
def rename_vip_via_ssh(old_name: str, new_name: str, vdom: str = "root"):
    import paramiko
    import time

    FORTIGATE_SSH_IP   = "45.198.225.33"
    FORTIGATE_SSH_USER = "admin"
    FORTIGATE_SSH_PASS = "ryGrNswGtt7cqj577fNr0x7fqGH5j1"
    FORTIGATE_SSH_PORT = 22

    def _ssh_read(shell, wait=1.5, max_wait=8.0):
        time.sleep(wait)
        output   = ""
        deadline = time.time() + max_wait
        last_recv = time.time()
        while time.time() < deadline:
            if shell.recv_ready():
                chunk     = shell.recv(4096).decode("utf-8", errors="ignore")
                output   += chunk
                last_recv = time.time()
            else:
                if output and (time.time() - last_recv) > 0.5:
                    break
                time.sleep(0.05)
        return output

    def _ssh_send(shell, cmd, wait=1.5):
        shell.send(cmd + "\n")
        return _ssh_read(shell, wait=wait)

    def _detect_scope(banner):
        last_line = banner.strip().splitlines()[-1] if banner.strip() else ""
        return "vdom" if ("(" in last_line and ")" in last_line) else "global"

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname      = FORTIGATE_SSH_IP,
            port          = FORTIGATE_SSH_PORT,
            username      = FORTIGATE_SSH_USER,
            password      = FORTIGATE_SSH_PASS,
            look_for_keys = False,
            allow_agent   = False,
            timeout       = 15
        )

        shell  = ssh.invoke_shell(width=220, height=50)
        banner = _ssh_read(shell, wait=3.0, max_wait=10.0)
        scope  = _detect_scope(banner)

        if scope == "vdom":
            out1 = _ssh_send(shell, "config firewall vip",                  wait=1.5)
            out2 = _ssh_send(shell, f'rename "{old_name}" to "{new_name}"', wait=2.0)
            out3 = _ssh_send(shell, "end",                                   wait=1.5)
            full_output = (out1 + out2 + out3).lower()
        else:
            out0 = _ssh_send(shell, "config vdom",                           wait=1.5)
            out1 = _ssh_send(shell, f"edit {vdom}",                          wait=1.5)
            out2 = _ssh_send(shell, "config firewall vip",                   wait=1.5)
            out3 = _ssh_send(shell, f'rename "{old_name}" to "{new_name}"',  wait=2.0)
            out4 = _ssh_send(shell, "end",                                   wait=1.5)
            out5 = _ssh_send(shell, "end",                                   wait=1.5)
            full_output = (out0 + out1 + out2 + out3 + out4 + out5).lower()

        _ssh_send(shell, "exit", wait=0.5)
        ssh.close()

        error_indicators = [
            "command fail", "entry not found", "object not found",
            "unknown action", "permission denied", "already exists",
        ]
        for indicator in error_indicators:
            if indicator in full_output:
                frappe.throw(
                    f"SSH VIP rename failed: '{old_name}' → '{new_name}' in VDOM '{vdom}'.\n\n"
                    f"SSH output:\n{full_output}"
                )

    except paramiko.AuthenticationException:
        frappe.throw(f"SSH Authentication Failed for user '{FORTIGATE_SSH_USER}'.")
    except paramiko.ssh_exception.NoValidConnectionsError:
        frappe.throw(f"SSH connection refused at {FORTIGATE_SSH_IP}:{FORTIGATE_SSH_PORT}.")
    except TimeoutError:
        frappe.throw(f"SSH Connection Timed Out to {FORTIGATE_SSH_IP}:{FORTIGATE_SSH_PORT}.")
    except frappe.exceptions.ValidationError:
        raise
    except Exception as e:
        frappe.throw(f"SSH VIP Rename Failed: {str(e)}")


# ---------------------------------------------
# RENAME VIRTUAL IP
# ---------------------------------------------
@frappe.whitelist()
def rename_virtual_ip(docname, new_name, ticket_id=None, remarks=None):
    doc      = frappe.get_doc("DFC 1 Virtual IP", docname)
    vdom     = doc.custom_virtual_domain or "root"
    old_name = doc.name1
    new_name = new_name.strip()

    if not new_name:
        frappe.throw("New VIP name is required.")
    if old_name == new_name:
        frappe.throw("New VIP name is same as current name.")

    rename_vip_via_ssh(old_name, new_name, vdom)

    frappe.db.set_value("DFC 1 Virtual IP", docname, "name1", new_name)
    frappe.db.commit()

    frappe.rename_doc("DFC 1 Virtual IP", docname, new_name, force=True)

    if ticket_id:
        frappe.get_doc({
            "doctype":           "Comment",
            "comment_type":      "Info",
            "reference_doctype": "DFC 1 Virtual IP",
            "reference_name":    new_name,
            "content": (
                f"<b>Action:</b> Rename Virtual IP<br>"
                f"<b>Old Name:</b> {old_name}<br>"
                f"<b>New Name:</b> {new_name}<br>"
                f"<b>Ticket ID:</b> {ticket_id}"
                + (f"<br><b>Remarks:</b> {remarks}" if remarks else "")
            )
        }).insert(ignore_permissions=True)

    return {
        "status":  "success",
        "message": f"Virtual IP '<b>{old_name}</b>' renamed to '<b>{new_name}</b>' successfully in FortiGate and Portal."
    }


# ---------------------------------------------
# COMPOSITE UNIQUENESS CHECK
# ---------------------------------------------
@frappe.whitelist()
def validate_vip_uniqueness(docname, name1, vdom):
    vdom     = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 1 Virtual IP",
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
    vdom     = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 1 Virtual IP",
        {"name1": doc.name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != doc.name:
        frappe.throw(
            f"Virtual IP <b>{doc.name1}</b> already exists in VDOM <b>{vdom}</b>.",
            title="Duplicate Virtual IP"
        )
