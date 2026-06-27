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

            if map_port:
                payload["mappedport"] = map_port
            else:
                payload["mappedport"] = ext_port

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

    doc         = frappe.get_doc("DFC 3-2 Virtual IP", docname)
    firewall_ip = "45.198.61.6"
    api_token   = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"

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

    doc         = frappe.get_doc("DFC 3-2 Virtual IP", docname)
    firewall_ip = "45.198.61.6"
    api_token   = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"

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

    firewall_ip = "45.198.61.6"
    api_token   = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"
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
                    "DFC 3-2 Virtual IP",
                    {"name1": name, "custom_virtual_domain": vdom}
                )

                if existing:
                    doc = frappe.get_doc("DFC 3-2 Virtual IP", existing)

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
                        "doctype":                   "DFC 3-2 Virtual IP",
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

    firewall_ip = "45.198.61.6"
    api_token   = "q5sG4H8jcxhywg4bq37Hh545cG1zyb"
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


# -------------------------------------------------------
# SSH helper for VIP rename
# -------------------------------------------------------
def rename_vip_via_ssh(old_name: str, new_name: str, vdom: str = "root"):
    import paramiko
    import time

    FORTIGATE_SSH_IP   = "45.198.61.6"
    FORTIGATE_SSH_USER = "SSHUSER"
    FORTIGATE_SSH_PASS = "FDSJF@$%@$!5445"
    FORTIGATE_SSH_PORT = 22

    def _ssh_read(shell, wait=1.5, max_wait=8.0):
        time.sleep(wait)
        output = ""
        deadline  = time.time() + max_wait
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

        frappe.log_error(
            message=f"SSH VIP RENAME | scope={scope} | vdom={vdom} | old={old_name} | new={new_name}\nBANNER:\n{banner}",
            title="VIP SSH RENAME DEBUG"
        )

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
            out4 = _ssh_send(shell, "end",                                    wait=1.5)
            out5 = _ssh_send(shell, "end",                                    wait=1.5)
            full_output = (out0 + out1 + out2 + out3 + out4 + out5).lower()

        _ssh_send(shell, "exit", wait=0.5)
        ssh.close()

        frappe.log_error(
            message=f"SSH VIP RENAME OUTPUT:\n{full_output}",
            title="VIP SSH RENAME OUTPUT"
        )

        error_indicators = [
            "command fail", "entry not found", "object not found",
            "unknown action", "permission denied", "already exists",
        ]
        for indicator in error_indicators:
            if indicator in full_output:
                frappe.throw(
                    f"SSH VIP rename failed: '{old_name}' to '{new_name}' in VDOM '{vdom}'.\n\n"
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


# -------------------------------------------------------
# Rename Virtual IP in Fortigate + Frappe (SSH-based)
# -------------------------------------------------------
@frappe.whitelist()
def rename_virtual_ip(docname, new_name, ticket_id=None, remarks=None):
    doc      = frappe.get_doc("DFC 3-2 Virtual IP", docname)
    vdom     = doc.custom_virtual_domain or "root"
    old_name = doc.name1

    new_name = new_name.strip()

    if not new_name:
        frappe.throw("New VIP name is required.")
    if old_name == new_name:
        frappe.throw("New VIP name is same as current name.")

    # Step 1: Rename in FortiGate via SSH
    rename_vip_via_ssh(old_name, new_name, vdom)

    # Step 2: Update name1 field directly in DB -- skips all hooks
    frappe.db.set_value("DFC 3-2 Virtual IP", docname, "name1", new_name)
    frappe.db.commit()

    # Step 3: Rename the Frappe doc
    frappe.rename_doc("DFC 3-2 Virtual IP", docname, new_name, force=True)

    # Step 4: Log ticket activity against new doc name
    if ticket_id:
        frappe.get_doc({
            "doctype":           "Comment",
            "comment_type":      "Info",
            "reference_doctype": "DFC 3-2 Virtual IP",
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
    vdom = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 3-2 Virtual IP",
        {"name1": name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != docname:
        return {
            "status": "duplicate",
            "message": f"Virtual IP '{name1}' already exists in VDOM '{vdom}'"
        }
    return {"status": "ok"}


# ---------------------------------------------
# VALIDATE HOOK
# ---------------------------------------------
def validate_vip(doc, method=None):
    vdom = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 3-2 Virtual IP",
        {"name1": doc.name1, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != doc.name:
        frappe.throw(
            f"Virtual IP <b>{doc.name1}</b> already exists in VDOM <b>{vdom}</b>.",
            title="Duplicate Virtual IP"
        )
