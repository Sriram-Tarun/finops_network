import frappe
import requests
import paramiko
import time
import urllib3
import urllib.parse
from frappe.utils.password import get_decrypted_password

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------------------------------------
# Configuration
# -------------------------------------------------------
FORTIGATE_IP       = "45.198.225.153"
API_TOKEN          = "qxNNdGy3fg7d0ks0fhw99qNtkGgzpy"

FORTIGATE_SSH_IP   = "45.198.225.153"
FORTIGATE_SSH_USER = "SSHUSER"
FORTIGATE_SSH_PASS = "FDSJF@$%@$!5445"
FORTIGATE_SSH_PORT = 22

BASE_URL = f"https://{FORTIGATE_IP}/api/v2/cmdb"
HEADERS  = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type":  "application/json"
}


# -------------------------------------------------------
# Internal helpers
# -------------------------------------------------------
def _safe_encode(value: str) -> str:
    return urllib.parse.quote(value, safe='')


def _ssh_read(shell, wait: float = 1.5, max_wait: float = 8.0) -> str:
    time.sleep(wait)
    output    = ""
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


def _ssh_send(shell, cmd: str, wait: float = 1.5) -> str:
    shell.send(cmd + "\n")
    return _ssh_read(shell, wait=wait)


def _detect_scope(banner: str) -> str:
    last_line = banner.strip().splitlines()[-1] if banner.strip() else ""
    return "vdom" if ("(" in last_line and ")" in last_line) else "global"


def _check_duplicate_username_vdom(username: str, vdom: str, exclude_name: str = None) -> bool:
    filters  = {"custom_dfc_2_username": username, "custom_virtual_domain": vdom}
    existing = frappe.db.get_value("DFC 2 User", filters, "name")
    if not existing:
        return False
    if exclude_name and existing == exclude_name:
        return False
    return True


def _check_duplicate_group_name_vdom(group_name: str, vdom: str, exclude_name: str = None) -> bool:
    filters  = {"group_name": group_name, "custom_virtual_domain": vdom}
    existing = frappe.db.get_value("DFC 2 User Group", filters, "name")
    if not existing:
        return False
    if exclude_name and existing == exclude_name:
        return False
    return True


def reset_password_via_ssh(username: str, new_password: str, vdom: str = "root"):
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
            _ssh_send(shell, "config user local",               wait=1.5)
            out_edit   = _ssh_send(shell, f'edit "{username}"', wait=1.5)
            out_passwd = _ssh_send(shell, f"set passwd {new_password}", wait=3.0)
            out_next   = _ssh_send(shell, "next",               wait=1.5)
            out_end    = _ssh_send(shell, "end",                wait=1.5)
            _ssh_send(shell, "exit",                             wait=0.5)
            full_output = (out_edit + out_passwd + out_next + out_end).lower()
        else:
            _ssh_send(shell, "config vdom",                     wait=1.5)
            out_vdom   = _ssh_send(shell, f"edit {vdom}",       wait=1.5)
            _ssh_send(shell, "config user local",               wait=1.5)
            out_edit   = _ssh_send(shell, f'edit "{username}"', wait=1.5)
            out_passwd = _ssh_send(shell, f"set passwd {new_password}", wait=3.0)
            out_next   = _ssh_send(shell, "next",               wait=1.5)
            out_end1   = _ssh_send(shell, "end",                wait=1.5)
            out_end2   = _ssh_send(shell, "end",                wait=1.5)
            _ssh_send(shell, "exit",                             wait=0.5)
            full_output = (out_vdom + out_edit + out_passwd + out_next + out_end1 + out_end2).lower()

        ssh.close()

        for indicator in ["must have", "minimum length", "too simple", "too short",
                          "same as", "password policy", "password strength"]:
            if indicator in full_output:
                frappe.throw(f"Password policy violation for user '{username}': FortiGate rejected the password.")

        for indicator in ["command fail", "entry not found", "object not found",
                          "unknown action", "permission denied"]:
            if indicator in full_output:
                frappe.throw(f"SSH password reset failed for user '{username}' in VDOM '{vdom}'.")

    except paramiko.AuthenticationException:
        frappe.throw(f"SSH Authentication Failed for user '{FORTIGATE_SSH_USER}'.")
    except paramiko.ssh_exception.NoValidConnectionsError:
        frappe.throw(f"SSH connection refused at {FORTIGATE_SSH_IP}:{FORTIGATE_SSH_PORT}.")
    except TimeoutError:
        frappe.throw(f"SSH Connection Timed Out to {FORTIGATE_SSH_IP}:{FORTIGATE_SSH_PORT}.")
    except frappe.exceptions.ValidationError:
        raise
    except Exception as e:
        frappe.throw(f"SSH Password Reset Failed: {str(e)}")


# -------------------------------------------------------
# Frappe Hooks — DFC 2 User
# -------------------------------------------------------
def validate(doc, method):
    if getattr(doc.flags, "ignore_fortigate_sync", False):
        return
    vdom = doc.custom_virtual_domain or "root"
    if doc.custom_dfc_2_username and " " in doc.custom_dfc_2_username:
        frappe.throw("Username should not contain spaces.")
    if doc.is_new():
        if _check_duplicate_username_vdom(doc.custom_dfc_2_username, vdom):
            frappe.throw(f"User '<b>{doc.custom_dfc_2_username}</b>' already exists in VDOM '<b>{vdom}</b>'.")
    else:
        if _check_duplicate_username_vdom(doc.custom_dfc_2_username, vdom, exclude_name=doc.name):
            frappe.throw(f"User '<b>{doc.custom_dfc_2_username}</b>' already exists in VDOM '<b>{vdom}</b>'.")


def validate_user_group(doc, method):
    if getattr(doc.flags, "ignore_fortigate_sync", False):
        return
    vdom = doc.custom_virtual_domain or "root"
    if doc.group_name and " " in doc.group_name:
        frappe.throw("Group Name should not contain spaces.")
    if doc.is_new():
        if _check_duplicate_group_name_vdom(doc.group_name, vdom):
            frappe.throw(f"User Group '<b>{doc.group_name}</b>' already exists in VDOM '<b>{vdom}</b>'.")
    else:
        if _check_duplicate_group_name_vdom(doc.group_name, vdom, exclude_name=doc.name):
            frappe.throw(f"User Group '<b>{doc.group_name}</b>' already exists in VDOM '<b>{vdom}</b>'.")


def on_save(doc, method):
    if getattr(doc.flags, "ignore_fortigate_sync", False):
        return

    vdom        = doc.custom_virtual_domain or "root"
    fg_username = doc.custom_dfc_2_username

    try:
        plain_password = get_decrypted_password("DFC 2 User", doc.name, "password")
    except Exception:
        plain_password = doc.password

    check_url  = f"{BASE_URL}/user/local/{_safe_encode(fg_username)}?vdom={vdom}"
    check_resp = requests.get(check_url, headers=HEADERS, verify=False, timeout=15)
    user_exists = (check_resp.status_code == 200 and check_resp.json().get("results"))

    if not user_exists:
        url     = f"{BASE_URL}/user/local?vdom={vdom}"
        payload = {
            "name":   fg_username,
            "type":   "password",
            "passwd": plain_password or "",
            "status": "enable" if doc.user_account_status else "disable"
        }
        response      = requests.post(url, headers=HEADERS, json=payload, verify=False, timeout=30)
        response_json = {}
        try:
            response_json = response.json()
        except Exception:
            pass

        if response.status_code == 200:
            if response_json.get("status") != "success":
                frappe.throw(f"DFC 2 User creation failed: {response_json.get('error_msg', response.text)}")
        elif response.status_code == 500 and response_json.get("error") == -5:
            pass
        else:
            frappe.throw(f"Failed to create user '{fg_username}' in FortiGate (status {response.status_code}): {response.text}")

        frappe.msgprint(f"User '<b>{fg_username}</b>' created in FortiGate (VDOM: {vdom})", indicator="green", alert=True)
    else:
        url      = f"{BASE_URL}/user/local/{_safe_encode(fg_username)}?vdom={vdom}"
        payload  = {"status": "enable" if doc.user_account_status else "disable"}
        response = requests.put(url, headers=HEADERS, json=payload, verify=False, timeout=30)
        if response.status_code != 200:
            frappe.throw(f"Failed to update status for '{fg_username}' (status {response.status_code}): {response.text}")
        frappe.msgprint(f"User '<b>{fg_username}</b>' updated in FortiGate (VDOM: {vdom})", indicator="blue", alert=True)

    if plain_password:
        reset_password_via_ssh(fg_username, plain_password, vdom)

    if doc.add_to_user_group and doc.user_group:
        if user_exists:
            update_user_group(fg_username, doc.user_group, vdom)
        else:
            add_user_to_group(fg_username, doc.user_group, vdom)
    else:
        remove_user_from_all_groups(fg_username, vdom)


def on_trash(doc, method):
    vdom        = doc.custom_virtual_domain or "root"
    fg_username = doc.custom_dfc_2_username
    url         = f"{BASE_URL}/user/local/{_safe_encode(fg_username)}?vdom={vdom}"
    response    = requests.delete(url, headers=HEADERS, verify=False, timeout=30)
    if response.status_code not in (200, 404):
        frappe.throw(f"Failed to delete '{fg_username}' from FortiGate (status {response.status_code}): {response.text}")


# -------------------------------------------------------
# Whitelist helpers
# -------------------------------------------------------
@frappe.whitelist()
def check_username_vdom_exists(username, vdom, exclude_name=None):
    filters  = {"custom_dfc_2_username": username, "custom_virtual_domain": vdom or "root"}
    existing = frappe.db.get_value("DFC 2 User", filters, "name")
    if not existing:
        return False
    if exclude_name and existing == exclude_name:
        return False
    return True


@frappe.whitelist()
def check_group_name_vdom_exists(group_name, vdom, exclude_name=None):
    filters  = {"group_name": group_name, "custom_virtual_domain": vdom or "root"}
    existing = frappe.db.get_value("DFC 2 User Group", filters, "name")
    if not existing:
        return False
    if exclude_name and existing == exclude_name:
        return False
    return True


@frappe.whitelist()
def get_vdoms():
    url = f"{BASE_URL}/system/vdom"
    try:
        response = requests.get(url, headers=HEADERS, verify=False, timeout=15)
        if response.status_code == 200:
            vdoms = [v.get("name") for v in response.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error DFC2 User")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def get_user_groups(vdom="root"):
    url      = f"{BASE_URL}/user/group?vdom={vdom}"
    response = requests.get(url, headers=HEADERS, verify=False, timeout=30)
    return [g.get("name") for g in response.json().get("results", []) if g.get("name")]


@frappe.whitelist()
def get_firewall_users(vdom="root"):
    url      = f"{BASE_URL}/user/local?vdom={vdom}"
    response = requests.get(url, headers=HEADERS, verify=False, timeout=30)
    return [u.get("name") for u in response.json().get("results", []) if u.get("name")]


# -------------------------------------------------------
# Manual buttons
# -------------------------------------------------------
@frappe.whitelist()
def create_fortigate_user(docname, password=None):
    doc         = frappe.get_doc("DFC 2 User", docname)
    vdom        = doc.custom_virtual_domain or "root"
    fg_username = doc.custom_dfc_2_username
    try:
        plain_password = password or get_decrypted_password("DFC 2 User", docname, "password")
    except Exception:
        plain_password = password or doc.password

    url     = f"{BASE_URL}/user/local?vdom={vdom}"
    payload = {
        "name":   fg_username,
        "type":   "password",
        "passwd": plain_password or "",
        "status": "enable" if doc.user_account_status else "disable"
    }
    response      = requests.post(url, headers=HEADERS, json=payload, verify=False, timeout=30)
    response_json = {}
    try:
        response_json = response.json()
    except Exception:
        pass

    if response.status_code == 200:
        if response_json.get("status") != "success":
            frappe.throw(f"User creation failed: {response_json.get('error_msg', response.text)}")
    elif response.status_code == 500 and response_json.get("error") == -5:
        frappe.throw(f"User '{fg_username}' already exists in FortiGate (VDOM: {vdom}).")
    else:
        frappe.throw(f"Failed to create user '{fg_username}' (status {response.status_code}): {response.text}")

    if plain_password:
        reset_password_via_ssh(fg_username, plain_password, vdom)

    if doc.add_to_user_group and doc.user_group:
        add_user_to_group(fg_username, doc.user_group, vdom)
    else:
        remove_user_from_all_groups(fg_username, vdom)

    return f"User '{fg_username}' created successfully in FortiGate (VDOM: {vdom})"


@frappe.whitelist()
def update_fortigate_user(docname, password=None):
    doc         = frappe.get_doc("DFC 2 User", docname)
    vdom        = doc.custom_virtual_domain or "root"
    fg_username = doc.custom_dfc_2_username
    try:
        plain_password = password or get_decrypted_password("DFC 2 User", docname, "password")
    except Exception:
        plain_password = password or doc.password

    url      = f"{BASE_URL}/user/local/{_safe_encode(fg_username)}?vdom={vdom}"
    payload  = {"status": "enable" if doc.user_account_status else "disable"}
    response = requests.put(url, headers=HEADERS, json=payload, verify=False, timeout=30)
    if response.status_code != 200:
        frappe.throw(f"Failed to update status for '{fg_username}' (status {response.status_code}): {response.text}")

    if plain_password:
        reset_password_via_ssh(fg_username, plain_password, vdom)

    if doc.add_to_user_group and doc.user_group:
        update_user_group(fg_username, doc.user_group, vdom)
    else:
        remove_user_from_all_groups(fg_username, vdom)

    return f"User '{fg_username}' updated successfully in FortiGate (VDOM: {vdom})"


@frappe.whitelist()
def delete_fortigate_user(docname):
    doc         = frappe.get_doc("DFC 2 User", docname)
    vdom        = doc.custom_virtual_domain or "root"
    fg_username = doc.custom_dfc_2_username
    url         = f"{BASE_URL}/user/local/{_safe_encode(fg_username)}?vdom={vdom}"
    response    = requests.delete(url, headers=HEADERS, verify=False, timeout=30)
    if response.status_code == 404:
        return f"User '{fg_username}' was already absent from FortiGate (VDOM: {vdom})"
    if response.status_code != 200:
        frappe.throw(f"Failed to delete user '{fg_username}' (status {response.status_code}): {response.text}")
    return f"User '{fg_username}' deleted successfully from FortiGate (VDOM: {vdom})"


# -------------------------------------------------------
# Group helpers
# -------------------------------------------------------
def add_user_to_group(username: str, group: str, vdom: str = "root"):
    group_encoded   = _safe_encode(group)
    url             = f"{BASE_URL}/user/group/{group_encoded}?vdom={vdom}"
    response        = requests.get(url, headers=HEADERS, verify=False, timeout=30)
    current_members = []
    if response.status_code == 200:
        results = response.json().get("results", [])
        if results:
            current_members = results[0].get("member", [])
    if not any(m.get("name") == username for m in current_members):
        current_members.append({"name": username})
    requests.put(url, headers=HEADERS, json={"member": current_members}, verify=False, timeout=30)


def update_user_group(username: str, new_group: str, vdom: str = "root"):
    remove_user_from_all_groups(username, vdom)
    add_user_to_group(username, new_group, vdom)


def remove_user_from_all_groups(username: str, vdom: str = "root"):
    url      = f"{BASE_URL}/user/group?vdom={vdom}"
    response = requests.get(url, headers=HEADERS, verify=False, timeout=30)
    groups   = response.json().get("results", [])
    for g in groups:
        group_name = g.get("name")
        members    = g.get("member", [])
        updated    = [m for m in members if m.get("name") != username]
        if len(updated) != len(members):
            group_url = f"{BASE_URL}/user/group/{_safe_encode(group_name)}?vdom={vdom}"
            requests.put(group_url, headers=HEADERS, json={"member": updated}, verify=False, timeout=30)


# -------------------------------------------------------
# Search by user group
# -------------------------------------------------------
@frappe.whitelist()
def search_by_user_group(search_term):
    results = frappe.db.sql("""
        SELECT name, custom_dfc_2_username, user_group, custom_virtual_domain, user_account_status
        FROM `tabDFC 2 User`
        WHERE user_group LIKE %s
        ORDER BY modified DESC
        LIMIT 500
    """, (f"%{search_term}%",), as_dict=True)
    return results


# -------------------------------------------------------
# Sync Users
# -------------------------------------------------------
@frappe.whitelist()
def sync_users_from_fortigate():
    try:
        vdom_res  = requests.get(f"{BASE_URL}/system/vdom", headers=HEADERS, verify=False, timeout=15)
        vdom_list = (
            [v.get("name") for v in vdom_res.json().get("results", []) if v.get("name")]
            if vdom_res.status_code == 200 else ["root"]
        )
        created = updated = skipped = 0

        for vdom in vdom_list:
            user_res  = requests.get(f"{BASE_URL}/user/local?vdom={vdom}",  headers=HEADERS, verify=False, timeout=20)
            group_res = requests.get(f"{BASE_URL}/user/group?vdom={vdom}",  headers=HEADERS, verify=False, timeout=20)
            users     = user_res.json().get("results", [])
            groups    = group_res.json().get("results", [])

            user_group_map = {}
            for g in groups:
                gname = (g.get("name") or "").strip()
                for m in g.get("member", []):
                    uname = (m.get("name") or "").strip()
                    if uname and uname not in user_group_map:
                        user_group_map[uname] = gname

            for u in users:
                fg_username = (u.get("name") or "").strip()
                if not fg_username:
                    skipped += 1
                    continue

                status     = u.get("status")
                user_group = user_group_map.get(fg_username)

                existing_name = frappe.db.get_value(
                    "DFC 2 User",
                    {"custom_dfc_2_username": fg_username, "custom_virtual_domain": vdom},
                    "name"
                )

                if existing_name:
                    try:
                        frappe.db.set_value("DFC 2 User", existing_name, {
                            "user_account_status":   1 if status == "enable" else 0,
                            "custom_virtual_domain": vdom,
                            "add_to_user_group":     1 if user_group else 0,
                            "user_group":            user_group or ""
                        })
                        updated += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC2 User Update Error: {fg_username}")
                        skipped += 1
                else:
                    try:
                        doc = frappe.get_doc({
                            "doctype":               "DFC 2 User",
                            "custom_dfc_2_username": fg_username,
                            "password":              "",
                            "user_account_status":   1 if status == "enable" else 0,
                            "custom_virtual_domain": vdom,
                            "add_to_user_group":     1 if user_group else 0,
                            "user_group":            user_group or ""
                        })
                        doc.flags.ignore_fortigate_sync = True
                        doc.flags.ignore_validate_links = True
                        doc.insert(ignore_permissions=True, ignore_links=True, ignore_mandatory=True)
                        created += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC2 User Insert Error: {fg_username}")
                        skipped += 1

        frappe.db.commit()
        return {"status": "success", "created": created, "updated": updated,
                "skipped": skipped, "vdoms_synced": vdom_list}

    except Exception as e:
        frappe.log_error(str(e), "Fortigate User Sync Error DFC2")
        return {"status": "error", "message": str(e)}


# -------------------------------------------------------
# Sync User Groups
# -------------------------------------------------------
@frappe.whitelist()
def sync_user_groups_from_fortigate():
    try:
        vdom_res  = requests.get(f"{BASE_URL}/system/vdom", headers=HEADERS, verify=False, timeout=15)
        vdom_list = (
            [v.get("name") for v in vdom_res.json().get("results", []) if v.get("name")]
            if vdom_res.status_code == 200 else ["root"]
        )
        created = updated = skipped = 0

        for vdom in vdom_list:
            response = requests.get(f"{BASE_URL}/user/group?vdom={vdom}", headers=HEADERS, verify=False, timeout=20)
            groups   = response.json().get("results", [])

            for g in groups:
                group_name = (g.get("name") or "").strip()
                if not group_name:
                    skipped += 1
                    continue

                raw_type   = (g.get("group-type") or "").lower()
                group_type = {
                    "firewall": "Firewall", "fsso-service": "FSSO",
                    "rsso":     "RSSO",     "guest": "Guest"
                }.get(raw_type, "Firewall")

                members  = g.get("member", [])
                existing = frappe.db.get_value(
                    "DFC 2 User Group",
                    {"group_name": group_name, "custom_virtual_domain": vdom},
                    "name"
                )

                if existing:
                    try:
                        doc = frappe.get_doc("DFC 2 User Group", existing)
                        doc.group_type            = group_type
                        doc.custom_virtual_domain = vdom
                        doc.members               = []
                        for m in members:
                            uname = (m.get("name") or "").strip()
                            if not uname:
                                continue
                            frappe_user_name = frappe.db.get_value(
                                "DFC 2 User",
                                {"custom_dfc_2_username": uname, "custom_virtual_domain": vdom},
                                "name"
                            )
                            if frappe_user_name:
                                doc.append("members", {"username": frappe_user_name})
                        doc.flags.ignore_fortigate_sync = True
                        doc.flags.ignore_validate_links = True
                        doc.save(ignore_permissions=True)
                        updated += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC2 User Group Update Error: {group_name}")
                        skipped += 1
                else:
                    try:
                        doc = frappe.get_doc({
                            "doctype":               "DFC 2 User Group",
                            "group_name":            group_name,
                            "group_type":            group_type,
                            "custom_virtual_domain": vdom,
                            "members":               []
                        })
                        for m in members:
                            uname = (m.get("name") or "").strip()
                            if not uname:
                                continue
                            frappe_user_name = frappe.db.get_value(
                                "DFC 2 User",
                                {"custom_dfc_2_username": uname, "custom_virtual_domain": vdom},
                                "name"
                            )
                            if frappe_user_name:
                                doc.append("members", {"username": frappe_user_name})
                        doc.flags.ignore_fortigate_sync = True
                        doc.insert(ignore_permissions=True, ignore_links=True, ignore_mandatory=True)
                        created += 1
                    except Exception as e:
                        frappe.log_error(str(e), f"DFC2 User Group Insert Error: {group_name}")
                        skipped += 1

        frappe.db.commit()
        return {"status": "success", "created": created, "updated": updated,
                "skipped": skipped, "vdoms_synced": vdom_list}

    except Exception as e:
        frappe.log_error(str(e), "Fortigate User Group Sync Error DFC2")
        return {"status": "error", "message": str(e)}


# -------------------------------------------------------
# User Group CRUD
# -------------------------------------------------------
@frappe.whitelist()
def create_fortigate_user_group(docname):
    doc  = frappe.get_doc("DFC 2 User Group", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"{BASE_URL}/user/group?vdom={vdom}"

    group_type_map       = {"Firewall": "firewall", "FSSO": "fsso-service", "RSSO": "rsso", "Guest": "guest"}
    fortigate_group_type = group_type_map.get(doc.group_type, "firewall")
    payload              = {"name": doc.group_name, "group-type": fortigate_group_type}

    if fortigate_group_type == "rsso":
        if not doc.custom_radius_attribute_value:
            frappe.throw("RADIUS Attribute Value is required for RSSO group type.")
        payload["sso-attribute-value"] = doc.custom_radius_attribute_value
    elif fortigate_group_type in ["firewall", "guest"]:
        members = [{"name": m.username.split("|")[0]} for m in doc.members if m.username]
        if members:
            payload["member"] = members

    response = requests.post(url, headers=HEADERS, json=payload, verify=False, timeout=30)
    if response.status_code != 200:
        frappe.throw(response.text)
    return f"User Group '{doc.group_name}' created successfully in FortiGate (VDOM: {vdom})"


@frappe.whitelist()
def update_fortigate_user_group(docname):
    doc  = frappe.get_doc("DFC 2 User Group", docname)
    vdom = doc.custom_virtual_domain or "root"

    group_type_map       = {"Firewall": "firewall", "FSSO": "fsso-service", "RSSO": "rsso", "Guest": "guest"}
    fortigate_group_type = group_type_map.get(doc.group_type, "firewall")

    get_url      = f"{BASE_URL}/user/group/{_safe_encode(doc.group_name)}?vdom={vdom}"
    get_response = requests.get(get_url, headers=HEADERS, verify=False, timeout=30)

    if get_response.status_code == 404:
        frappe.throw(f"Group '<b>{doc.group_name}</b>' not found in FortiGate (VDOM: {vdom}). Please create it first.")

    payload = {"name": doc.group_name}
    if fortigate_group_type == "rsso":
        if not doc.custom_radius_attribute_value:
            frappe.throw("RADIUS Attribute Value is required for RSSO group type.")
        payload["sso-attribute-value"] = doc.custom_radius_attribute_value
    elif fortigate_group_type in ["firewall", "guest"]:
        payload["member"] = [{"name": m.username.split("|")[0]} for m in doc.members if m.username]

    put_url  = f"{BASE_URL}/user/group/{_safe_encode(doc.group_name)}?vdom={vdom}"
    response = requests.put(put_url, headers=HEADERS, json=payload, verify=False, timeout=30)
    if response.status_code != 200:
        frappe.throw(response.text)
    return f"User Group '{doc.group_name}' updated successfully in FortiGate (VDOM: {vdom})"


@frappe.whitelist()
def rename_fortigate_user(docname, new_username, ticket_id=None, remarks=None):
    doc          = frappe.get_doc("DFC 2 User", docname)
    vdom         = doc.custom_virtual_domain or "root"
    old_username = doc.custom_dfc_2_username
    new_username = new_username.strip()

    if not new_username:
        frappe.throw("New username is required.")
    if old_username == new_username:
        frappe.throw("New username is same as current username.")
    if _check_duplicate_username_vdom(new_username, vdom, exclude_name=docname):
        frappe.throw(f"User '<b>{new_username}</b>' already exists in VDOM '<b>{vdom}</b>'.")

    try:
        plain_password = get_decrypted_password("DFC 2 User", docname, "password")
    except Exception:
        plain_password = doc.password

    del_url  = f"{BASE_URL}/user/local/{_safe_encode(old_username)}?vdom={vdom}"
    del_resp = requests.delete(del_url, headers=HEADERS, verify=False, timeout=30)
    if del_resp.status_code not in (200, 404):
        frappe.throw(f"Failed to delete old user '{old_username}' (status {del_resp.status_code}): {del_resp.text}")

    create_url  = f"{BASE_URL}/user/local?vdom={vdom}"
    payload     = {
        "name":   new_username, "type": "password",
        "passwd": plain_password or "",
        "status": "enable" if doc.user_account_status else "disable"
    }
    create_resp = requests.post(create_url, headers=HEADERS, json=payload, verify=False, timeout=30)
    create_json = {}
    try:
        create_json = create_resp.json()
    except Exception:
        pass

    if not (create_resp.status_code == 500 and create_json.get("error") == -5):
        if create_resp.status_code != 200 or create_json.get("status") != "success":
            frappe.throw(f"Failed to create new user '{new_username}' (status {create_resp.status_code}): {create_resp.text}")

    if plain_password:
        reset_password_via_ssh(new_username, plain_password, vdom)

    if doc.add_to_user_group and doc.user_group:
        remove_user_from_all_groups(old_username, vdom)
        add_user_to_group(new_username, doc.user_group, vdom)
    else:
        remove_user_from_all_groups(old_username, vdom)

    new_doc_name = f"{new_username}|{vdom}"
    doc.custom_dfc_2_username       = new_username
    doc.flags.ignore_fortigate_sync = True
    doc.save(ignore_permissions=True)
    frappe.rename_doc("DFC 2 User", docname, new_doc_name, force=True)

    if ticket_id:
        frappe.get_doc({
            "doctype": "Comment", "comment_type": "Info",
            "reference_doctype": "DFC 2 User", "reference_name": new_doc_name,
            "content": (
                f"<b>Action:</b> Rename User<br>"
                f"<b>Old Username:</b> {old_username}<br>"
                f"<b>New Username:</b> {new_username}<br>"
                f"<b>Ticket ID:</b> {ticket_id}"
                + (f"<br><b>Remarks:</b> {remarks}" if remarks else "")
            )
        }).insert(ignore_permissions=True)

    return {"status": "success", "message": f"User '<b>{old_username}</b>' renamed to '<b>{new_username}</b>' successfully."}


# -------------------------------------------------------
# Rename User Group — DFC 2
# -------------------------------------------------------
@frappe.whitelist()
def rename_fortigate_user_group(docname, new_group_name, ticket_id=None, remarks=None):
    doc            = frappe.get_doc("DFC 2 User Group", docname)
    vdom           = doc.custom_virtual_domain or "root"
    old_group_name = doc.group_name
    new_group_name = new_group_name.strip()

    if not new_group_name:
        frappe.throw("New group name is required.")
    if old_group_name == new_group_name:
        frappe.throw("New group name is same as current group name.")
    if _check_duplicate_group_name_vdom(new_group_name, vdom, exclude_name=docname):
        frappe.throw(f"User Group '<b>{new_group_name}</b>' already exists in VDOM '<b>{vdom}</b>'.")

    get_resp = requests.get(
        f"{BASE_URL}/user/group/{_safe_encode(old_group_name)}?vdom={vdom}",
        headers=HEADERS, verify=False, timeout=30
    )
    current_members = []
    current_type    = "firewall"
    if get_resp.status_code == 200:
        results         = get_resp.json().get("results", [])
        current_members = results[0].get("member", []) if results else []
        current_type    = results[0].get("group-type", "firewall") if results else "firewall"

    create_resp = requests.post(
        f"{BASE_URL}/user/group?vdom={vdom}",
        headers=HEADERS,
        json={"name": new_group_name, "group-type": current_type, "member": current_members},
        verify=False, timeout=30
    )
    create_json = {}
    try:
        create_json = create_resp.json()
    except Exception:
        pass

    if create_resp.status_code == 500 and create_json.get("error") == -5:
        pass
    elif create_resp.status_code != 200 or create_json.get("status") != "success":
        frappe.throw(
            f"Failed to create new group '{new_group_name}' in FortiGate "
            f"(status {create_resp.status_code}): {create_resp.text}"
        )

    del_resp = requests.delete(
        f"{BASE_URL}/user/group/{_safe_encode(old_group_name)}?vdom={vdom}",
        headers=HEADERS, verify=False, timeout=30
    )
    if del_resp.status_code not in (200, 404):
        frappe.throw(
            f"New group '{new_group_name}' was created but deleting '{old_group_name}' failed "
            f"(status {del_resp.status_code}). Please delete '{old_group_name}' manually from FortiGate."
        )

    new_doc_name = f"{new_group_name}|{vdom}"
    doc.flags.ignore_fortigate_sync = True
    doc.group_name = new_group_name
    doc.save(ignore_permissions=True)
    frappe.rename_doc("DFC 2 User Group", docname, new_doc_name, force=True)

    if ticket_id:
        frappe.get_doc({
            "doctype": "Comment", "comment_type": "Info",
            "reference_doctype": "DFC 2 User Group", "reference_name": new_doc_name,
            "content": (
                f"<b>Action:</b> Rename Group<br>"
                f"<b>Old Group Name:</b> {old_group_name}<br>"
                f"<b>New Group Name:</b> {new_group_name}<br>"
                f"<b>Ticket ID:</b> {ticket_id}"
                + (f"<br><b>Remarks:</b> {remarks}" if remarks else "")
            )
        }).insert(ignore_permissions=True)

    return {"status": "success", "message": f"Group '<b>{old_group_name}</b>' renamed to '<b>{new_group_name}</b>' successfully."}


@frappe.whitelist()
def get_frappe_users(vdom="root"):
    """Returns Frappe DFC 2 User doc names (username|VDOM) for the given VDOM."""
    results = frappe.db.get_all(
        "DFC 2 User",
        filters={"custom_virtual_domain": vdom},
        fields=["name"],
        order_by="name asc"
    )
    return [r.name for r in results]
