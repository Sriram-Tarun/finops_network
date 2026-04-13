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
FORTIGATE_IP       = "45.198.61.18"
API_TOKEN          = "H1yt7w4Q0g6r3nyc1kzg504k7bnQHm"

FORTIGATE_SSH_IP   = "45.198.61.18"
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
    if "(" in last_line and ")" in last_line:
        return "vdom"
    return "global"


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
            _ssh_send(shell, "config user local",                        wait=1.5)
            out_edit   = _ssh_send(shell, f'edit "{username}"',          wait=1.5)
            out_passwd = _ssh_send(shell, f"set passwd {new_password}",  wait=3.0)
            out_next   = _ssh_send(shell, "next",                        wait=1.5)
            out_end    = _ssh_send(shell, "end",                         wait=1.5)
            _ssh_send(shell, "exit",                                      wait=0.5)
            full_output = (out_edit + out_passwd + out_next + out_end).lower()
        else:
            _ssh_send(shell, "config vdom",                              wait=1.5)
            out_vdom   = _ssh_send(shell, f"edit {vdom}",                wait=1.5)
            _ssh_send(shell, "config user local",                        wait=1.5)
            out_edit   = _ssh_send(shell, f'edit "{username}"',          wait=1.5)
            out_passwd = _ssh_send(shell, f"set passwd {new_password}",  wait=3.0)
            out_next   = _ssh_send(shell, "next",                        wait=1.5)
            out_end1   = _ssh_send(shell, "end",                         wait=1.5)
            out_end2   = _ssh_send(shell, "end",                         wait=1.5)
            _ssh_send(shell, "exit",                                      wait=0.5)
            full_output = (out_vdom + out_edit + out_passwd + out_next + out_end1 + out_end2).lower()

        ssh.close()

        policy_indicators = [
            "must have", "minimum length", "too simple", "too short",
            "same as", "password policy", "password strength",
        ]
        for indicator in policy_indicators:
            if indicator in full_output:
                frappe.throw(
                    f"Password policy violation for user '{username}': "
                    f"FortiGate rejected the password -- check complexity rules.\n\nSSH output:\n{full_output}"
                )

        error_indicators = [
            "command fail", "entry not found", "object not found",
            "unknown action", "permission denied",
        ]
        for indicator in error_indicators:
            if indicator in full_output:
                frappe.throw(
                    f"SSH password reset failed for user '{username}' in VDOM '{vdom}'.\n\n"
                    f"Detected scope: {scope}\n\nSSH output:\n{full_output}"
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
        frappe.throw(f"SSH Password Reset Failed: {str(e)}")


# -------------------------------------------------------
# Frappe Document Hook ï¿½ fires on every Save
# -------------------------------------------------------
def on_save(doc, method):
    """
    Called automatically by Frappe on every Save of a Fortigate User doc.
    The plain-text password is available here because Frappe has not yet
    cleared/hashed it ï¿½ on_save fires BEFORE the doc is written to DB.

    Logic:
      - If user does not exist in FortiGate ? Create
      - If user already exists in FortiGate ? Update
    """
    vdom           = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    
    try:
        plain_password = get_decrypted_password("DFC 3 User", doc.name, "password")
    except Exception:
        plain_password = doc.password

    # Check if user already exists in FortiGate
    check_url  = f"{BASE_URL}/user/local/{_safe_encode(doc.username)}?vdom={vdom}"
    check_resp = requests.get(check_url, headers=HEADERS, verify=False, timeout=15)
    user_exists = (
        check_resp.status_code == 200
        and check_resp.json().get("results")
    )

    if not user_exists:
        # ---- CREATE ----
        url     = f"{BASE_URL}/user/local?vdom={vdom}"
        payload = {
            "name":   doc.username,
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
                frappe.throw(
                    f"DFC 3 User creation failed: "
                    f"{response_json.get('error_msg', response.text)}"
                )
        elif response.status_code == 500 and response_json.get("error") == -5:
            pass  # already exists ï¿½ fall through to update path below
        else:
            frappe.throw(
                f"Failed to create user '{doc.username}' in FortiGate "
                f"(status {response.status_code}): {response.text}"
            )

        frappe.msgprint(
            f"User '<b>{doc.username}</b>' created in FortiGate (VDOM: {vdom})",
            indicator="green", alert=True
        )
    else:
        # ---- UPDATE ----
        url     = f"{BASE_URL}/user/local/{_safe_encode(doc.username)}?vdom={vdom}"
        payload = {"status": "enable" if doc.user_account_status else "disable"}
        response = requests.put(url, headers=HEADERS, json=payload, verify=False, timeout=30)
        if response.status_code != 200:
            frappe.throw(
                f"Failed to update status for '{doc.username}' in FortiGate "
                f"(status {response.status_code}): {response.text}"
            )

        frappe.msgprint(
            f"User '<b>{doc.username}</b>' updated in FortiGate (VDOM: {vdom})",
            indicator="blue", alert=True
        )

    # ---- Set password via SSH if a password was provided ----
    if plain_password:
        reset_password_via_ssh(doc.username, plain_password, vdom)

    # ---- Group membership ----
    if doc.add_to_user_group and doc.user_group:
        if user_exists:
            update_user_group(doc.username, doc.user_group, vdom)
        else:
            add_user_to_group(doc.username, doc.user_group, vdom)
    else:
        remove_user_from_all_groups(doc.username, vdom)


# -------------------------------------------------------
# Frappe Document Hook ï¿½ fires on Delete
# -------------------------------------------------------
def on_trash(doc, method):
    """Auto-delete from FortiGate when the Frappe doc is deleted."""
    vdom     = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    url      = f"{BASE_URL}/user/local/{_safe_encode(doc.username)}?vdom={vdom}"
    response = requests.delete(url, headers=HEADERS, verify=False, timeout=30)
    if response.status_code not in (200, 404):
        frappe.throw(
            f"Failed to delete '{doc.username}' from FortiGate "
            f"(status {response.status_code}): {response.text}"
        )


# -------------------------------------------------------
# Get User Groups
# -------------------------------------------------------
@frappe.whitelist()
def get_user_groups(vdom="root"):
    url      = f"{BASE_URL}/user/group?vdom={vdom}"
    response = requests.get(url, headers=HEADERS, verify=False, timeout=30)
    data     = response.json()
    return [g.get("name") for g in data.get("results", []) if g.get("name")]


# -------------------------------------------------------
# Manual buttons ï¿½ kept for backward compatibility
# but on_save now handles everything automatically
# -------------------------------------------------------
@frappe.whitelist()
def create_fortigate_user(docname, password=None):
    doc  = frappe.get_doc("DFC 3 User", docname)
    vdom = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    try:
        plain_password = password or get_decrypted_password("DFC 3 User", docname, "password")
    except Exception:
        plain_password = password or doc.password

    url     = f"{BASE_URL}/user/local?vdom={vdom}"
    payload = {
        "name":   doc.username,
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
    elif response.status_code == 500:
        if response_json.get("error") == -5:
            frappe.throw(f"User '{doc.username}' already exists in FortiGate (VDOM: {vdom}).")
        else:
            frappe.throw(f"FortiGate error (500): {response_json.get('error_msg', response.text)}")
    elif response.status_code == 400:
        error_msg = response_json.get("error_msg", response_json.get("message", response.text))
        frappe.throw(f"Bad request (400): {error_msg}")
    else:
        frappe.throw(f"Failed to create user '{doc.username}' (status {response.status_code}): {response.text}")

    if plain_password:
        reset_password_via_ssh(doc.username, plain_password, vdom)

    if doc.add_to_user_group and doc.user_group:
        add_user_to_group(doc.username, doc.user_group, vdom)
    else:
        remove_user_from_all_groups(doc.username, vdom)

    return f"User '{doc.username}' created successfully in FortiGate (VDOM: {vdom})"


@frappe.whitelist()
def update_fortigate_user(docname, password=None):
    doc  = frappe.get_doc("DFC 3 User", docname)
    vdom = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    try:
        plain_password = password or get_decrypted_password("DFC 3 User", docname, "password")
    except Exception:
        plain_password = password or doc.password

    url      = f"{BASE_URL}/user/local/{_safe_encode(doc.username)}?vdom={vdom}"
    payload  = {"status": "enable" if doc.user_account_status else "disable"}
    response = requests.put(url, headers=HEADERS, json=payload, verify=False, timeout=30)
    if response.status_code != 200:
        frappe.throw(f"Failed to update status for '{doc.username}' (status {response.status_code}): {response.text}")

    if plain_password:
        reset_password_via_ssh(doc.username, plain_password, vdom)

    if doc.add_to_user_group and doc.user_group:
        update_user_group(doc.username, doc.user_group, vdom)
    else:
        remove_user_from_all_groups(doc.username, vdom)

    return f"User '{doc.username}' updated successfully in FortiGate (VDOM: {vdom})"


@frappe.whitelist()
def delete_fortigate_user(docname):
    doc      = frappe.get_doc("DFC 3 User", docname)
    vdom     = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    url      = f"{BASE_URL}/user/local/{_safe_encode(doc.username)}?vdom={vdom}"
    response = requests.delete(url, headers=HEADERS, verify=False, timeout=30)

    if response.status_code == 404:
        return f"User '{doc.username}' was already absent from FortiGate (VDOM: {vdom})"
    if response.status_code != 200:
        frappe.throw(f"Failed to delete user '{doc.username}' (status {response.status_code}): {response.text}")

    return f"User '{doc.username}' deleted successfully from FortiGate (VDOM: {vdom})"


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
# Get Firewall Users
# -------------------------------------------------------
@frappe.whitelist()
def get_firewall_users(vdom="root"):
    url      = f"{BASE_URL}/user/local?vdom={vdom}"
    response = requests.get(url, headers=HEADERS, verify=False, timeout=30)
    return [u.get("name") for u in response.json().get("results", []) if u.get("name")]


# -------------------------------------------------------
# Create User Group
# -------------------------------------------------------
@frappe.whitelist()
def create_fortigate_user_group(docname):
    doc  = frappe.get_doc("DFC 3 User Group", docname)
    vdom = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    url  = f"{BASE_URL}/user/group?vdom={vdom}"

    group_type_map       = {
        "Firewall": "firewall", "FSSO": "fsso-service",
        "RSSO":     "rsso",     "Guest": "guest"
    }
    fortigate_group_type = group_type_map.get(doc.group_type, "firewall")
    payload              = {"name": doc.group_name, "group-type": fortigate_group_type}

    if fortigate_group_type == "rsso":
        if not doc.custom_radius_attribute_value:
            frappe.throw("RADIUS Attribute Value is required for RSSO group type.")
        payload["sso-attribute-value"] = doc.custom_radius_attribute_value
    elif fortigate_group_type in ["firewall", "guest"]:
        members = [{"name": m.username} for m in doc.members if m.username]
        if members:
            payload["member"] = members

    response = requests.post(url, headers=HEADERS, json=payload, verify=False, timeout=30)
    if response.status_code != 200:
        frappe.throw(response.text)

    return f"User Group '{doc.group_name}' created successfully in FortiGate (VDOM: {vdom})"


# -------------------------------------------------------
# Update User Group
# -------------------------------------------------------
@frappe.whitelist()
def update_fortigate_user_group(docname):
    doc  = frappe.get_doc("DFC 3 User Group", docname)
    vdom = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"

    group_type_map       = {
        "Firewall": "firewall", "FSSO": "fsso-service",
        "RSSO":     "rsso",     "Guest": "guest"
    }
    fortigate_group_type = group_type_map.get(doc.group_type, "firewall")

    get_url      = f"{BASE_URL}/user/group/{_safe_encode(doc.group_name)}?vdom={vdom}"
    get_response = requests.get(get_url, headers=HEADERS, verify=False, timeout=30)

    if get_response.status_code == 404:
        frappe.throw(
            f"Group '<b>{doc.group_name}</b>' not found in FortiGate (VDOM: {vdom}).<br><br>"
            f"Please click <b>Create Group in Fortigate</b> first."
        )

    results                = get_response.json().get("results", [])
    current_fortigate_type = results[0].get("group-type", "firewall") if results else "firewall"

    if current_fortigate_type != fortigate_group_type:
        frappe.throw(
            f"FortiGate does not allow changing Group Type on an existing group via API.<br><br>"
            f"<b>Current type in FortiGate:</b> {current_fortigate_type}<br>"
            f"<b>Requested type in Portal:</b> {fortigate_group_type}<br><br>"
            f"To change the group type, delete the group in FortiGate then recreate it."
        )

    payload = {"name": doc.group_name}
    if fortigate_group_type == "rsso":
        if not doc.custom_radius_attribute_value:
            frappe.throw("RADIUS Attribute Value is required for RSSO group type.")
        payload["sso-attribute-value"] = doc.custom_radius_attribute_value
    elif fortigate_group_type in ["firewall", "guest"]:
        payload["member"] = [{"name": m.username} for m in doc.members if m.username]

    put_url  = f"{BASE_URL}/user/group/{_safe_encode(doc.group_name)}?vdom={vdom}"
    response = requests.put(put_url, headers=HEADERS, json=payload, verify=False, timeout=30)
    if response.status_code != 200:
        frappe.throw(response.text)

    return f"User Group '{doc.group_name}' updated successfully in FortiGate (VDOM: {vdom})"


# -------------------------------------------------------
# Get Group Members
# -------------------------------------------------------
@frappe.whitelist()
def get_group_members(group_name, vdom="root"):
    url      = f"{BASE_URL}/user/group/{_safe_encode(group_name)}?vdom={vdom}"
    response = requests.get(url, headers=HEADERS, verify=False, timeout=30)
    results  = response.json().get("results", [])
    if results:
        return [m.get("name") for m in results[0].get("member", []) if m.get("name")]
    return []


# -------------------------------------------------------
# Sync Users from FortiGate
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
                username = (u.get("name") or "").strip()
                if not username:
                    skipped += 1
                    continue
                status     = u.get("status")
                user_group = user_group_map.get(username)
                existing   = frappe.db.exists("DFC 3 User", {"username": username})

                if existing:
                    doc = frappe.get_doc("DFC 3 User", existing)
                    doc.user_account_status   = 1 if status == "enable" else 0
                    doc.custom_virtual_domain = vdom
                    doc.add_to_user_group     = 1 if user_group else 0
                    doc.user_group            = user_group or ""
                    doc.flags.ignore_fortigate_sync = True  # prevent re-syncing back
                    doc.save(ignore_permissions=True)
                    updated += 1
                else:
                    try:
                        doc = frappe.get_doc({
                            "doctype": "DFC 3 User", "username": username, "password": "",
                            "user_account_status":   1 if status == "enable" else 0,
                            "custom_virtual_domain": vdom,
                            "add_to_user_group":     1 if user_group else 0,
                            "user_group":            user_group or ""
                        })
                        doc.flags.ignore_fortigate_sync = True  # prevent re-syncing back
                        doc.insert(ignore_permissions=True)
                        created += 1
                    except Exception:
                        skipped += 1

        frappe.db.commit()
        return {"status": "success", "created": created, "updated": updated,
                "skipped": skipped, "vdoms_synced": vdom_list}

    except Exception as e:
        frappe.log_error(str(e), "Fortigate User Sync Error")
        return {"status": "error", "message": str(e)}


# -------------------------------------------------------
# Sync User Groups from FortiGate
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
                existing = frappe.db.exists("DFC 3 User Group", {"group_name": group_name})

                if existing:
                    doc = frappe.get_doc("DFC 3 User Group", existing)
                    doc.group_type            = group_type
                    doc.custom_virtual_domain = vdom
                    doc.members               = []
                    for m in members:
                        uname = (m.get("name") or "").strip()
                        if uname:
                            doc.append("members", {"username": uname})
                    doc.save(ignore_permissions=True)
                    updated += 1
                else:
                    try:
                        doc = frappe.get_doc({
                            "doctype": "DFC 3 User Group", "group_name": group_name,
                            "group_type": group_type, "custom_virtual_domain": vdom, "members": []
                        })
                        for m in members:
                            uname = (m.get("name") or "").strip()
                            if uname:
                                doc.append("members", {"username": uname})
                        doc.insert(ignore_permissions=True)
                        created += 1
                    except Exception:
                        skipped += 1

        frappe.db.commit()
        return {"status": "success", "created": created, "updated": updated,
                "skipped": skipped, "vdoms_synced": vdom_list}

    except Exception as e:
        frappe.log_error(str(e), "Fortigate User Group Sync Error")
        return {"status": "error", "message": str(e)}


# -------------------------------------------------------
# Get VDOMs
# -------------------------------------------------------
@frappe.whitelist()
def get_vdoms():
    url = f"{BASE_URL}/system/vdom"
    try:
        response = requests.get(url, headers=HEADERS, verify=False, timeout=15)
        if response.status_code == 200:
            vdoms = [
                v.get("name") for v in response.json().get("results", [])
                if v.get("name")
            ]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error")
        return {"status": "error", "message": str(e)}


# -------------------------------------------------------
# Debug helper (remove after testing)
# -------------------------------------------------------
@frappe.whitelist()
def debug_ssh_password_reset(username, password, vdom="root"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=FORTIGATE_SSH_IP, port=FORTIGATE_SSH_PORT,
        username=FORTIGATE_SSH_USER, password=FORTIGATE_SSH_PASS,
        look_for_keys=False, allow_agent=False, timeout=15
    )
    shell  = ssh.invoke_shell(width=220, height=50)
    banner = _ssh_read(shell, wait=3.0, max_wait=10.0)
    scope  = _detect_scope(banner)
    log    = [f"=== BANNER (scope={scope}) ===", banner, "=== COMMANDS ==="]

    def send_log(cmd, wait=1.5):
        shell.send(cmd + "\n")
        out = _ssh_read(shell, wait=wait)
        log.append(f"CMD: {repr(cmd)}")
        log.append(f"OUT: {repr(out)}")
        return out

    if scope == "vdom":
        send_log("config user local")
        send_log(f'edit "{username}"')
        send_log(f"set passwd {password}", wait=3.0)
        send_log("next")
        send_log("end")
    else:
        send_log("config vdom")
        send_log(f"edit {vdom}")
        send_log("config user local")
        send_log(f'edit "{username}"')
        send_log(f"set passwd {password}", wait=3.0)
        send_log("next")
        send_log("end")
        send_log("end")

    send_log("exit", wait=0.5)
    ssh.close()
    return "\n".join(log)

@frappe.whitelist()
def search_by_user_group(search_term):
    results = frappe.db.sql("""
        SELECT name, username, user_group, custom_virtual_domain, user_account_status
        FROM `tabDFC 3 User`
        WHERE user_group LIKE %s
        ORDER BY modified DESC
        LIMIT 500
    """, (f"%{search_term}%",), as_dict=True)
    return results

# -------------------------------------------------------
# Rename User in Fortigate + Frappe
# -------------------------------------------------------
@frappe.whitelist()
def rename_fortigate_user(docname, new_username, ticket_id=None, remarks=None):
    doc  = frappe.get_doc("DFC 3 User", docname)
    vdom = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    old_username = doc.username

    new_username = new_username.strip()

    if not new_username:
        frappe.throw("New username is required.")
    if old_username == new_username:
        frappe.throw("New username is same as current username.")

    try:
        plain_password = get_decrypted_password("DFC 3 User", docname, "password")
    except Exception:
        plain_password = doc.password

    # Step 1: Delete old user from FortiGate
    del_url  = f"{BASE_URL}/user/local/{_safe_encode(old_username)}?vdom={vdom}"
    del_resp = requests.delete(del_url, headers=HEADERS, verify=False, timeout=30)
    if del_resp.status_code not in (200, 404):
        frappe.throw(
            f"Failed to delete old user '{old_username}' in FortiGate "
            f"(status {del_resp.status_code}): {del_resp.text}"
        )

    # Step 2: Check if new username already exists in FortiGate, delete if so
    check_new_url  = f"{BASE_URL}/user/local/{_safe_encode(new_username)}?vdom={vdom}"
    check_new_resp = requests.get(check_new_url, headers=HEADERS, verify=False, timeout=15)
    if check_new_resp.status_code == 200 and check_new_resp.json().get("results"):
        requests.delete(check_new_url, headers=HEADERS, verify=False, timeout=30)

    # Step 2b: Create new user in FortiGate
    create_url = f"{BASE_URL}/user/local?vdom={vdom}"
    payload    = {
        "name":   new_username,
        "type":   "password",
        "passwd": plain_password or "",
        "status": "enable" if doc.user_account_status else "disable"
    }
    create_resp = requests.post(create_url, headers=HEADERS, json=payload, verify=False, timeout=30)
    create_json = {}
    try:
        create_json = create_resp.json()
    except Exception:
        pass

    if create_resp.status_code == 500 and create_json.get("error") == -5:
        pass  # already exists — fine, continue
    elif create_resp.status_code != 200:
        frappe.throw(
            f"Failed to create new user '{new_username}' in FortiGate "
            f"(status {create_resp.status_code}): {create_resp.text}"
        )
    elif create_json.get("status") != "success":
        frappe.throw(f"FortiGate error: {create_json.get('error_msg', create_resp.text)}")
    # Step 3: Set password via SSH
    if plain_password:
        reset_password_via_ssh(new_username, plain_password, vdom)

    # Step 4: Handle group membership
    if doc.add_to_user_group and doc.user_group:
        remove_user_from_all_groups(old_username, vdom)
        add_user_to_group(new_username, doc.user_group, vdom)
    else:
        remove_user_from_all_groups(old_username, vdom)

    # Step 5: Rename Frappe doc
    frappe.rename_doc("DFC 3 User", docname, new_username, force=True)

    # Step 6: Log ticket activity
    if ticket_id:
        frappe.get_doc({
            "doctype": "Comment",
            "comment_type": "Info",
            "reference_doctype": "DFC 3 User",
            "reference_name": new_username,
            "content": (
                f"<b>Action:</b> Rename User<br>"
                f"<b>Old Username:</b> {old_username}<br>"
                f"<b>New Username:</b> {new_username}<br>"
                f"<b>Ticket ID:</b> {ticket_id}"
                + (f"<br><b>Remarks:</b> {remarks}" if remarks else "")
            )
        }).insert(ignore_permissions=True)

    return {
        "status": "success",
        "message": f"User '<b>{old_username}</b>' renamed to '<b>{new_username}</b>' successfully in FortiGate and Portal."
    }


# -------------------------------------------------------
# Rename User Group in Fortigate + Frappe
# -------------------------------------------------------
@frappe.whitelist()
def rename_fortigate_user_group(docname, new_group_name, ticket_id=None, remarks=None):
    doc  = frappe.get_doc("DFC 3 User Group", docname)
    vdom = doc.custom_virtual_domain if doc.custom_virtual_domain else "root"
    old_group_name = doc.group_name

    new_group_name = new_group_name.strip()

    if not new_group_name:
        frappe.throw("New group name is required.")
    if old_group_name == new_group_name:
        frappe.throw("New group name is same as current group name.")

    # Step 1: Get current members from FortiGate
    get_url  = f"{BASE_URL}/user/group/{_safe_encode(old_group_name)}?vdom={vdom}"
    get_resp = requests.get(get_url, headers=HEADERS, verify=False, timeout=30)
    current_members = []
    current_type    = "firewall"
    if get_resp.status_code == 200:
        results         = get_resp.json().get("results", [])
        current_members = results[0].get("member", []) if results else []
        current_type    = results[0].get("group-type", "firewall") if results else "firewall"

    # Step 2: Check if new group name already exists, delete if so
    check_new_url  = f"{BASE_URL}/user/group/{_safe_encode(new_group_name)}?vdom={vdom}"
    check_new_resp = requests.get(check_new_url, headers=HEADERS, verify=False, timeout=15)
    if check_new_resp.status_code == 200 and check_new_resp.json().get("results"):
        requests.delete(check_new_url, headers=HEADERS, verify=False, timeout=30)

    # Step 3: Create new group in FortiGate with same type and members
    create_url  = f"{BASE_URL}/user/group?vdom={vdom}"
    payload     = {
        "name":       new_group_name,
        "group-type": current_type,
        "member":     current_members
    }
    create_resp = requests.post(create_url, headers=HEADERS, json=payload, verify=False, timeout=30)
    create_json = {}
    try:
        create_json = create_resp.json()
    except Exception:
        pass

    if create_resp.status_code == 500 and create_json.get("error") == -5:
        pass  # already exists — fine
    elif create_resp.status_code != 200:
        frappe.throw(
            f"Failed to create new group '{new_group_name}' in FortiGate "
            f"(status {create_resp.status_code}): {create_resp.text}"
        )
    elif create_json.get("status") != "success":
        frappe.throw(f"FortiGate error: {create_json.get('error_msg', create_resp.text)}")

    # Step 4: Delete old group from FortiGate
    del_url  = f"{BASE_URL}/user/group/{_safe_encode(old_group_name)}?vdom={vdom}"
    del_resp = requests.delete(del_url, headers=HEADERS, verify=False, timeout=30)
    if del_resp.status_code not in (200, 404):
        frappe.throw(
            f"Failed to delete old group '{old_group_name}' in FortiGate "
            f"(status {del_resp.status_code}): {del_resp.text}"
        )

    # Step 5: Update Frappe doc group_name field and rename doc
    doc.flags.ignore_fortigate_sync = True
    doc.group_name = new_group_name
    doc.save(ignore_permissions=True)
    frappe.rename_doc("DFC 3 User Group", docname, new_group_name, force=True)

    # Step 6: Log ticket activity
    if ticket_id:
        frappe.get_doc({
            "doctype": "Comment",
            "comment_type": "Info",
            "reference_doctype": "DFC 3 User Group",
            "reference_name": new_group_name,
            "content": (
                f"<b>Action:</b> Rename Group<br>"
                f"<b>Old Group Name:</b> {old_group_name}<br>"
                f"<b>New Group Name:</b> {new_group_name}<br>"
                f"<b>Ticket ID:</b> {ticket_id}"
                + (f"<br><b>Remarks:</b> {remarks}" if remarks else "")
            )
        }).insert(ignore_permissions=True)

    return {
        "status": "success",
        "message": f"Group '<b>{old_group_name}</b>' renamed to '<b>{new_group_name}</b>' successfully in FortiGate and Portal."
    }