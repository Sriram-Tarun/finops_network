import frappe
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()

FIREWALL_IP = "45.198.225.33"
API_TOKEN   = "ryGrNswGtt7cqj577fNr0x7fqGH5j1"
HEADERS     = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type":  "application/json"
}
BASE_URL = f"https://{FIREWALL_IP}/api/v2/cmdb"


# -------------------------------------------------------
# Interface name helpers
# -------------------------------------------------------
def extract_raw_interface_name(display_name):
    if display_name and "(" in display_name and display_name.endswith(")"):
        return display_name[display_name.rfind("(") + 1:-1].strip()
    return (display_name or "").strip()


def _build_interface_map(vdom):
    try:
        r = requests.get(
            f"{BASE_URL}/system/interface?vdom={vdom}",
            headers=HEADERS, verify=False, timeout=15
        )
        iface_map = {}
        for iface in r.json().get("results", []):
            raw_name  = iface.get("name") or ""
            alias_val = iface.get("alias") or ""
            if not raw_name:
                continue
            display = f"{alias_val} ({raw_name})" if alias_val else raw_name
            iface_map[raw_name] = display
        return iface_map
    except Exception:
        return {}


# -------------------------------------------------------
# Fetch helpers
# -------------------------------------------------------
def _fetch_vdoms():
    try:
        r = requests.get(
            f"{BASE_URL}/system/vdom",
            headers=HEADERS, verify=False, timeout=15
        )
        if r.status_code == 200:
            return [v.get("name") for v in r.json().get("results", []) if v.get("name")]
    except Exception:
        pass
    return ["root"]


def _fetch_policies(vdom):
    try:
        r = requests.get(
            f"{BASE_URL}/firewall/policy?vdom={vdom}",
            headers=HEADERS, verify=False, timeout=30
        )
        return r.json().get("results", [])
    except Exception:
        return []


def _fetch_services_for_vdom(vdom):
    services  = []
    endpoints = [
        f"{BASE_URL}/firewall.service/custom?vdom={vdom}",
        f"{BASE_URL}/firewall.service/group?vdom={vdom}",
    ]
    try:
        for ep in endpoints:
            r = requests.get(ep, headers=HEADERS, verify=False, timeout=15)
            for svc in r.json().get("results", []):
                if svc.get("name"):
                    services.append(svc["name"])
        r = requests.get(
            f"{BASE_URL}/firewall.service/category?vdom={vdom}",
            headers=HEADERS, verify=False, timeout=15
        )
        for cat in r.json().get("results", []):
            for m in cat.get("member", []):
                if m.get("name"):
                    services.append(m["name"])
        return sorted(set(filter(None, services)))
    except Exception:
        return []


def _fetch_one_address_endpoint(url):
    try:
        r = requests.get(url, headers=HEADERS, verify=False, timeout=15)
        if r.status_code == 200:
            return [
                item.get("name") for item in r.json().get("results", [])
                if item.get("name")
            ]
    except Exception:
        pass
    return []


# -------------------------------------------------------
# Policy CRUD
# -------------------------------------------------------
@frappe.whitelist()
def create_policy(docname):
    doc  = frappe.get_doc("DFC 1 Policy", docname)
    vdom = doc.custom_virtual_domain or "root"
    url  = f"{BASE_URL}/firewall/policy?vdom={vdom}"

    nat_value    = "enable" if doc.nat else "disable"
    status_value = "enable" if doc.enable_this_policy else "disable"
    services     = [{"name": row.service} for row in doc.custom_services]

    payload = {
        "name":     doc.policy_name,
        "srcintf":  [{"name": extract_raw_interface_name(doc.incoming_interface)}],
        "dstintf":  [{"name": extract_raw_interface_name(doc.outgoing_interface)}],
        "srcaddr":  [{"name": doc.source}],
        "dstaddr":  [{"name": doc.destination}],
        "service":  services,
        "schedule": "always",
        "action":   "accept",
        "nat":      nat_value,
        "status":   status_value
    }

    if doc.ip_pool_configuration == "Use Dynamic IP Pool" and doc.custom_ip_pool:
        payload["ippool"]   = "enable"
        payload["poolname"] = [{"name": doc.custom_ip_pool}]

    try:
        response = requests.post(url, headers=HEADERS, json=payload, verify=False, timeout=20)
        if response.status_code == 200:
            result    = response.json()
            policy_id = result.get("mkey")
            if policy_id:
                doc.custom_firewall_policy_id = policy_id
                doc.save(ignore_permissions=True)
            return {"status": "success", "message": f"Policy created (ID: {policy_id}) in VDOM: {vdom}"}
        return {"status": "error", "message": response.text}
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Policy Error DFC1")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def update_policy(docname):
    doc = frappe.get_doc("DFC 1 Policy", docname)
    if not doc.custom_firewall_policy_id:
        frappe.throw("Policy not created in FortiGate yet")

    vdom = doc.custom_virtual_domain or "root"
    url  = f"{BASE_URL}/firewall/policy/{doc.custom_firewall_policy_id}?vdom={vdom}"

    nat_value    = "enable" if doc.nat else "disable"
    status_value = "enable" if doc.enable_this_policy else "disable"

    services = []
    for row in doc.custom_services:
        if row.service:
            svc_doc     = frappe.db.get_value("DFC 1 Service", row.service, "service_name", as_dict=True)
            actual_name = svc_doc.service_name if svc_doc else row.service
            services.append({"name": actual_name})

    payload = {
        "name":     doc.policy_name,
        "srcintf":  [{"name": extract_raw_interface_name(doc.incoming_interface)}],
        "dstintf":  [{"name": extract_raw_interface_name(doc.outgoing_interface)}],
        "srcaddr":  [{"name": doc.source}],
        "dstaddr":  [{"name": doc.destination}],
        "service":  services,
        "schedule": "always",
        "action":   "accept",
        "nat":      nat_value,
        "status":   status_value
    }

    if doc.ip_pool_configuration == "Use Dynamic IP Pool" and doc.custom_ip_pool:
        payload["ippool"]   = "enable"
        payload["poolname"] = [{"name": doc.custom_ip_pool}]

    response = requests.put(url, headers=HEADERS, json=payload, verify=False, timeout=20)
    if response.status_code != 200:
        frappe.throw(response.text)

    return f"Policy updated successfully (VDOM: {vdom})"


# -------------------------------------------------------
# Get helpers
# -------------------------------------------------------
@frappe.whitelist()
def get_vdoms():
    try:
        r = requests.get(
            f"{BASE_URL}/system/vdom",
            headers=HEADERS, verify=False, timeout=15
        )
        if r.status_code == 200:
            vdoms = [v.get("name") for v in r.json().get("results", []) if v.get("name")]
            return {"status": "success", "vdoms": vdoms}
        return {"status": "error", "message": r.text}
    except Exception as e:
        frappe.log_error(str(e), "FortiGate Get VDOMs Error DFC1 Policy")
        return {"status": "error", "message": str(e)}


@frappe.whitelist()
def get_interfaces(vdom="root"):
    try:
        response = requests.get(
            f"{BASE_URL}/system/interface?vdom={vdom}",
            headers=HEADERS, verify=False, timeout=15
        )
        result = []
        for i in response.json().get("results", []):
            raw_name   = i.get("name") or ""
            alias_val  = i.get("alias") or ""
            iface_vdom = i.get("vdom") or ""
            if not raw_name or iface_vdom != vdom:
                continue
            display = f"{alias_val} ({raw_name})" if alias_val else raw_name
            result.append(display)
        return result
    except Exception as e:
        frappe.log_error(str(e), "Fortigate Interface Fetch Error DFC1")
        return []


@frappe.whitelist()
def get_addresses(vdom="root"):
    endpoints = [
        f"{BASE_URL}/firewall/address?vdom={vdom}",
        f"{BASE_URL}/firewall/addrgrp?vdom={vdom}",
        f"{BASE_URL}/firewall/vip?vdom={vdom}",
        f"{BASE_URL}/firewall/vipgrp?vdom={vdom}",
        f"{BASE_URL}/firewall/internet-service?vdom={vdom}",
        f"{BASE_URL}/user/local?vdom={vdom}",
        f"{BASE_URL}/user/group?vdom={vdom}",
    ]

    all_names = []
    with ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
        future_to_url = {
            executor.submit(_fetch_one_address_endpoint, url): url
            for url in endpoints
        }
        for future in as_completed(future_to_url):
            try:
                all_names.extend(future.result())
            except Exception as e:
                frappe.log_error(str(e), "Fortigate Address Fetch Error DFC1")

    seen   = set()
    result = []
    for name in all_names:
        if not name or name.strip().lower() == "all":
            continue
        if name not in seen:
            seen.add(name)
            result.append(name)

    return sorted(result)


@frappe.whitelist()
def get_ip_pools(vdom="root"):
    try:
        r = requests.get(
            f"{BASE_URL}/firewall/ippool?vdom={vdom}",
            headers=HEADERS, verify=False, timeout=15
        )
        return [p.get("name") for p in r.json().get("results", []) if p.get("name")]
    except Exception as e:
        frappe.log_error(str(e), "Fortigate IP Pool Fetch Error DFC1")
        return []


@frappe.whitelist()
def get_services(vdom="root"):
    services = _fetch_services_for_vdom(vdom)

    for svc_name in services:
        unique_name = f"{svc_name}-{vdom}"
        if frappe.db.exists("DFC 1 Service", unique_name):
            continue
        if frappe.db.exists("DFC 1 Service", svc_name):
            continue
        try:
            svc_doc                       = frappe.new_doc("DFC 1 Service")
            svc_doc.name                  = unique_name
            svc_doc.service_name          = svc_name
            svc_doc.custom_virtual_domain = vdom
            svc_doc.insert(ignore_permissions=True)
        except Exception as e:
            frappe.log_error(str(e), f"DFC1 Service Insert: {unique_name}")

    frappe.db.commit()
    return services


# -------------------------------------------------------
# Sync services
# -------------------------------------------------------
@frappe.whitelist()
def sync_firewall_services():
    vdom_list = _fetch_vdoms()

    def sync_one(vdom):
        try:
            get_services(vdom)
            return vdom, None
        except Exception as e:
            return vdom, str(e)

    errors = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(sync_one, v): v for v in vdom_list}
        for future in as_completed(futures):
            vdom, err = future.result()
            if err:
                errors.append(f"{vdom}: {err}")

    if errors:
        frappe.log_error("\n".join(errors), "Sync Firewall Services Errors DFC1")

    return f"Services synced for VDOMs: {', '.join(vdom_list)}"


# -------------------------------------------------------
# Sync policies
# -------------------------------------------------------
@frappe.whitelist()
def sync_policies_from_fortigate():
    vdom_list = _fetch_vdoms()

    def fetch_vdom_data(vdom):
        return {
            "vdom":      vdom,
            "policies":  _fetch_policies(vdom),
            "iface_map": _build_interface_map(vdom),
        }

    vdom_data_list = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_vdom_data, v): v for v in vdom_list}
        for future in as_completed(futures):
            try:
                vdom_data_list.append(future.result())
            except Exception as e:
                frappe.log_error(str(e), "FortiGate Fetch VDOM Data Error DFC1")

    created = updated = skipped = 0

    for vd in vdom_data_list:
        vdom      = vd["vdom"]
        iface_map = vd["iface_map"]

        for pol in vd["policies"]:
            policy_id = pol.get("policyid")
            if not policy_id:
                skipped += 1
                continue

            try:
                name = pol.get("name") or f"Policy-{policy_id}"

                incoming_raw       = pol.get("srcintf", [{}])[0].get("name", "")
                outgoing_raw       = pol.get("dstintf", [{}])[0].get("name", "")
                incoming_interface = iface_map.get(incoming_raw, incoming_raw)
                outgoing_interface = iface_map.get(outgoing_raw, outgoing_raw)

                source      = pol.get("srcaddr", [{}])[0].get("name", "")
                destination = pol.get("dstaddr", [{}])[0].get("name", "")
                services    = [s.get("name") for s in pol.get("service", []) if s.get("name")]
                nat           = pol.get("nat") == "enable"
                enable_policy = pol.get("status") == "enable"

                ip_pool               = ""
                ip_pool_configuration = "Use Outgoing Interface Address"
                if pol.get("ippool") in ["enable", 1, True]:
                    ip_pool_configuration = "Use Dynamic IP Pool"
                    pool_list = pol.get("poolname", [])
                    if pool_list:
                        ip_pool = pool_list[0].get("name", "")

                existing = frappe.db.exists("DFC 1 Policy", {
                    "custom_firewall_policy_id": str(policy_id),
                    "custom_virtual_domain":     vdom
                })
                if not existing:
                    existing = frappe.db.exists("DFC 1 Policy", {
                        "policy_name":           name,
                        "custom_virtual_domain": vdom
                    })

                doc = frappe.get_doc("DFC 1 Policy", existing) if existing else frappe.new_doc("DFC 1 Policy")

                doc.policy_name               = name
                doc.custom_firewall_policy_id = str(policy_id)
                doc.custom_virtual_domain     = vdom
                doc.incoming_interface        = incoming_interface
                doc.outgoing_interface        = outgoing_interface
                doc.source                    = source
                doc.destination               = destination
                doc.nat                       = nat
                doc.enable_this_policy        = enable_policy
                doc.ip_pool_configuration     = ip_pool_configuration
                doc.custom_ip_pool            = ip_pool
                doc.custom_services           = []

                for svc in services:
                    if svc:
                        doc.append("custom_services", {"service": svc})

                if existing:
                    doc.save(ignore_permissions=True, ignore_links=True)
                    updated += 1
                else:
                    doc.insert(ignore_permissions=True, ignore_links=True)
                    created += 1

            except Exception as row_error:
                frappe.log_error(
                    str(row_error),
                    f"DFC1 Policy Sync Error - VDOM: {vdom} ID: {policy_id}"
                )
                skipped += 1

    frappe.db.commit()
    return {
        "status":       "success",
        "created":      created,
        "updated":      updated,
        "skipped":      skipped,
        "vdoms_synced": vdom_list
    }


# -------------------------------------------------------
# Uniqueness check + validate hook
# -------------------------------------------------------
@frappe.whitelist()
def validate_policy_uniqueness(docname, policy_name, vdom):
    vdom     = vdom or "root"
    existing = frappe.db.get_value(
        "DFC 1 Policy",
        {"policy_name": policy_name, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != docname:
        return {
            "status":  "duplicate",
            "message": f"Policy '{policy_name}' already exists in VDOM '{vdom}'"
        }
    return {"status": "ok"}


def validate_policy(doc, method=None):
    vdom     = doc.custom_virtual_domain or "root"
    existing = frappe.db.get_value(
        "DFC 1 Policy",
        {"policy_name": doc.policy_name, "custom_virtual_domain": vdom},
        "name"
    )
    if existing and existing != doc.name:
        frappe.throw(
            f"Policy <b>{doc.policy_name}</b> already exists in VDOM <b>{vdom}</b>.",
            title="Duplicate Policy"
        )
