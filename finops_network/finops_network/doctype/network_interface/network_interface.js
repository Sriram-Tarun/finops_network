frappe.ui.form.on('Network Interface', {
    refresh(frm) {

        frm.add_custom_button('Create Interface in FortiGate', function () {

            frappe.call({
                method: "finops_network.finops_network.api.fortigate.create_interface",
                args: {
                    docname: frm.doc.name
                },
                freeze: true,
                freeze_message: "Creating Interface in FortiGate...",
                callback: function(r) {

                    console.log("FortiGate Response:", r);

                    if (r.message) {
                        frappe.msgprint({
                            title: "FortiGate Response",
                            message: JSON.stringify(r.message, null, 2),
                            indicator: "green"
                        });
                    } else {
                        frappe.msgprint("No response returned from API");
                    }
                }
            });

        });

    }
});