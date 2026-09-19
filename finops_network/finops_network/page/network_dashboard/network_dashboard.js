frappe.pages['network-dashboard'].on_page_load = function(wrapper) {var page = frappe.ui.make_app_page({parent: wrapper,title: 'Network Activity Dashboard',single_column: true});

var CSS = [
	'#nd-wrap { padding: 18px 0; font-family: inherit; }',
	'#nd-wrap * { box-sizing: border-box; }',

	/* -- Filter bar -- */
	'.nd-filter-bar { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:20px; }',
	'.nd-filter-bar select, .nd-filter-bar input[type="date"] { font-size:13px; padding:6px 10px; border:1px solid var(--border-color); border-radius:6px; background:var(--card-bg); color:var(--text-color); min-width:155px; height:34px; cursor:pointer; }',
	'.nd-btn-apply { height:34px; padding:0 18px; font-size:13px; font-weight:600; border:none; border-radius:6px; background:#1a1a1a; color:#fff; cursor:pointer; }',
	'.nd-btn-apply:hover { background:#333; }',
	'.nd-btn-excel { height:34px; padding:0 16px; font-size:13px; font-weight:600; border:none; border-radius:6px; background:#22c55e; color:#fff; cursor:pointer; display:flex; align-items:center; gap:6px; }',
	'.nd-btn-excel:hover { background:#16a34a; }',
	'.nd-btn-excel svg { flex-shrink:0; }',

	/* -- Summary section -- */
	'.nd-summary-wrap { border:1px solid var(--border-color); border-radius:8px; margin-bottom:24px; overflow:hidden; }',
	'.nd-summary-title { font-size:13px; font-weight:600; color:var(--text-color); padding:12px 18px; background:var(--subtle-fg); border-bottom:1px solid var(--border-color); display:flex; align-items:center; justify-content:space-between; }',
	'.nd-summary-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); }',
	'.nd-summary-card { padding:14px 18px; border-right:1px solid var(--border-color); border-bottom:1px solid var(--border-color); }',
	'.nd-summary-card:hover { background:var(--subtle-fg); }',
	'.nd-summary-label { font-size:11px; color:var(--text-muted); margin-bottom:5px; line-height:1.5; }',
	'.nd-summary-value { font-size:24px; font-weight:600; color:var(--text-color); }',

	/* -- DFC group tabs -- */
	'.nd-dfc-tabs { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:16px; }',
	'.nd-dfc-tab { height:30px; padding:0 14px; font-size:12px; font-weight:600; border:1px solid var(--border-color); border-radius:20px; background:var(--card-bg); color:var(--text-muted); cursor:pointer; white-space:nowrap; }',
	'.nd-dfc-tab.active { background:#1a1a1a; color:#fff; border-color:#1a1a1a; }',
	'.nd-dfc-tab:hover:not(.active) { background:var(--subtle-fg); }',

	/* -- Search bar row -- */
	'.nd-search-row { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; align-items:center; }',
	'.nd-search-row input { font-size:13px; padding:6px 10px; border:1px solid var(--border-color); border-radius:6px; background:var(--card-bg); color:var(--text-color); flex:1; min-width:200px; }',
	'.nd-search-row select { font-size:13px; padding:6px 10px; border:1px solid var(--border-color); border-radius:6px; background:var(--card-bg); color:var(--text-color); }',

	/* -- Table -- */
	'.nd-table-wrap { border:1px solid var(--border-color); border-radius:8px; overflow:hidden; overflow-x:auto; }',
	'.nd-table { width:100%; border-collapse:collapse; font-size:13px; }',
	'.nd-table thead th { background:var(--subtle-fg); color:var(--text-muted); font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.05em; padding:10px 14px; text-align:left; border-bottom:1px solid var(--border-color); white-space:nowrap; }',
	'.nd-table tbody tr { border-bottom:1px solid var(--border-color); cursor:pointer; }',
	'.nd-table tbody tr:last-child { border-bottom:none; }',
	'.nd-table tbody tr:hover { background:var(--subtle-fg); }',
	'.nd-table tbody td { padding:9px 14px; color:var(--text-color); vertical-align:middle; }',
	'.nd-td-clip { max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }',

	/* -- Pills / badges -- */
	'.nd-doctype-pill { display:inline-block; padding:2px 9px; border-radius:4px; font-size:11px; background:#ede9fe; border:1px solid #c4b5fd; color:#5b21b6; white-space:nowrap; }',
	'.nd-dfc-badge { display:inline-block; padding:1px 6px; border-radius:3px; font-size:10px; font-weight:700; margin-right:4px; white-space:nowrap; }',
	'.nd-dfc-1   { background:#dbeafe; color:#1e40af; border:1px solid #93c5fd; }',
	'.nd-dfc-1-mum { background:#fce7f3; color:#9d174d; border:1px solid #f9a8d4; }',
	'.nd-dfc-1-blr { background:#ecfdf5; color:#065f46; border:1px solid #6ee7b7; }',
	'.nd-dfc-2   { background:#fef3c7; color:#92400e; border:1px solid #fcd34d; }',
	'.nd-dfc-3   { background:#ede9fe; color:#5b21b6; border:1px solid #c4b5fd; }',
        '.nd-dfc-3-2 { background:#fff7ed; color:#9a3412; border:1px solid #fdba74; }',
        '.nd-dfc-4   { background:#e0f2fe; color:#0c4a6e; border:1px solid #7dd3fc; }',
	'.nd-ticket { font-family:monospace; font-size:12px; color:#1e40af; font-weight:700; background:#dbeafe; padding:2px 8px; border-radius:4px; }',
	'.nd-ticket-empty { color:var(--text-muted); font-size:12px; }',
	'.nd-time { font-size:12px; color:var(--text-muted); white-space:nowrap; }',
	'.nd-avatar { width:26px; height:26px; border-radius:50%; background:#e0e7ff; color:#4338ca; font-size:10px; font-weight:700; display:inline-flex; align-items:center; justify-content:center; flex-shrink:0; margin-right:7px; }',
	'.nd-user-cell { display:flex; align-items:center; white-space:nowrap; }',
	'.nd-change-list { list-style:none; padding:0; margin:0; }',
	'.nd-change-list li { font-size:12px; color:var(--text-muted); line-height:1.7; }',
	'.nd-old { color:#dc2626; }',
	'.nd-new { color:#16a34a; }',

	/* -- Action badges -- */
	'.nd-action-badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; white-space:nowrap; }',
	'.nd-action-create { background:#dcfce7; color:#15803d; border:1px solid #86efac; }',
	'.nd-action-update { background:#fef9c3; color:#854d0e; border:1px solid #fde047; }',
	'.nd-action-delete { background:#fee2e2; color:#b91c1c; border:1px solid #fca5a5; }',
	'.nd-action-rename { background:#e0f2fe; color:#075985; border:1px solid #7dd3fc; }',

	/* -- Section header -- */
	'.nd-section-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:10px; }',
	'.nd-section-title { font-size:14px; font-weight:600; color:var(--text-color); }',
	'.nd-row-count { font-size:12px; color:var(--text-muted); }',
	'.nd-no-results { padding:32px; text-align:center; color:var(--text-muted); font-size:14px; }',
	'.nd-loading { padding:32px; text-align:center; color:var(--text-muted); font-size:14px; }',

	/* -- Detail popup -- */
	'.nd-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.4); z-index:9998; }',
	'.nd-popup { position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); background:var(--card-bg); border:1px solid var(--border-color); border-radius:10px; padding:24px 28px; z-index:9999; min-width:440px; max-width:640px; max-height:80vh; overflow-y:auto; }',
	'.nd-popup h4 { font-size:15px; font-weight:600; color:var(--text-color); margin-bottom:16px; border-bottom:1px solid var(--border-color); padding-bottom:10px; }',
	'.nd-pop-row { display:flex; padding:8px 0; border-bottom:1px solid var(--border-color); gap:16px; }',
	'.nd-pop-label { font-size:11px; font-weight:600; color:var(--text-muted); width:120px; flex-shrink:0; text-transform:uppercase; letter-spacing:.04em; padding-top:2px; }',
	'.nd-pop-val { font-size:13px; color:var(--text-color); flex:1; word-break:break-word; }',
	'.nd-changes-ul { list-style:disc; margin:6px 0 0 16px; padding:0; }',
	'.nd-changes-ul li { font-size:13px; line-height:1.8; color:var(--text-color); }',
	'.nd-close-btn { margin-top:18px; cursor:pointer; color:var(--text-muted); font-size:13px; border:1px solid var(--border-color); border-radius:5px; padding:5px 16px; background:var(--subtle-fg); float:right; }',
	'.nd-record-link { color:#1e40af; text-decoration:none; font-weight:500; }',
	'.nd-record-link:hover { text-decoration:underline; }'
];

$('<style id="nd-style">').text(CSS.join('\n')).appendTo('head');

var $wrap = $('<div id="nd-wrap">').appendTo(page.main);

$wrap.html(
	/* -- Filter bar -- */
	'<div class="nd-filter-bar">' +
		'<select id="nd-f-role">' +
			'<option value="">All Roles</option>' +
			'<option value="Network Team NOC">Network Team NOC</option>' +
			'<option value="Network Team L1">Network Team L1</option>' +
			'<option value="Network Team">Network Team</option>' +
		'</select>' +
		'<select id="nd-f-user"><option value="">Select User</option></select>' +
		'<select id="nd-f-doctype"><option value="">Select Doctype</option></select>' +
		'<select id="nd-f-action">' +
			'<option value="">All Actions</option>' +
			'<option value="Create">Create</option>' +
			'<option value="Update">Update</option>' +
			'<option value="Delete">Delete</option>' +
			'<option value="Rename">Rename</option>' +
		'</select>' +
		'<input type="date" id="nd-f-from" title="From Date" />' +
		'<input type="date" id="nd-f-to" title="To Date" />' +
		'<button class="nd-btn-apply" id="nd-btn-apply">Apply</button>' +
		'<button class="nd-btn-excel" id="nd-btn-excel">' +
			'<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">' +
				'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>' +
				'<polyline points="14 2 14 8 20 8"/>' +
				'<line x1="8" y1="13" x2="16" y2="13"/>' +
				'<line x1="8" y1="17" x2="16" y2="17"/>' +
				'<polyline points="10 9 9 9 8 9"/>' +
			'</svg>' +
			'Download Excel' +
		'</button>' +
	'</div>' +

	/* -- DFC Group Tabs -- */
	'<div class="nd-dfc-tabs">' +
		'<button class="nd-dfc-tab active" data-dfc="">All DFCs</button>' +
		'<button class="nd-dfc-tab" data-dfc="DFC 1">DFC 1</button>' +
		'<button class="nd-dfc-tab" data-dfc="DFC 1 Mumbai">DFC 1 Mumbai</button>' +
		'<button class="nd-dfc-tab" data-dfc="DFC 1 Bangalore">DFC 1 Bangalore</button>' +
		'<button class="nd-dfc-tab" data-dfc="DFC 2">DFC 2</button>' +
		'<button class="nd-dfc-tab" data-dfc="DFC 3">DFC 3</button>' +
                '<button class="nd-dfc-tab" data-dfc="DFC 3-2">DFC 3-2</button>'+
                '<button class="nd-dfc-tab" data-dfc="DFC 4">DFC 4</button>'+
	'</div>' +

	/* -- Network Actions Summary -- */
	'<div class="nd-summary-wrap">' +
		'<div class="nd-summary-title"><span>Network Actions Summary</span><span id="nd-summary-scope" style="font-size:11px;font-weight:400;color:var(--text-muted);">All DFCs</span></div>' +
		'<div class="nd-summary-grid" id="nd-summary-grid">' +
			'<div class="nd-loading" style="grid-column:1/-1;">Loading...</div>' +
		'</div>' +
	'</div>' +

	/* Search + ticket */
	'<div class="nd-search-row">' +
		'<input type="text" id="nd-search" placeholder="Search user, doctype, ticket, record, field..." />' +
		'<select id="nd-f-ticket"><option value="">All Tickets</option></select>' +
	'</div>' +

	/* Table */
	'<div class="nd-section-header">' +
		'<span class="nd-section-title">Activity Log</span>' +
		'<span class="nd-row-count" id="nd-row-count"></span>' +
	'</div>' +
	'<div class="nd-table-wrap">' +
		'<table class="nd-table">' +
			'<thead><tr>' +
				'<th>Time</th><th>Updated By</th><th>DFC</th><th>Doctype</th>' +
				'<th>Record (ID)</th><th>Action</th><th>Fields Changed</th><th>Ticket ID</th>' +
			'</tr></thead>' +
			'<tbody id="nd-tbody"><tr><td colspan="8" class="nd-loading">Loading...</td></tr></tbody>' +
		'</table>' +
	'</div>'
);

/* ================================================================
   STATE
   ================================================================ */
var allData     = [];
var roleUserMap = {};
var roleUsers   = [];
var activeDFC   = '';   /* '' = All DFCs */

/* ----------------------------------------------------------------
   DFC GROUP DEFINITIONS
   Each group has a label, a css key for badge colouring,
   and the list of doctype prefixes that belong to it.
   The actual Frappe doctypes are "<prefix> Interface" etc.
   ---------------------------------------------------------------- */
var DFC_GROUPS = [
	{ key: 'DFC 1',           label: 'DFC 1',           cssKey: 'dfc-1',     prefix: 'DFC 1'           },
	{ key: 'DFC 1 Mumbai',    label: 'DFC 1 Mumbai',    cssKey: 'dfc-1-mum', prefix: 'DFC 1 Mumbai'    },
	{ key: 'DFC 1 Bangalore', label: 'DFC 1 Bangalore', cssKey: 'dfc-1-blr', prefix: 'DFC 1 Bangalore' },
	{ key: 'DFC 2',           label: 'DFC 2',           cssKey: 'dfc-2',     prefix: 'DFC 2'           },
	{ key: 'DFC 3',           label: 'DFC 3',           cssKey: 'dfc-3',     prefix: 'DFC 3'           },
        { key: 'DFC 3-2',         label: 'DFC 3-2',         cssKey: 'dfc-3-2',   prefix: 'DFC 3-2'         },
        { key: 'DFC 4',           label: 'DFC 4',           cssKey: 'dfc-4',     prefix: 'DFC 4'           }
];

/* Doctype suffix types shared across all DFC groups */
var DOCTYPE_SUFFIXES = [
	'Interface', 'Address', 'Policy', 'Service',
	'Service Group', 'User', 'User Group', 'Virtual IP'
];

/* Build the flat list of ALL network doctypes across every DFC group */
var NETWORK_DOCTYPES = [];
DFC_GROUPS.forEach(function(g) {
	DOCTYPE_SUFFIXES.forEach(function(s) {
		NETWORK_DOCTYPES.push(g.prefix + ' ' + s);
	});
});

var NETWORK_ROLES = ['Network Team NOC', 'Network Team L1', 'Network Team'];

/* ----------------------------------------------------------------
   Helper: derive DFC group key from a doctype string
   e.g. "DFC 1 Mumbai Interface" -> "DFC 1 Mumbai"
   ---------------------------------------------------------------- */
function dfcGroupOf(doctype) {
	/* Sort groups longest-prefix-first so "DFC 1 Mumbai" beats "DFC 1" */
	var sorted = DFC_GROUPS.slice().sort(function(a,b){ return b.prefix.length - a.prefix.length; });
	for (var i=0; i<sorted.length; i++) {
		if (doctype.indexOf(sorted[i].prefix) === 0) return sorted[i].key;
	}
	return '';
}

function dfcCssKey(dfcGroup) {
	for (var i=0; i<DFC_GROUPS.length; i++) {
		if (DFC_GROUPS[i].key === dfcGroup) return DFC_GROUPS[i].cssKey;
	}
	return 'dfc-3';
}

/* Summary card definitions � generated dynamically per DFC group */
var SUMMARY_CARD_TEMPLATES = [
	{ label: 'Create / Update\nInterface',            suffix: 'Interface',    actions: ['Create','Update'] },
	{ label: 'Create / Update\nAddress',              suffix: 'Address',      actions: ['Create','Update'] },
	{ label: 'Create / Update\nPolicy',               suffix: 'Policy',       actions: ['Create','Update'] },
	{ label: 'Create / Update\nService',              suffix: 'Service',      actions: ['Create','Update'] },
	{ label: 'Create / Update\nService Group',        suffix: 'Service Group',actions: ['Create','Update'] },
	{ label: 'Create / Update /\nRename User',        suffix: 'User',         actions: ['Create','Update','Rename'] },
	{ label: 'Create / Update /\nRename User Group',  suffix: 'User Group',   actions: ['Create','Update','Rename'] },
	{ label: 'Create / Update /\nRename VIP',         suffix: 'Virtual IP',   actions: ['Create','Update','Rename'] }
];

/* Build summary cards for a given dfcKey ('' = all) */
function buildSummaryCards(dfcKey) {
	var groups = dfcKey ? DFC_GROUPS.filter(function(g){ return g.key === dfcKey; }) : DFC_GROUPS;
	var cards  = [];
	groups.forEach(function(g) {
		SUMMARY_CARD_TEMPLATES.forEach(function(tpl) {
			var doctype = g.prefix + ' ' + tpl.suffix;
			cards.push({
				label:    tpl.label,
				dfcLabel: g.label,
				doctypes: [doctype],
				actions:  tpl.actions
			});
		});
	});
	return cards;
}

/* ================================================================
   HELPERS
   ================================================================ */
function initials(name) {
	if (!name) return '?';
	return name.replace(/@.*/, '').split(/[\s._\-]+/).map(function(w){ return w[0]||''; }).join('').slice(0,2).toUpperCase() || '?';
}

function extractTicket(text) {
	if (!text) return '';
	var plain = text.replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ');
	var m = plain.match(/Ticket\s*ID\s*[:=]\s*([A-Za-z0-9_\-]+)/i);
	if (m && m[1] && m[1].length > 1 && m[1].toLowerCase() !== 'id') return m[1].trim();
	return '';
}

function extractChanges(html) {
	if (!html) return [];
	var changes = [];
	var tmp = $('<div>').html(html);
	tmp.find('li').each(function(){
		var text = $(this).text().replace(/\s+/g,' ').trim();
		if (!text || /ticket\s*id/i.test(text)) return;
		var oldSpan = $(this).find('.text-danger,[style*="color:red"],[style*="color: red"]').first().text().trim();
		var newSpan = $(this).find('.text-success,[style*="color:green"],[style*="color: green"]').first().text().trim();
		if (oldSpan || newSpan) {
			changes.push(text.split(':')[0].trim() + ': ' + oldSpan + ' -> ' + newSpan);
		} else { changes.push(text); }
	});
	if (!changes.length) {
		var plain = html.replace(/<br\s*\/?>/gi,'\n').replace(/<\/li>/gi,'\n').replace(/<\/p>/gi,'\n')
			.replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').replace(/&gt;/g,'>').replace(/&lt;/g,'<').replace(/&amp;/g,'&');
		plain.split(/\n/).forEach(function(line){
			line = line.replace(/\s+/g,' ').trim();
			if (!line || line.length < 3) return;
			if (/ticket\s*id/i.test(line)) return;
			if (/action\s*:\s*saved/i.test(line)) return;
			if (/you (changed|created|last|edited)/i.test(line)) return;
			if (/add to this activity/i.test(line)) return;
			if (line.indexOf(':') !== -1) changes.push(line);
		});
	}
	return changes.slice(0,10);
}

function detectAction(plain, changes) {
	if (/renamed/i.test(plain))  return 'Rename';
	if (/deleted/i.test(plain))  return 'Delete';
	if (/created/i.test(plain) && !changes.length) return 'Create';
	return 'Update';
}

/* ================================================================
   PARSE COMMENT
   ================================================================ */
function parseComment(comment, doctype) {
	var content = comment.content || '';
	var plain = content.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ');

	var isSaved      = /action\s*:\s*saved/i.test(plain);
	var hasChanges   = /changes\s*:/i.test(plain);
	var isCreated    = /created\s+this\s+document|document\s+created|added\s+this\s+document|submitted\s+this\s+document/i.test(plain);
	var isDeleted    = /deleted\s+this\s+document|document\s+deleted|cancelled\s+this\s+document/i.test(plain);
	var isRenamed    = /renamed\s+(from|to)/i.test(plain);
	var isEditType   = (comment.comment_type === 'Edit');
	var hasTicketTag = /ticket\s*id\s*[:=]/i.test(plain);
	var hasActionTag = /^\s*action\s*:/i.test(plain);

	if (!isSaved && !hasChanges && !isCreated && !isDeleted && !isRenamed && !isEditType && !(hasTicketTag && hasActionTag)) return null;

	var ticket  = extractTicket(plain);
	var changes = extractChanges(content);

	var action;
	if (isDeleted || /delete\s+(user\s+in|.*)\s*(fortigate|firewall)/i.test(plain)) action = 'Delete';
	else if (isRenamed || /rename.*(fortigate|firewall)|rename\s+user/i.test(plain)) action = 'Rename';
	else if (isCreated || /create\s+(user\s+in|.*)\s*(fortigate|firewall)/i.test(plain)) action = 'Create';
	else if (/update.*(fortigate|firewall)/i.test(plain))                               action = 'Update';
	else                                                                                 action = detectAction(plain, changes);

	if (action === 'Update' && !ticket && !changes.length) return null;

	return {
		creation:  comment.creation,
		_user:     (comment.owner||'Administrator').replace(/@[^@]+$/,'').trim(),
		_fulluser: comment.owner||'Administrator',
		_doctype:  doctype,
		_dfcGroup: dfcGroupOf(doctype),
		_record:   comment.reference_name||'',
		_action:   action,
		_changes:  changes,
		_ticket:   ticket
	};
}

function actionBadge(action) {
	var cls = {
		'Create': 'nd-action-create',
		'Update': 'nd-action-update',
		'Delete': 'nd-action-delete',
		'Rename': 'nd-action-rename'
	}[action] || 'nd-action-update';
	return '<span class="nd-action-badge ' + cls + '">' + frappe.utils.escape_html(action) + '</span>';
}

function dfcBadge(dfcGroup) {
	if (!dfcGroup) return '';
	var css = dfcCssKey(dfcGroup);
	return '<span class="nd-dfc-badge nd-' + css + '">' + frappe.utils.escape_html(dfcGroup) + '</span>';
}

function changesHtml(changes) {
	if (!changes||!changes.length) return '<span style="color:var(--text-muted);font-size:12px;">-</span>';
	var lines = changes.slice(0,3).map(function(c){
		var parts = c.split(/\s*->\s*/);
		if (parts.length===2){
			var label  = parts[0].indexOf(':')!==-1 ? parts[0].split(':')[0]+': ' : '';
			var oldVal = parts[0].indexOf(':')!==-1 ? parts[0].split(':').slice(1).join(':').trim() : parts[0].trim();
			return '<li><span style="color:var(--text-muted);">'+frappe.utils.escape_html(label)+'</span>'+
				'<span class="nd-old">'+frappe.utils.escape_html(oldVal)+'</span>'+
				' -&gt; <span class="nd-new">'+frappe.utils.escape_html(parts[1].trim())+'</span></li>';
		}
		return '<li style="color:var(--text-muted);">'+frappe.utils.escape_html(c)+'</li>';
	});
	if (changes.length>3) lines.push('<li style="color:var(--text-muted);font-style:italic;">+'+(changes.length-3)+' more...</li>');
	return lines.join('');
}

/* ================================================================
   RENDER SUMMARY
   ================================================================ */
function renderSummary(data) {
	var cards = buildSummaryCards(activeDFC);
	$('#nd-summary-scope').text(activeDFC || 'All DFCs');

	/* When showing all DFCs, group cards under a per-DFC sub-heading */
	if (!activeDFC) {
		var html = '';
		DFC_GROUPS.forEach(function(g) {
			var groupCards = cards.filter(function(c){ return c.dfcLabel === g.label; });
			var groupHtml  = groupCards.map(function(card){
				var count = data.filter(function(r){
					return card.doctypes.indexOf(r._doctype) !== -1 && card.actions.indexOf(r._action) !== -1;
				}).length;
				return '<div class="nd-summary-card">'+
					'<div class="nd-summary-label">'+card.label.replace(/\n/g,'<br>')+'</div>'+
					'<div class="nd-summary-value">'+count+'</div>'+
				'</div>';
			}).join('');

			html += '<div style="grid-column:1/-1;padding:8px 18px 4px;font-size:11px;font-weight:700;color:var(--text-muted);background:var(--subtle-fg);border-bottom:1px solid var(--border-color);letter-spacing:.06em;text-transform:uppercase;">'+
				dfcBadge(g.key) + ' ' + frappe.utils.escape_html(g.label) +
			'</div>' + groupHtml;
		});
		$('#nd-summary-grid').html(html);
	} else {
		var html2 = cards.map(function(card){
			var count = data.filter(function(r){
				return card.doctypes.indexOf(r._doctype) !== -1 && card.actions.indexOf(r._action) !== -1;
			}).length;
			return '<div class="nd-summary-card">'+
				'<div class="nd-summary-label">'+card.label.replace(/\n/g,'<br>')+'</div>'+
				'<div class="nd-summary-value">'+count+'</div>'+
			'</div>';
		}).join('');
		$('#nd-summary-grid').html(html2);
	}
}

/* ================================================================
   RENDER TABLE
   ================================================================ */
function renderTable(data) {
	$('#nd-row-count').text(data.length+' record'+(data.length!==1?'s':''));
	if (!data.length){
		$('#nd-tbody').html('<tr><td colspan="8" class="nd-no-results">No matching records found.</td></tr>');
		return;
	}
	$('#nd-tbody').html(data.map(function(r,idx){
		var timeStr   = r.creation ? frappe.datetime.str_to_user(r.creation) : '-';
		var recordUrl = '/app/'+frappe.router.slug(r._doctype)+'/'+encodeURIComponent(r._record);
		return '<tr data-idx="'+idx+'">'+
			'<td class="nd-time">'+timeStr+'</td>'+
			'<td><div class="nd-user-cell"><span class="nd-avatar">'+initials(r._user)+'</span>'+frappe.utils.escape_html(r._user)+'</div></td>'+
			'<td>'+dfcBadge(r._dfcGroup)+'</td>'+
			'<td><span class="nd-doctype-pill">'+frappe.utils.escape_html(r._doctype)+'</span></td>'+
			'<td class="nd-td-clip"><a class="nd-record-link" href="'+recordUrl+'" onclick="event.stopPropagation();" target="_blank">'+frappe.utils.escape_html(r._record)+'</a></td>'+
			'<td>'+actionBadge(r._action)+'</td>'+
			'<td><ul class="nd-change-list">'+changesHtml(r._changes)+'</ul></td>'+
			'<td>'+(r._ticket?'<span class="nd-ticket">'+frappe.utils.escape_html(r._ticket)+'</span>':'<span class="nd-ticket-empty">-</span>')+'</td>'+
		'</tr>';
	}).join(''));
	$('#nd-tbody tr').on('click',function(){ showDetail(data[parseInt($(this).attr('data-idx'),10)]); });
}

/* ================================================================
   USER DROPDOWN � role-aware
   ================================================================ */
function populateUserDropdown(selectedRole) {
	var prev = $('#nd-f-user').val();
	$('#nd-f-user').find('option:not(:first)').remove();

	var usersToShow = [], seen = {};

	if (!selectedRole) {
		roleUsers.forEach(function(u){ if(!seen[u]){seen[u]=1;usersToShow.push(u);} });
		allData.forEach(function(r){ if(!seen[r._user]){seen[r._user]=1;usersToShow.push(r._user);} });
	} else {
		Object.keys(roleUserMap).forEach(function(u){
			if(roleUserMap[u].indexOf(selectedRole)!==-1 && !seen[u]){seen[u]=1;usersToShow.push(u);}
		});
	}

	usersToShow.sort().forEach(function(u){
		$('#nd-f-user').append('<option value="'+u+'">'+u+'</option>');
	});

	if (prev && $('#nd-f-user option[value="'+prev+'"]').length) {
		$('#nd-f-user').val(prev);
	} else {
		$('#nd-f-user').val('');
	}
}

/* ================================================================
   BUILD STATIC FILTERS (doctype, ticket)
   ================================================================ */
function buildFilters(data) {
	var dts=[], tkts=[], dtS={}, tS={};
	data.forEach(function(r){
		if(!dtS[r._doctype]){dts.push(r._doctype);dtS[r._doctype]=1;}
		if(r._ticket&&!tS[r._ticket]){tkts.push(r._ticket);tS[r._ticket]=1;}
	});
	dts.sort(); tkts.sort();

	$('#nd-f-doctype').find('option:not(:first)').remove();
	dts.forEach(function(d){ $('#nd-f-doctype').append('<option value="'+d+'">'+d+'</option>'); });

	$('#nd-f-ticket').find('option:not(:first)').remove();
	tkts.forEach(function(t){ $('#nd-f-ticket').append('<option value="'+t+'">'+t+'</option>'); });

	populateUserDropdown('');
}

/* ================================================================
   FILTER
   ================================================================ */
function getFilteredData() {
	var q    = ($('#nd-search').val()||'').toLowerCase();
	var rl   = $('#nd-f-role').val();
	var dt   = $('#nd-f-doctype').val();
	var us   = $('#nd-f-user').val();
	var tk   = $('#nd-f-ticket').val();
	var ac   = $('#nd-f-action').val();
	var from = $('#nd-f-from').val();
	var to   = $('#nd-f-to').val();

	var roleFilterUsers = null;
	if (rl) {
		roleFilterUsers = {};
		Object.keys(roleUserMap).forEach(function(u){
			if(roleUserMap[u].indexOf(rl)!==-1) roleFilterUsers[u]=1;
		});
	}

	return allData.filter(function(r){
		/* DFC tab filter */
		if (activeDFC && r._dfcGroup !== activeDFC) return false;

		var hay=(r._user+' '+r._doctype+' '+(r._ticket||'')+' '+r._record+' '+r._changes.join(' ')+' '+(r._dfcGroup||'')).toLowerCase();
		if(q   && hay.indexOf(q)===-1)              return false;
		if(roleFilterUsers && !roleFilterUsers[r._user]) return false;
		if(dt  && r._doctype!==dt)                  return false;
		if(us  && r._user!==us)                     return false;
		if(tk  && r._ticket!==tk)                   return false;
		if(ac  && r._action!==ac)                   return false;
		if(from && r.creation && r.creation.slice(0,10)<from) return false;
		if(to   && r.creation && r.creation.slice(0,10)>to)   return false;
		return true;
	});
}

function applyFilters(){
	var f = getFilteredData();
	renderSummary(f);
	renderTable(f);
}

/* ================================================================
   DOWNLOAD EXCEL
   ================================================================ */
function downloadExcel(){
	var filtered = getFilteredData();
	if(!filtered.length){ frappe.msgprint('No data to export.'); return; }
	var BOM = '\uFEFF';
	var headers = ['Time','Updated By','Full Email','DFC Group','Doctype','Record (ID)','Action','Fields Changed','Ticket ID'];
	function csvCell(val){ val=(val==null?'':String(val)).replace(/"/g,'""'); return '"'+val+'"'; }
	var rows = [headers.map(csvCell).join(',')];
	filtered.forEach(function(r){
		rows.push([
			csvCell(r.creation?frappe.datetime.str_to_user(r.creation):''),
			csvCell(r._user), csvCell(r._fulluser), csvCell(r._dfcGroup||''),
			csvCell(r._doctype), csvCell(r._record), csvCell(r._action),
			csvCell(r._changes.join(' | ')), csvCell(r._ticket||'')
		].join(','));
	});
	var blob = new Blob([BOM+rows.join('\r\n')],{type:'text/csv;charset=utf-8;'});
	var url  = URL.createObjectURL(blob);
	var a    = document.createElement('a');
	a.href=url; a.download='network_activity_'+frappe.datetime.now_date()+'.csv';
	document.body.appendChild(a); a.click(); document.body.removeChild(a);
	URL.revokeObjectURL(url);
}

/* ================================================================
   DETAIL POPUP
   ================================================================ */
function showDetail(row){
	$('.nd-overlay,.nd-popup').remove();
	var $ov = $('<div class="nd-overlay">').appendTo('body');
	var chHtml = row._changes.length
		? '<ul class="nd-changes-ul">'+row._changes.map(function(c){
			var parts=c.split(/\s*->\s*/);
			if(parts.length===2){
				var lbl=parts[0].indexOf(':')!==-1?parts[0].split(':')[0]+': ':'';
				var ov =parts[0].indexOf(':')!==-1?parts[0].split(':').slice(1).join(':').trim():parts[0].trim();
				return '<li><b>'+frappe.utils.escape_html(lbl)+'</b>'+
					'<span class="nd-old">'+frappe.utils.escape_html(ov)+'</span>'+
					' -&gt; <span class="nd-new">'+frappe.utils.escape_html(parts[1].trim())+'</span></li>';
			}
			return '<li>'+frappe.utils.escape_html(c)+'</li>';
		}).join('')+'</ul>'
		: '<span style="color:var(--text-muted);">No field changes recorded</span>';
	var recordUrl='/app/'+frappe.router.slug(row._doctype)+'/'+encodeURIComponent(row._record);
	var $pop=$(
		'<div class="nd-popup">'+
			'<h4>Activity Detail</h4>'+
			'<div class="nd-pop-row"><div class="nd-pop-label">Time</div><div class="nd-pop-val">'+(row.creation?frappe.datetime.str_to_user(row.creation):'-')+'</div></div>'+
			'<div class="nd-pop-row"><div class="nd-pop-label">Updated By</div><div class="nd-pop-val">'+frappe.utils.escape_html(row._fulluser)+'</div></div>'+
			'<div class="nd-pop-row"><div class="nd-pop-label">DFC Group</div><div class="nd-pop-val">'+dfcBadge(row._dfcGroup)+'</div></div>'+
			'<div class="nd-pop-row"><div class="nd-pop-label">Doctype</div><div class="nd-pop-val"><span class="nd-doctype-pill">'+frappe.utils.escape_html(row._doctype)+'</span></div></div>'+
			'<div class="nd-pop-row"><div class="nd-pop-label">Record</div><div class="nd-pop-val"><a class="nd-record-link" href="'+recordUrl+'" target="_blank">'+frappe.utils.escape_html(row._record)+'</a></div></div>'+
			'<div class="nd-pop-row"><div class="nd-pop-label">Action</div><div class="nd-pop-val">'+actionBadge(row._action)+'</div></div>'+
			'<div class="nd-pop-row"><div class="nd-pop-label">Ticket ID</div><div class="nd-pop-val"><span class="nd-ticket" style="font-size:15px;">'+(row._ticket||'-')+'</span></div></div>'+
			'<div class="nd-pop-row"><div class="nd-pop-label">Fields Changed</div><div class="nd-pop-val">'+chHtml+'</div></div>'+
			'<button class="nd-close-btn">Close</button>'+
		'</div>'
	).appendTo('body');
	$ov.on('click',function(){$ov.remove();$pop.remove();});
	$pop.find('.nd-close-btn').on('click',function(){$ov.remove();$pop.remove();});
}

/* ================================================================
   DATA LOADING
   ================================================================ */
function mergeButtonActions(rows){
	var TWO_MIN = 2 * 60 * 1000;
	var actionRows  = [];
	var normalRows  = [];

	rows.forEach(function(r){
		var isButtonAction = r._changes.length === 1 &&
			/^Action\s*:/i.test(r._changes[0]);
		if(isButtonAction) actionRows.push(r);
		else               normalRows.push(r);
	});

	actionRows.forEach(function(ar){
		var arTime = ar.creation ? new Date(ar.creation).getTime() : 0;
		var best = null, bestDiff = Infinity;
		normalRows.forEach(function(nr){
			if(nr._doctype !== ar._doctype || nr._record !== ar._record) return;
			var nrTime = nr.creation ? new Date(nr.creation).getTime() : 0;
			var diff   = Math.abs(arTime - nrTime);
			if(diff <= TWO_MIN && diff < bestDiff){
				bestDiff = diff;
				best     = nr;
			}
		});
		if(best){
			if(!best._ticket && ar._ticket) best._ticket = ar._ticket;
			var label = ar._changes[0].replace(/^Action\s*:\s*/i,'').trim();
			best._changes.push('Firewall: ' + label);
		} else {
			normalRows.push(ar);
		}
	});

	return normalRows;
}

function finishLoad(rows){
	rows = mergeButtonActions(rows);
	rows.sort(function(a,b){return b.creation>a.creation?1:-1;});
	allData=rows;
	buildFilters(rows);
	renderSummary(rows);
	renderTable(rows);
}

function loadData(){
	allData=[]; roleUsers=[]; roleUserMap={};
	$('#nd-tbody').html('<tr><td colspan="8" class="nd-loading">Loading activity data...</td></tr>');
	$('#nd-summary-grid').html('<div class="nd-loading" style="grid-column:1/-1;">Loading...</div>');

	var roleUserSet={}, rolePending=NETWORK_ROLES.length;

	NETWORK_ROLES.forEach(function(role){
		frappe.call({
			method:'frappe.client.get_list',
			args:{doctype:'User',filters:[['Has Role','role','=',role]],fields:['name','full_name','username'],limit:200},
			callback:function(rr){
				(rr.message||[]).forEach(function(u){
					var uname=(u.full_name||u.username||u.name||'').replace(/@[^@]+$/,'').trim();
					if(uname){
						if(!roleUserSet[uname]){roleUserSet[uname]=1;roleUsers.push(uname);}
						if(!roleUserMap[uname]) roleUserMap[uname]=[];
						if(roleUserMap[uname].indexOf(role)===-1) roleUserMap[uname].push(role);
					}
				});
				rolePending--;
				if(rolePending===0) fetchComments();
			},
			error:function(){rolePending--;if(rolePending===0)fetchComments();}
		});
	});

	function fetchComments(){
		var allRows=[], commentPending=NETWORK_DOCTYPES.length;

		NETWORK_DOCTYPES.forEach(function(doctype){
			frappe.call({
				method:'frappe.client.get_list',
				args:{
					doctype:'Comment',
					filters:[
						['reference_doctype','=',doctype],
						['comment_type','in',['Info','Edit','Workflow','Label','Update','Created','Deleted']]
					],
					fields:['name','creation','owner','reference_name','reference_doctype','content','comment_type'],
					order_by:'creation desc',
					limit:500
				},
				callback:function(r){
					(r.message||[]).forEach(function(c){
						var parsed=parseComment(c,doctype);
						if(parsed) allRows.push(parsed);
					});
					commentPending--;
					if(commentPending===0) fetchDocs();
				},
				error:function(){
					commentPending--;
					if(commentPending===0) fetchDocs();
				}
			});
		});

		function fetchDocs(){
			var commentCreates = {};
			allRows.forEach(function(row){
				if(row._action === 'Create'){
					commentCreates[row._doctype + ':::' + row._record] = 1;
				}
			});

			var docPending=NETWORK_DOCTYPES.length;

			NETWORK_DOCTYPES.forEach(function(doctype){
				frappe.call({
					method:'frappe.client.get_list',
					args:{
						doctype: doctype,
						fields:['name','creation','owner'],
						order_by:'creation desc',
						limit:500
					},
					callback:function(dr){
						var docs=dr.message||[];
						docs.forEach(function(doc){
							var key=doctype+':::'+doc.name;
							if(commentCreates[key]) return;
							var uname=(doc.owner||'Administrator').replace(/@[^@]+$/,'').trim();
							allRows.push({
								creation:  doc.creation,
								_user:     uname,
								_fulluser: doc.owner||'Administrator',
								_doctype:  doctype,
								_dfcGroup: dfcGroupOf(doctype),
								_record:   doc.name,
								_action:   'Create',
								_changes:  [],
								_ticket:   ''
							});
						});
						docPending--;
						if(docPending===0) finishLoad(allRows);
					},
					error:function(){
						docPending--;
						if(docPending===0) finishLoad(allRows);
					}
				});
			});
		}
	}
}

/* ================================================================
   EVENT BINDINGS
   ================================================================ */
$wrap.on('change','#nd-f-role',function(){
	populateUserDropdown($(this).val());
	applyFilters();
});

$wrap.on('input',  '#nd-search', applyFilters);
$wrap.on('change', '#nd-f-doctype, #nd-f-user, #nd-f-ticket, #nd-f-action', applyFilters);
$wrap.on('click',  '#nd-btn-apply',  applyFilters);
$wrap.on('click',  '#nd-btn-excel',  downloadExcel);

/* DFC tab switching */
$wrap.on('click', '.nd-dfc-tab', function(){
	$('.nd-dfc-tab').removeClass('active');
	$(this).addClass('active');
	activeDFC = $(this).attr('data-dfc');
	applyFilters();
});

page.add_action_item('Refresh',function(){
	$('#nd-f-role,#nd-f-doctype,#nd-f-user,#nd-f-ticket,#nd-f-action').val('');
	$('#nd-f-from,#nd-f-to,#nd-search').val('');
	$('.nd-dfc-tab').removeClass('active');
	$('.nd-dfc-tab[data-dfc=""]').addClass('active');
	activeDFC = '';
	loadData();
});

loadData();

};